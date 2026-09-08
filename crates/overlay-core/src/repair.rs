//! When to ask a peer for the chunks a message is still missing, who to ask, and what for
//! (§5.6, D23, D24).
//!
//! Everything here is a decision and nothing here is a socket: one tick reads the reassembler,
//! answers what to do about each message past its deadline, and hands that back to the transport
//! task that opens the streams. The lock the reassembler holds is taken and released inside
//! [`Reassembler::incomplete_older_than`], and [`Scheduler::tick`] is not `async`, so a caller
//! cannot hold it across an `await` even by accident.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::msgid::MessageId;
use crate::reassemble::{Incomplete, Reassembler};
use crate::roster::Hostname;

/// How often the scheduler looks at what is still incomplete. Short against the 250 ms deadline,
/// so a message is asked about within a tick of the moment it is due.
pub const REPAIR_TICK: Duration = Duration::from_millis(50);

/// How many peers one message is asked before public gossip is left to deliver it (D24).
pub const REPAIR_ATTEMPTS: usize = 3;

/// The floor on one attempt's timeout, for a peer close enough that four round trips are no time
/// at all (D24).
pub const REPAIR_ATTEMPT_MIN: Duration = Duration::from_millis(100);

/// The ceiling on one attempt's timeout, so three attempts to a distant peer still fit inside
/// [`REPAIR_TOTAL_BUDGET`] (D24).
pub const REPAIR_ATTEMPT_MAX: Duration = Duration::from_millis(500);

/// How long a message is repaired for, measured from its deadline. Past it the message is given
/// up on whoever is left to ask, because a block that arrives this late has already lost the race
/// the overlay exists to win (D24).
pub const REPAIR_TOTAL_BUDGET: Duration = Duration::from_millis(1500);

/// How long one attempt is given: four round trips to the peer, clamped (D24). The round trip is
/// quinn's smoothed estimate, read once when the candidate list is built.
pub fn attempt_timeout(rtt: Duration) -> Duration {
    (4 * rtt).clamp(REPAIR_ATTEMPT_MIN, REPAIR_ATTEMPT_MAX)
}

/// How one repair request ended, as the `outcome` label on `repair_requests_total` (§12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The chunks came back and the message with them.
    Completed,
    /// The peer does not hold the message, so the next candidate is asked.
    NotFound,
    /// The peer did not answer within the attempt's timeout.
    Timeout,
    /// Nobody is left to ask, or the budget ran out. No request was sent and public gossip
    /// delivers the message (D24).
    GaveUp,
}

impl Outcome {
    /// The `outcome` label this carries (§12).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::NotFound => "not_found",
            Self::Timeout => "timeout",
            Self::GaveUp => "gave_up",
        }
    }
}

/// One request the scheduler decided to make.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The message the indices belong to.
    pub msg_id: MessageId,
    /// Who to ask.
    pub peer: Hostname,
    /// The indices to ask for, data first (D24).
    pub missing: Vec<u16>,
    /// How long the answer is waited for, from [`attempt_timeout`].
    pub timeout: Duration,
}

/// What one tick decided about one message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Open a stream to the peer and ask it for these indices.
    Ask(Request),
    /// Stop asking about this message and count [`Outcome::GaveUp`].
    GaveUp(MessageId),
}

/// Which indices to ask for, given a split of `k` data chunks, the `held` chunks of any kind
/// that have arrived and the `missing` indices ascending (D24).
///
/// `k - held` more chunks of any kind put the message back together, so that is what is asked
/// for and nothing beyond it: a host that holds a parity chunk has already been covered for one
/// data index and does not ask for it again. The indices listed are data ones, because a message
/// whose every data chunk is present comes back by concatenation and never reaches the codec
/// (T-071).
///
/// Parity indices only make up a shortfall. A message the reassembler is collecting cannot have
/// one, since every parity chunk it holds lowers `k - held` by the same one it removes from the
/// missing data indices; the arm is D24's rule stated where the request is built, so a shorter
/// list still asks for enough to reach `k`.
pub fn wanted(k: u16, held: usize, missing: &[u16]) -> Vec<u16> {
    let need = usize::from(k).saturating_sub(held);
    let is_data = |index: &u16| usize::from(*index) < usize::from(k);
    let mut want: Vec<u16> = missing.iter().copied().filter(is_data).take(need).collect();
    want.extend(
        missing
            .iter()
            .copied()
            .filter(|index| !is_data(index))
            .take(need - want.len()),
    );
    want
}

/// Which peers to ask for a message, in the order to ask them (D23).
///
/// In-region peers that sent a `FORWARDED` chunk come first, by round trip; then the origin, the
/// peer that sent a chunk with the flag clear. There is no region check here because a forwarded
/// chunk can only have come from an in-region peer, which is what makes this D24's "same region
/// first, then RTT" order without a second lookup.
///
/// `rtt` answers `None` for a peer that cannot be asked at all: one that has left the live set,
/// or one that never advertised `REPAIR` (D29). A peer that sent both a forwarded and a clear
/// chunk is asked once, in the earlier of its two places.
///
/// The sort is stable, so peers whose round trips are equal keep the order their chunks arrived
/// in, which on a quiet fleet is every peer.
pub fn candidates<R>(senders: &[(Hostname, bool)], rtt: R) -> Vec<Hostname>
where
    R: Fn(&Hostname) -> Option<Duration>,
{
    let mut forwarded: Vec<(&Hostname, Duration)> = senders
        .iter()
        .filter(|(_, forwarded)| *forwarded)
        .filter_map(|(peer, _)| Some((peer, rtt(peer)?)))
        .collect();
    forwarded.sort_by_key(|(_, rtt)| *rtt);

    let origins = senders
        .iter()
        .filter(|(_, forwarded)| !forwarded)
        .filter(|(peer, _)| rtt(peer).is_some())
        .map(|(peer, _)| peer);

    let mut order = Vec::new();
    for peer in forwarded.iter().map(|(peer, _)| *peer).chain(origins) {
        if !order.contains(peer) {
            order.push(peer.clone());
        }
    }
    order
}

/// What one host has asked about, and how long it has been asking.
///
/// One entry per message under repair, opened the first tick its deadline is seen to have passed
/// and dropped the tick it is no longer incomplete, so this is bounded by the reassembler's own
/// [`MAX_IN_FLIGHT`](crate::reassemble::MAX_IN_FLIGHT).
#[derive(Default)]
pub struct Scheduler(HashMap<MessageId, Repair>);

/// One message's repair: when it became due, who has been asked, and whether an answer is still
/// outstanding.
struct Repair {
    due_at: Instant,
    tried: Vec<Hostname>,
    asking: bool,
    gave_up: bool,
}

impl Scheduler {
    /// What to do now about every message whose first chunk arrived `deadline` ago and which is
    /// still missing chunks.
    ///
    /// Deliberately not `async` and deliberately taking no stream: the reassembler's lock is
    /// taken and dropped inside `incomplete_older_than` before anything here runs, and the
    /// network work happens to the [`Decision`]s this returns. That is the DoD's rule about the
    /// lock and the `await` made structural rather than remembered.
    ///
    /// `deadline` is read afresh on every call, so a reload of `classes.large.repair_deadline_ms`
    /// takes hold on the next tick (T-043).
    pub fn tick<R>(
        &mut self,
        reassembler: &Reassembler,
        deadline: Duration,
        rtt: R,
        now: Instant,
    ) -> Vec<Decision>
    where
        R: Fn(&Hostname) -> Option<Duration>,
    {
        let incomplete = reassembler.incomplete_older_than(deadline, now);
        self.0
            .retain(|msg_id, _| incomplete.iter().any(|msg| msg.msg_id == *msg_id));
        incomplete
            .iter()
            .filter_map(|msg| self.decide(msg, &rtt, now))
            .collect()
    }

    /// Records that the request for `msg_id` has been answered, one way or another, so the next
    /// tick may ask the next candidate.
    pub fn answered(&mut self, msg_id: &MessageId) {
        if let Some(repair) = self.0.get_mut(msg_id) {
            repair.asking = false;
        }
    }

    fn decide<R>(&mut self, msg: &Incomplete, rtt: &R, now: Instant) -> Option<Decision>
    where
        R: Fn(&Hostname) -> Option<Duration>,
    {
        let repair = self.0.entry(msg.msg_id).or_insert_with(|| Repair {
            due_at: now,
            tried: Vec::new(),
            asking: false,
            gave_up: false,
        });
        if repair.asking || repair.gave_up {
            return None;
        }
        let over_budget = now.saturating_duration_since(repair.due_at) > REPAIR_TOTAL_BUDGET;
        let peer = (!over_budget && repair.tried.len() < REPAIR_ATTEMPTS)
            .then(|| candidates(&msg.senders, rtt))
            .and_then(|order| order.into_iter().find(|peer| !repair.tried.contains(peer)));
        let Some(peer) = peer else {
            repair.gave_up = true;
            return Some(Decision::GaveUp(msg.msg_id));
        };
        repair.asking = true;
        repair.tried.push(peer.clone());
        Some(Decision::Ask(Request {
            msg_id: msg.msg_id,
            missing: wanted(msg.k, msg.held, &msg.missing),
            timeout: attempt_timeout(rtt(&peer).unwrap_or(REPAIR_ATTEMPT_MAX)),
            peer,
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;

    use super::*;
    use crate::reassemble::{ReassembleConfig, Reassembler};
    use crate::time::{Clock, FakeClock};
    use crate::topic::Topic;
    use crate::wire::Chunk;

    const TOPIC: &str = "/eth2/6a95a1a9/beacon_block/ssz_snappy";
    const DEADLINE: Duration = Duration::from_millis(250);

    fn topic() -> Topic {
        Topic::parse(TOPIC).expect("a topic in the only shape the parser takes")
    }

    fn host(name: &str) -> Hostname {
        Hostname(name.to_owned())
    }

    /// One chunk of a four-data, two-parity message. Nothing decodes it: every test here holds
    /// fewer than `k` of them, which is what makes the message one to repair.
    fn chunk(index: u16) -> Chunk {
        Chunk {
            msg_id: MessageId([9; 20]),
            topic_id: 0,
            k: 4,
            m: 2,
            index,
            total_len: 256,
            data: Bytes::from(vec![index as u8; 64]),
        }
    }

    /// A reassembler holding `indices`, each from the peer named beside it.
    fn collecting(indices: &[(u16, &str, bool)], now: Instant) -> Reassembler {
        let reassembler = Reassembler::new(ReassembleConfig::default());
        for (index, from, forwarded) in indices {
            reassembler.on_chunk(&chunk(*index), &topic(), &host(from), *forwarded, now);
        }
        reassembler
    }

    /// Every peer answers with the same round trip, which is what a test that is not about the
    /// order wants.
    fn reachable(_: &Hostname) -> Option<Duration> {
        Some(Duration::from_millis(10))
    }

    #[test]
    fn no_request_before_deadline() {
        let clock = FakeClock::new();
        let reassembler = collecting(&[(0, "a", false)], clock.now());
        let mut scheduler = Scheduler::default();

        clock.advance(DEADLINE - Duration::from_millis(1));
        assert_eq!(
            scheduler.tick(&reassembler, DEADLINE, reachable, clock.now()),
            Vec::new()
        );

        clock.advance(Duration::from_millis(1));
        assert!(matches!(
            scheduler.tick(&reassembler, DEADLINE, reachable, clock.now()).as_slice(),
            [Decision::Ask(request)] if request.peer == host("a")
        ));
    }

    /// The only decision a request carries besides who to ask: a host two chunks short of `k`
    /// asks for two of them, and asks for data indices so completion is a concatenation rather
    /// than a decode (D24, T-071).
    #[test]
    fn request_after_deadline_lists_missing_data_indices_first_and_only_as_many_as_needed() {
        let clock = FakeClock::new();
        // One data chunk and one parity chunk of a four-data message: two short of k, with
        // three data indices to choose from.
        let reassembler = collecting(&[(0, "a", false), (4, "a", false)], clock.now());
        let mut scheduler = Scheduler::default();
        clock.advance(DEADLINE);

        let decided = scheduler.tick(&reassembler, DEADLINE, reachable, clock.now());

        let [Decision::Ask(request)] = decided.as_slice() else {
            panic!("expected one request, got {decided:?}");
        };
        assert_eq!(request.missing, vec![1, 2]);
    }
}
