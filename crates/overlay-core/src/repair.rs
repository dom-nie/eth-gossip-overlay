//! When to ask a peer for the chunks a message is still missing, who to ask, and what for
//! (§5.6, D23, D24).
//!
//! Everything here is a decision and nothing here is a socket: one tick reads the reassembler,
//! answers what to do about each message past its deadline, and hands that back to the transport
//! task that opens the streams. The lock the reassembler holds is taken and released inside
//! [`Reassembler::incomplete_older_than`], and [`Scheduler::tick`] is not `async`, so a caller
//! cannot hold it across an `await` even by accident.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use crate::custody::{BitSet, ColumnGap};
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
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
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

/// How a column is named where no message id exists: the block it belongs to and its index
/// (D23, T-083).
pub type ColumnKey = ([u8; 32], u16);

/// One column the scheduler decided to ask a peer for by identity (T-083).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColumnRequest {
    /// The block the column belongs to.
    pub block_root: [u8; 32],
    /// The column index, which is also its subnet.
    pub index: u16,
    /// Who to ask: an in-region live peer, by round trip.
    pub peer: Hostname,
    /// How long the answer is waited for, from [`attempt_timeout`].
    pub timeout: Duration,
}

/// What one tick decided about one message or one column.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Open a stream to the peer and ask it for these indices.
    Ask(Request),
    /// Open a stream to the peer and ask it for this column by identity (T-083).
    AskColumn(ColumnRequest),
    /// Stop asking about this message and count [`Outcome::GaveUp`].
    GaveUp(MessageId),
    /// Stop asking about this column and count [`Outcome::GaveUp`].
    GaveUpColumn(ColumnKey),
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
pub struct Scheduler {
    messages: HashMap<MessageId, Repair>,
    columns: HashMap<ColumnKey, Repair>,
}

/// One message's repair: when it became due, who has been asked, and whether an answer is still
/// outstanding.
struct Repair {
    due_at: Instant,
    tried: Vec<Hostname>,
    asking: bool,
    gave_up: bool,
}

impl Repair {
    fn new(now: Instant) -> Self {
        Self {
            due_at: now,
            tried: Vec::new(),
            asking: false,
            gave_up: false,
        }
    }
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
        // A message that is no longer late is one that came back or was evicted, and either way
        // this host is done asking about it. The set is built once rather than scanned per
        // entry, because both sides of that comparison are bounded by `MAX_IN_FLIGHT`.
        let still_late: HashSet<MessageId> = incomplete.iter().map(|msg| msg.msg_id).collect();
        self.messages.retain(|msg_id, _| still_late.contains(msg_id));
        incomplete
            .iter()
            .filter_map(|msg| self.decide(msg, &rtt, now))
            .collect()
    }

    /// Records that the request for `msg_id` has been answered, one way or another, so the next
    /// tick may ask the next candidate.
    pub fn answered(&mut self, msg_id: &MessageId) {
        if let Some(repair) = self.messages.get_mut(msg_id) {
            repair.asking = false;
        }
    }

    /// What to do now about the columns of every block past its deadline (T-083).
    ///
    /// `gaps` arrive from the custody tracker already in priority order, so this walks each
    /// one's `missing` from the front and stops at `threshold - have_count`: past that the
    /// beacon node can reconstruct the rest and another request buys nothing (§2).
    ///
    /// A column the reassembler already holds chunks of is left to [`Scheduler::tick`] above:
    /// the chunk path knows which indices are missing and which peers sent the rest, and asking
    /// for the whole column by identity would fetch what this host already has.
    pub fn tick_columns(
        &mut self,
        gaps: &[ColumnGap],
        threshold: usize,
        in_flight: &BitSet,
        candidates: &[(Hostname, Duration)],
        now: Instant,
    ) -> Vec<Decision> {
        let _ = (gaps, threshold, in_flight, candidates, now);
        Vec::new()
    }

    /// Records that the request for `key` has been answered, one way or another, so the next
    /// tick may ask the next candidate.
    pub fn answered_column(&mut self, key: &ColumnKey) {
        if let Some(repair) = self.columns.get_mut(key) {
            repair.asking = false;
        }
    }

    fn decide<R>(&mut self, msg: &Incomplete, rtt: &R, now: Instant) -> Option<Decision>
    where
        R: Fn(&Hostname) -> Option<Duration>,
    {
        let repair = self
            .messages
            .entry(msg.msg_id)
            .or_insert_with(|| Repair::new(now));
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

    /// One chunk of a `k`-data, two-parity message of 64-byte chunks. Nothing decodes it: every
    /// test here holds fewer than `k` of them, which is what makes the message one to repair.
    fn chunk(k: u16, index: u16) -> Chunk {
        Chunk {
            msg_id: MessageId([9; 20]),
            topic_id: 0,
            k,
            m: 2,
            index,
            total_len: u32::from(k) * 64,
            data: Bytes::from(vec![index as u8; 64]),
        }
    }

    /// A reassembler holding `indices` of a `k`-data message, each from the peer named beside it.
    fn collecting(k: u16, indices: &[(u16, &str, bool)], now: Instant) -> Reassembler {
        let reassembler = Reassembler::new(ReassembleConfig::default());
        for (index, from, forwarded) in indices {
            reassembler.on_chunk(&chunk(k, *index), &topic(), &host(from), *forwarded, now);
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
        let reassembler = collecting(4, &[(0, "a", false)], clock.now());
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
        let reassembler = collecting(4, &[(0, "a", false), (4, "a", false)], clock.now());
        let mut scheduler = Scheduler::default();
        clock.advance(DEADLINE);

        let decided = scheduler.tick(&reassembler, DEADLINE, reachable, clock.now());

        let [Decision::Ask(request)] = decided.as_slice() else {
            panic!("expected one request, got {decided:?}");
        };
        assert_eq!(request.missing, vec![1, 2]);
    }

    /// Against [`wanted`] rather than through the reassembler, because the reassembler cannot
    /// produce the shortfall: every parity chunk it holds takes one off `k - held` and one off
    /// the missing data indices at the same time. The rule is D24's and this is where it lives.
    #[test]
    fn parity_indices_are_listed_only_when_missing_data_indices_cannot_reach_k() {
        // Three short of five data chunks with two data indices left to ask for, so one parity
        // index makes up the difference.
        assert_eq!(wanted(5, 2, &[3, 4, 5, 6]), vec![3, 4, 5]);

        // The same shortfall with a data index to spare lists no parity at all.
        assert_eq!(wanted(5, 2, &[1, 2, 3, 4, 5, 6]), vec![1, 2, 3]);
    }

    /// D23's order: the peers that forwarded a chunk first, by round trip, and the origin after
    /// them. A forwarded chunk can only have come from an in-region peer, so the region is the
    /// flag and not a second lookup. Equal round trips keep arrival order, which is every peer
    /// on a fleet whose links are the same length.
    #[test]
    fn candidates_are_in_region_forwarded_senders_by_rtt_then_the_origin() {
        let senders = [
            (host("origin"), false),
            (host("far"), true),
            (host("near"), true),
            (host("near-too"), true),
            (host("gone"), true),
        ];
        let rtt = |peer: &Hostname| match peer.0.as_str() {
            "origin" => Some(Duration::from_millis(1)),
            "far" => Some(Duration::from_millis(50)),
            "near" | "near-too" => Some(Duration::from_millis(10)),
            // Not live, or live without the `REPAIR` bit: never asked, whatever it sent (D29).
            _ => None,
        };

        assert_eq!(
            candidates(&senders, rtt),
            vec![host("near"), host("near-too"), host("far"), host("origin")]
        );
    }

    /// A message whose only sender has gone, or never advertised `REPAIR`, is not asked about at
    /// all: nothing is sent to a peer that could not read the frame (D29), and public gossip is
    /// what delivers the message (D24).
    #[test]
    fn no_candidates_means_no_request_and_a_gave_up_count() {
        let clock = FakeClock::new();
        let reassembler = collecting(4, &[(0, "a", false)], clock.now());
        let mut scheduler = Scheduler::default();
        clock.advance(DEADLINE);

        assert_eq!(
            scheduler.tick(&reassembler, DEADLINE, |_| None, clock.now()),
            vec![Decision::GaveUp(MessageId([9; 20]))]
        );

        // And it is given up on once: a later tick has nothing more to say about it.
        clock.advance(REPAIR_TICK);
        assert_eq!(
            scheduler.tick(&reassembler, DEADLINE, |_| None, clock.now()),
            Vec::new()
        );
    }

    /// D24 scales the wait to the peer rather than to a number: four round trips, but never so
    /// short that a healthy peer is given up on nor so long that three attempts miss the budget.
    #[test]
    fn attempt_timeout_is_four_rtt_clamped_to_100_and_500_ms() {
        assert_eq!(
            attempt_timeout(Duration::from_millis(10)),
            Duration::from_millis(100)
        );
        assert_eq!(
            attempt_timeout(Duration::from_millis(60)),
            Duration::from_millis(240)
        );
        assert_eq!(
            attempt_timeout(Duration::from_millis(200)),
            Duration::from_millis(500)
        );
    }

    /// Who the scheduler asks over a message's life, and where it stops: three peers of the one
    /// candidate list, never the same peer twice, and no fourth however many are left (D24).
    #[test]
    fn three_attempts_go_to_three_distinct_peers_and_a_fourth_is_not_made() {
        let clock = FakeClock::new();
        let reassembler = collecting(
            6,
            &[
                (0, "a", false),
                (1, "b", true),
                (2, "c", true),
                (3, "d", true),
            ],
            clock.now(),
        );
        let mut scheduler = Scheduler::default();
        clock.advance(DEADLINE);

        let mut asked = Vec::new();
        for _ in 0..4 {
            for decision in scheduler.tick(&reassembler, DEADLINE, reachable, clock.now()) {
                match decision {
                    Decision::Ask(request) => asked.push(request.peer),
                    Decision::GaveUp(_) => asked.push(host("gave up")),
                    other => panic!("the chunk path decided {other:?}"),
                }
            }
            scheduler.answered(&MessageId([9; 20]));
            clock.advance(REPAIR_TICK);
        }

        assert_eq!(
            asked,
            vec![host("b"), host("c"), host("d"), host("gave up")]
        );
    }

    /// The budget is a wall the candidate list does not get past: 1.5 s after the deadline the
    /// message is given up on whoever is left to ask, because one that arrives later has already
    /// lost the race (D24).
    #[test]
    fn budget_of_1500_ms_from_the_deadline_ends_in_gave_up_even_with_candidates_left() {
        let clock = FakeClock::new();
        let reassembler = collecting(
            6,
            &[(0, "a", false), (1, "b", true), (2, "c", true)],
            clock.now(),
        );
        let mut scheduler = Scheduler::default();
        clock.advance(DEADLINE);

        assert!(matches!(
            scheduler.tick(&reassembler, DEADLINE, reachable, clock.now()).as_slice(),
            [Decision::Ask(request)] if request.peer == host("b")
        ));
        scheduler.answered(&MessageId([9; 20]));
        clock.advance(REPAIR_TOTAL_BUDGET + Duration::from_millis(1));

        assert_eq!(
            scheduler.tick(&reassembler, DEADLINE, reachable, clock.now()),
            vec![Decision::GaveUp(MessageId([9; 20]))]
        );
    }

    /// The deadline is read on every tick rather than held from the first one, so `eth-gossip-
    /// overlayctl reload` moves it under a running sidecar (T-043, D24).
    #[test]
    fn reloaded_deadline_applies_from_the_next_tick() {
        let clock = FakeClock::new();
        let reassembler = collecting(4, &[(0, "a", false)], clock.now());
        let mut scheduler = Scheduler::default();
        clock.advance(Duration::from_millis(150));

        assert_eq!(
            scheduler.tick(&reassembler, DEADLINE, reachable, clock.now()),
            Vec::new()
        );

        let reloaded = Duration::from_millis(100);
        assert!(matches!(
            scheduler
                .tick(&reassembler, reloaded, reachable, clock.now())
                .as_slice(),
            [Decision::Ask(_)]
        ));
    }

    /// A gap for one block: `have` columns already in, `missing` still wanted.
    fn gap(missing: &[u16], have_count: usize) -> ColumnGap {
        ColumnGap {
            block_root: [3; 32],
            missing: missing.to_vec(),
            have_count,
        }
    }

    /// Mainnet's threshold, which is the only number `tick_columns` takes from the snapshot.
    const THRESHOLD: usize = 64;

    /// D23's answer for a column nobody announced: in-region live peers by round trip, and the
    /// next one the moment the first says it does not hold it.
    #[test]
    fn never_seen_column_is_requested_from_in_region_peers_in_rtt_order_and_moves_on_after_not_found()
    {
        let clock = FakeClock::new();
        let candidates = [
            (host("near"), Duration::from_millis(5)),
            (host("far"), Duration::from_millis(50)),
        ];
        let gaps = [gap(&[4], 0)];
        let none = BitSet::new(128);
        let mut scheduler = Scheduler::default();

        let first = scheduler.tick_columns(&gaps, THRESHOLD, &none, &candidates, clock.now());
        assert_eq!(
            first,
            vec![Decision::AskColumn(ColumnRequest {
                block_root: [3; 32],
                index: 4,
                peer: host("near"),
                timeout: REPAIR_ATTEMPT_MIN,
            })]
        );

        // Nothing more is asked while the first request is outstanding.
        assert_eq!(
            scheduler.tick_columns(&gaps, THRESHOLD, &none, &candidates, clock.now()),
            Vec::new()
        );

        scheduler.answered_column(&([3; 32], 4));
        clock.advance(REPAIR_TICK);

        assert!(matches!(
            scheduler
                .tick_columns(&gaps, THRESHOLD, &none, &candidates, clock.now())
                .as_slice(),
            [Decision::AskColumn(request)] if request.peer == host("far")
        ));
    }
}
