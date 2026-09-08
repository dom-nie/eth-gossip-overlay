//! What a striped message's chunks are collected in, and the one question the receive path asks
//! of that state per chunk: forward this one, or not (D19).
//!
//! Putting the pieces back together is T-074's. This release sends chunks (T-073) and forwards
//! them, so what it needs here is the state that decides a forward and nothing else: an entry per
//! message in flight carrying a bitmap of the indices already forwarded, and the set of message
//! ids that have been completed. A clear chunk is forwarded once per index and a message already
//! held is not forwarded at all, so two origins that made the same assignment cost their region
//! one second hop rather than two.
//!
//! The bitmap lives in the entry rather than in a table of its own, which is what bounds it: an
//! entry goes when the message completes, when it has waited [`INCOMPLETE_TTL`] without
//! completing, or when [`MAX_IN_FLIGHT`] messages are already in flight, and the forwarded state
//! goes with it. Nothing else in this module grows.
//!
//! `now` is a parameter rather than a clock of its own, so a test drives arrival and expiry with
//! plain `Instant` arithmetic and the receive path passes the clock it already holds.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::msgid::MessageId;
use crate::roster::Hostname;
use crate::wire::Chunk;

/// Messages one host collects chunks for at once. A slot brings one block and 128 data columns,
/// so a host that is a few slots behind on the ones it has not finished still fits, and a peer
/// that invents message ids reaches the bound instead of the host's memory (§10).
pub const MAX_IN_FLIGHT: usize = 512;

/// How long a message that never completed keeps its entry. Longer than the repair deadline plus
/// the 1.5 s a repair is given after it (D24), so T-082 still finds the senders it would ask.
pub const INCOMPLETE_TTL: Duration = Duration::from_secs(4);

/// What one chunk's arrival came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The chunk was recorded. `forward` is D19's answer: it arrived clear, this host does not
    /// hold the message, and no copy of this index has been forwarded before.
    Stored {
        /// Whether the caller owes this chunk to the rest of its region.
        forward: bool,
    },
    /// The message was already complete, so the chunk is a copy of something this host has and
    /// costs nothing but the counter.
    LateAfterCompletion,
}

/// The chunks in flight and the messages already finished with, shared by every peer's receiver.
///
/// The lock guard is recovered from poisoning: nothing between a lock and its release can panic,
/// so the state is whole, and refusing to answer afterwards would stop a host forwarding for a
/// reason unrelated to it.
pub struct Reassembler(Mutex<State>);

impl Reassembler {
    /// State for `max_in_flight` messages, each kept `incomplete_ttl` after its first chunk.
    /// [`MAX_IN_FLIGHT`] and [`INCOMPLETE_TTL`] are what the sidecar passes; a test passes less
    /// so the bounds are reachable without a slot's traffic.
    pub fn new(max_in_flight: usize, incomplete_ttl: Duration) -> Self {
        Self(Mutex::new(State {
            max_in_flight,
            incomplete_ttl,
            in_flight: HashMap::new(),
            order: VecDeque::new(),
            completed: HashSet::new(),
            completed_order: VecDeque::new(),
        }))
    }

    /// Records one chunk of a striped message and answers whether the caller owes it to the rest
    /// of its region.
    ///
    /// `bytes` and `from` are what T-074 reconstructs from and what T-082 asks for the chunks
    /// this host is missing (D23). Neither is kept yet: this release forwards a chunk and drops
    /// it, so keeping either would be state nothing reads.
    pub fn on_chunk(
        &self,
        hdr: &Chunk,
        _bytes: Bytes,
        _from: &Hostname,
        forwarded: bool,
        now: Instant,
    ) -> Outcome {
        let mut state = self.state();
        state.expire(now);
        if state.completed.contains(&hdr.msg_id) {
            return Outcome::LateAfterCompletion;
        }
        let indices = usize::from(hdr.k) + usize::from(hdr.m);
        let entry = state.entry(hdr.msg_id, now);
        // A forwarded chunk is the second hop and there is no third (D11), so its index is left
        // clear: the copy that arrives clear afterwards is the one this host owes its region.
        let forward = !forwarded && entry.forwarded.claim(hdr.index, indices);
        Outcome::Stored { forward }
    }

    /// Records `msg_id` as one this host holds, which is what stops a late chunk of it being
    /// forwarded a second time round the region (D19). T-074's completion is what calls it once
    /// a message is reconstructed.
    pub fn complete(&self, msg_id: MessageId) {
        let mut state = self.state();
        state.forget(&msg_id);
        if state.completed.insert(msg_id) {
            state.completed_order.push_back(msg_id);
        }
        while state.completed_order.len() > state.max_in_flight {
            let Some(oldest) = state.completed_order.pop_front() else {
                break;
            };
            state.completed.remove(&oldest);
        }
    }

    /// How many messages are in flight, which is the only thing that grows as chunks arrive.
    pub fn in_flight(&self) -> usize {
        self.state().in_flight.len()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Everything one host holds about messages it has not finished with.
struct State {
    max_in_flight: usize,
    incomplete_ttl: Duration,
    in_flight: HashMap<MessageId, Entry>,
    /// The ids of `in_flight` in arrival order, so the oldest is what the bound takes.
    order: VecDeque<MessageId>,
    completed: HashSet<MessageId>,
    completed_order: VecDeque<MessageId>,
}

impl State {
    /// The entry for `msg_id`, opened at `now` if this is its first chunk. Opening one may take
    /// the oldest entry away, which is the bound on how many a peer can make this host hold.
    fn entry(&mut self, msg_id: MessageId, now: Instant) -> &mut Entry {
        if !self.in_flight.contains_key(&msg_id) {
            while self.in_flight.len() >= self.max_in_flight {
                let Some(oldest) = self.order.pop_front() else {
                    break;
                };
                self.in_flight.remove(&oldest);
            }
            self.order.push_back(msg_id);
            self.in_flight.insert(msg_id, Entry::new(now));
        }
        self.in_flight
            .entry(msg_id)
            .or_insert_with(|| Entry::new(now))
    }

    /// Drops every entry whose first chunk arrived more than `incomplete_ttl` ago. The deque is
    /// in arrival order and a repeat never refreshes it, so expiry only ever looks at the front.
    fn expire(&mut self, now: Instant) {
        while let Some(oldest) = self.order.front() {
            let expired = self.in_flight.get(oldest).is_none_or(|entry| {
                now.saturating_duration_since(entry.first_chunk_at) > self.incomplete_ttl
            });
            if !expired {
                return;
            }
            let Some(oldest) = self.order.pop_front() else {
                return;
            };
            self.in_flight.remove(&oldest);
        }
    }

    /// Drops one message's entry, for a message that has been finished with.
    fn forget(&mut self, msg_id: &MessageId) {
        if self.in_flight.remove(msg_id).is_some() {
            self.order.retain(|held| held != msg_id);
        }
    }
}

/// One message being collected.
struct Entry {
    first_chunk_at: Instant,
    forwarded: Forwarded,
}

impl Entry {
    fn new(first_chunk_at: Instant) -> Self {
        Self {
            first_chunk_at,
            forwarded: Forwarded::default(),
        }
    }
}

/// The indices of one message this host has already forwarded, one bit each.
#[derive(Default)]
struct Forwarded(Vec<u64>);

impl Forwarded {
    /// Sets the bit for `index` and reports whether it was this call that set it. An index at or
    /// past `indices` belongs to no chunk of this message and claims nothing: a header that
    /// disagrees with the first one is T-074's `HeaderConflict`, and until then it must not be
    /// able to grow the bitmap past the message it is for.
    fn claim(&mut self, index: u16, indices: usize) -> bool {
        if usize::from(index) >= indices {
            return false;
        }
        let (word, bit) = (usize::from(index) / 64, usize::from(index) % 64);
        if self.0.len() <= word {
            self.0.resize(word + 1, 0);
        }
        let claimed = self.0[word] & (1 << bit) == 0;
        self.0[word] |= 1 << bit;
        claimed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rs::{self, Params};
    use crate::topic::Topic;

    const TOPIC: &str = "/eth2/6a95a1a9/beacon_block/ssz_snappy";

    fn block() -> Topic {
        Topic::parse(TOPIC).expect("a topic in the only shape the parser takes")
    }

    /// A gossipsub payload of about `bytes`, the split a sender would give it, and the chunks
    /// that come out of it. The id is the one the payload hashes to, because the reassembler
    /// checks its work against it.
    fn striped(bytes: usize, chunk_bytes: usize) -> (MessageId, Params, Vec<Bytes>, Bytes) {
        let raw: Vec<u8> = (0..bytes).map(|i| (i * 31 % 251) as u8).collect();
        let payload = Bytes::from(snap::raw::Encoder::new().compress_vec(&raw).expect("snappy"));
        let params = Params::for_len(payload.len(), chunk_bytes, 0.25).expect("a split");
        let id = msgid::compute(TOPIC, &payload, MAX_PAYLOAD_BYTES).id;
        (id, params, rs::encode(&payload, params), payload)
    }

    /// One chunk of `params`' split as it would arrive off a peer's stream.
    fn header(msg_id: MessageId, params: Params, index: u16, data: Bytes) -> Chunk {
        Chunk {
            msg_id,
            topic_id: 7,
            k: params.k,
            m: params.m,
            index,
            total_len: params.total_len,
            data,
        }
    }

    fn chunk(msg_id: u8, index: u16, k: u16, m: u16) -> Chunk {
        Chunk {
            msg_id: MessageId([msg_id; 20]),
            topic_id: 1,
            k,
            m,
            index,
            total_len: u32::from(k) * 8,
            data: Bytes::from_static(b"12345678"),
        }
    }

    fn host() -> Hostname {
        Hostname("bn-01".to_owned())
    }

    fn on(reassembler: &Reassembler, chunk: &Chunk, forwarded: bool, now: Instant) -> Outcome {
        reassembler.on_chunk(chunk, &block(), &host(), forwarded, now)
    }

    /// Feeds `indices` of a striped message in the order given and answers what the last one
    /// came to.
    fn feed(
        reassembler: &Reassembler,
        msg_id: MessageId,
        params: Params,
        chunks: &[Bytes],
        indices: &[u16],
        now: Instant,
    ) -> Outcome {
        let mut last = Outcome::LateAfterCompletion;
        for &index in indices {
            let chunk = header(msg_id, params, index, chunks[usize::from(index)].clone());
            last = on(reassembler, &chunk, false, now);
        }
        last
    }

    fn completed(outcome: Outcome) -> (Bytes, bool) {
        match outcome {
            Outcome::Completed {
                payload,
                used_parity,
                ..
            } => (payload, used_parity),
            other => panic!("the message should have completed, not {other:?}"),
        }
    }

    /// The normal case (§5.4 step 4): every data chunk arrives, so the message is the chunks
    /// joined back together and the codec is never called.
    #[test]
    fn completes_when_k_data_chunks_present_without_parity() {
        let (msg_id, params, chunks, payload) = striped(4096, 512);
        let reassembler = Reassembler::new(ReassembleConfig::default());
        let now = Instant::now();
        let data: Vec<u16> = (0..params.k).collect();

        let last = feed(&reassembler, msg_id, params, &chunks, &data, now);

        let (got, used_parity) = completed(last);
        assert_eq!(got, payload);
        assert!(!used_parity, "no data chunk was missing");
        assert_eq!(reassembler.in_flight(), 0, "the entry went with the message");
    }

    /// A host was down or a chunk was lost, so one of the parity chunks stands in for a data
    /// one. `used_parity` is what `parity_used_total` counts (§12).
    #[test]
    fn completes_with_parity_when_a_data_chunk_is_missing_and_reports_used_parity() {
        let (msg_id, params, chunks, payload) = striped(4096, 512);
        let reassembler = Reassembler::new(ReassembleConfig::default());
        let now = Instant::now();
        let mut indices: Vec<u16> = (1..params.k).collect();
        indices.push(params.k);

        let last = feed(&reassembler, msg_id, params, &chunks, &indices, now);

        let (got, used_parity) = completed(last);
        assert_eq!(got, payload);
        assert!(used_parity, "a data chunk was missing");
    }

    /// The last data chunk is zero-padded, so the header's total length is what says where the
    /// payload ended. A message whose length is not a whole number of chunks would otherwise
    /// reach the beacon node with the padding still on it.
    #[test]
    fn payload_is_truncated_to_total_length() {
        let (msg_id, params, chunks, payload) = striped(3000, 512);
        assert!(
            payload.len() % params.chunk_bytes != 0,
            "the test needs a payload the split has to pad"
        );
        let reassembler = Reassembler::new(ReassembleConfig::default());
        let now = Instant::now();
        let data: Vec<u16> = (0..params.k).collect();

        let last = feed(&reassembler, msg_id, params, &chunks, &data, now);

        assert_eq!(completed(last).0.len(), payload.len());
    }

    /// D19 per index: the first clear copy is the one this host owes its region, and the second
    /// costs nothing. Two origins with the same live view make the same assignment, so the second
    /// copy is the ordinary case rather than the odd one.
    #[test]
    fn first_clear_chunk_of_an_index_forwards_and_a_second_does_not() {
        let reassembler = Reassembler::new(ReassembleConfig::default());
        let now = Instant::now();

        assert_eq!(
            on(&reassembler, &chunk(1, 0, 4, 1), false, now),
            Outcome::Stored { forward: true }
        );
        assert_eq!(
            on(&reassembler, &chunk(1, 0, 4, 1), false, now),
            Outcome::Duplicate { forward: false }
        );
        assert_eq!(
            on(&reassembler, &chunk(1, 1, 4, 1), false, now),
            Outcome::Stored { forward: true }
        );
    }

    /// The second hop is never a third (D11), and the bit stays clear so the clear copy that
    /// follows is still forwarded.
    #[test]
    fn forwarded_chunk_never_asks_for_a_forward() {
        let reassembler = Reassembler::new(ReassembleConfig::default());
        let now = Instant::now();

        assert_eq!(
            on(&reassembler, &chunk(1, 0, 4, 1), true, now),
            Outcome::Stored { forward: false }
        );
        assert_eq!(
            on(&reassembler, &chunk(1, 0, 4, 1), false, now),
            Outcome::Duplicate { forward: true }
        );
    }

    /// A message this host has put together is one every neighbour was offered a chunk of
    /// already, so a copy arriving afterwards is late and goes nowhere (D19).
    #[test]
    fn chunk_of_a_completed_message_is_late_and_asks_for_nothing() {
        let reassembler = Reassembler::new(ReassembleConfig::default());
        let now = Instant::now();
        reassembler.complete(MessageId([1; 20]));

        assert_eq!(
            on(&reassembler, &chunk(1, 0, 4, 1), false, now),
            Outcome::LateAfterCompletion
        );
        assert_eq!(reassembler.in_flight(), 0);
    }

    /// The bitmap is the entry's, so it dies with it: after the ttl the same chunk is one this
    /// host has no record of and forwards again.
    #[test]
    fn forwarded_bitmap_dies_with_the_entry() {
        let ttl = Duration::from_secs(4);
        let reassembler = Reassembler::new(ReassembleConfig {
            incomplete_ttl: ttl,
            ..ReassembleConfig::default()
        });
        let now = Instant::now();
        on(&reassembler, &chunk(1, 0, 4, 1), false, now);

        let later = now + ttl + Duration::from_millis(1);

        assert_eq!(
            on(&reassembler, &chunk(1, 0, 4, 1), false, later),
            Outcome::Stored { forward: true }
        );
        assert_eq!(reassembler.in_flight(), 1);
    }

    /// The count bound, for a peer that names message ids nothing will ever complete.
    #[test]
    fn max_in_flight_takes_the_oldest_entry() {
        let reassembler = Reassembler::new(ReassembleConfig {
            max_in_flight: 2,
            ..ReassembleConfig::default()
        });
        let now = Instant::now();
        for msg_id in 1..=3 {
            on(&reassembler, &chunk(msg_id, 0, 4, 1), false, now);
        }

        assert_eq!(reassembler.in_flight(), 2);
        assert_eq!(
            on(&reassembler, &chunk(1, 0, 4, 1), false, now),
            Outcome::Stored { forward: true },
            "the oldest entry should have gone"
        );
    }

    /// An index no chunk of the message has claims no bit, so a header naming one cannot grow
    /// the bitmap past the message it belongs to.
    #[test]
    fn index_past_the_split_claims_nothing() {
        let reassembler = Reassembler::new(ReassembleConfig::default());
        let now = Instant::now();

        assert_eq!(
            on(&reassembler, &chunk(1, 5, 4, 1), false, now),
            Outcome::HeaderConflict
        );
    }

    /// Completion frees the entry as well as recording the id, so nothing stays in flight for a
    /// message this host is done with.
    #[test]
    fn completion_drops_the_entry_it_finished() {
        let reassembler = Reassembler::new(ReassembleConfig::default());
        let now = Instant::now();
        on(&reassembler, &chunk(1, 0, 4, 1), false, now);
        assert_eq!(reassembler.in_flight(), 1);

        reassembler.complete(MessageId([1; 20]));

        assert_eq!(reassembler.in_flight(), 0);
    }
}
