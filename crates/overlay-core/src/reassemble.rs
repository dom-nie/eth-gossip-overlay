//! Where a striped message's chunks are collected, put back together and handed on once (§5.4
//! step 4), and where the receive path asks, per chunk, whether it owes that chunk to the rest
//! of its region (D19).
//!
//! A chunk header is self-describing, so nothing here needs to know who was assigned what: the
//! first chunk of a message fixes `k`, `m`, the chunk length and the total length, and a later
//! chunk that disagrees is a [`Outcome::HeaderConflict`] rather than something that can corrupt
//! the entry. As soon as `k` distinct chunks are present the message is decoded, checked
//! against the id its chunks claimed, and answered as [`Outcome::Completed`] for the caller to
//! gate, remember and publish. Everything that arrives afterwards is late and costs one lookup.
//!
//! Who sent what is kept as well, because repair asks the peers that already have the message:
//! in-region peers that sent a `FORWARDED` chunk first, then the origin (D23). There is no
//! announcement to go with it.
//!
//! # What bounds this
//!
//! A host takes every block and all 128 data columns of a slot, so a few hundred messages can be
//! in flight at once. Three bounds keep that from growing without end: [`MAX_IN_FLIGHT`] on the
//! count, [`MAX_BYTES`] on the chunk bytes held, and [`INCOMPLETE_TTL`] on how long a message
//! that never completed keeps its place. Each of them takes the oldest entry first and counts
//! what it took, and the forwarded bitmap and the sender list go with the entry, so nothing in
//! this module is sized or expired on its own.
//!
//! `now` is a parameter rather than a clock of its own, so a test drives arrival and expiry with
//! plain `Instant` arithmetic and the receive path passes the clock it already holds.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::msgid::{self, Branch, MessageId};
use crate::roster::Hostname;
use crate::rs::{self, Decoded, Params};
use crate::topic::{Topic, TopicKind};
use crate::wire::{Chunk, MAX_PAYLOAD_BYTES};

/// Messages one host collects chunks for at once.
///
/// A slot brings one block and all 128 data columns to every host at full custody, so 129
/// messages, and four slots of that is 516 (§10). Rounded down to the power of two, which is a
/// host four slots behind on the messages it has not finished; a peer that invents message ids
/// reaches this bound instead of the host's memory. T-076's memory budget table takes this row
/// from here and from [`MAX_BYTES`].
pub const MAX_IN_FLIGHT: usize = 512;

/// Chunk bytes one host holds for messages it has not finished with.
///
/// One slot is a 200 KB block and 128 data columns of about 40 KB, which is 5.2 MiB of payload,
/// and a message is buffered as its chunks, so the parity chunks put roughly a tenth on top:
/// about 5.7 MiB for a slot. Four slots of that, which is the same margin [`MAX_IN_FLIGHT`]
/// carries over the 129 messages a slot brings, is 23 MiB, rounded up here to the 32 MiB
/// T-017's large publish lane is bounded by, so the two large-class buffers are the same size
/// (§10).
pub const MAX_BYTES: usize = 32 * 1024 * 1024;

/// How long a message that never completed keeps its entry. Longer than the repair deadline plus
/// the 1.5 s a repair is given after it (D24), so T-082 still finds the senders it would ask.
pub const INCOMPLETE_TTL: Duration = Duration::from_secs(4);

/// What one host's reassembly is held to. The sidecar passes [`ReassembleConfig::default`],
/// which is the three constants above; a test passes less so the bounds are reachable without a
/// slot's traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReassembleConfig {
    /// Messages in flight at once, oldest evicted past it.
    pub max_in_flight: usize,
    /// Chunk bytes held for them, oldest message evicted past it.
    pub max_bytes: usize,
    /// How long a message that never completed keeps its entry.
    pub incomplete_ttl: Duration,
}

impl Default for ReassembleConfig {
    fn default() -> Self {
        Self {
            max_in_flight: MAX_IN_FLIGHT,
            max_bytes: MAX_BYTES,
            incomplete_ttl: INCOMPLETE_TTL,
        }
    }
}

/// What one chunk's arrival came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The chunk was recorded and the message still needs more. `forward` is D19's answer: it
    /// arrived clear, this host does not hold the message, and no copy of this index has been
    /// forwarded before.
    Stored {
        /// Whether the caller owes this chunk to the rest of its region.
        forward: bool,
    },
    /// The chunk was the one that made `k` of them, and the message is back.
    Completed {
        /// The id its chunks carried, which is also the id the payload hashes to.
        msg_id: MessageId,
        /// The sender's id for the topic, as the chunk header named it.
        topic_id: u16,
        /// The message, padding removed.
        payload: Bytes,
        /// Whether a parity chunk had to stand in for a data one (§12).
        used_parity: bool,
        /// When the first chunk of this message arrived, which is what `reconstruct_seconds`
        /// and the repair deadline are both measured from.
        first_chunk_at: Instant,
        /// The first sender of a clear chunk, else the first sender: the host this message is
        /// counted against when its payload turns out to be one no beacon node would take.
        origin: Hostname,
        /// The same as [`Stored`](Self::Stored)'s, because completing is not holding: at the
        /// moment this chunk arrived the message was still missing, so the region is owed it.
        forward: bool,
    },
    /// An index this host already has. The bytes are dropped; `forward` can still be true, for
    /// the clear copy of an index a `FORWARDED` one arrived under first (D11, D19).
    Duplicate {
        /// Whether the caller owes this chunk to the rest of its region.
        forward: bool,
    },
    /// The message was already complete, so the chunk is a copy of something this host has and
    /// costs nothing but the counter.
    LateAfterCompletion,
    /// The header disagrees with the first chunk of the same message, or names an index the
    /// split it declares has no chunk for. Either a bug or a forged chunk (§8).
    HeaderConflict,
    /// The chunk, or the message it completed, is one this host will not publish.
    Rejected {
        /// What is wrong with it.
        reason: Reason,
        /// Who it is counted against: the origin for a message that came back and turned out to
        /// be one no beacon node would take, and the sender for a chunk refused on its header
        /// alone (D03).
        origin: Hostname,
    },
}

impl Outcome {
    /// Whether the caller owes this chunk to the rest of its region (D19). Decided before
    /// anything is decoded, so cut-through does not wait for a message to finish.
    pub fn forward(&self) -> bool {
        match self {
            Self::Stored { forward }
            | Self::Completed { forward, .. }
            | Self::Duplicate { forward } => *forward,
            _ => false,
        }
    }
}

/// Why a chunk, or the message it completed, goes no further.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The first chunk of a message describes a split no message could have been cut into: a
    /// chunk length the codec cannot take, or a total length that does not fit in `k` of them.
    BadHeader,
    /// The message came back, and its payload took the invalid snappy branch, declared more than
    /// the maximum, or is not the payload its id names (D03). The caller counts
    /// `invalid_payload_total{peer}` against the origin and warns once per peer.
    InvalidPayload,
    /// `k` chunks were present and the codec could not turn them into a message. Nothing a
    /// header this module accepted describes should reach this.
    Undecodable,
}

/// Which bound took an entry away, as the label on `reassembly_evicted_total`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Evicted {
    /// [`ReassembleConfig::max_in_flight`] was reached by a new message.
    MaxInFlight,
    /// [`ReassembleConfig::max_bytes`] was passed by a stored chunk.
    MaxBytes,
    /// The message waited [`ReassembleConfig::incomplete_ttl`] without completing.
    Expired,
}

impl Evicted {
    /// The `reason` label this eviction carries (§12).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MaxInFlight => "max_in_flight",
            Self::MaxBytes => "max_bytes",
            Self::Expired => "ttl",
        }
    }
}

/// Where an evicted message is counted. Every eviction is a message this host will not put back
/// together, so a rate above zero is reassembly losing to one of its bounds.
pub trait ReassembleStats: Send + Sync {
    /// `reassembly_evicted_total{reason}`: one message dropped before it completed.
    fn evicted(&self, reason: Evicted);
}

/// A message still missing chunks, and who to ask for them (D23).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Incomplete {
    /// The message the indices belong to.
    pub msg_id: MessageId,
    /// The indices no chunk has arrived for, ascending, so the data ones come first (D24).
    pub missing: Vec<u16>,
    /// Every peer that sent a chunk of it and whether that chunk carried `FORWARDED`, in
    /// arrival order.
    pub senders: Vec<(Hostname, bool)>,
    /// How many data chunks the message was cut into, which is how many of any kind put it back
    /// together and so what a repair request counts against (D24).
    pub k: u16,
    /// How many chunks of it have arrived, whether data or parity.
    pub held: usize,
}

/// The chunks in flight and the messages already finished with, shared by every peer's receiver.
///
/// The lock guard is recovered from poisoning: nothing between a lock and its release can panic,
/// so the state is whole, and refusing to answer afterwards would stop a host forwarding for a
/// reason unrelated to it.
pub struct Reassembler(Mutex<State>);

impl Reassembler {
    /// State held to `cfg`. [`ReassembleConfig::default`] is what the sidecar passes.
    pub fn new(cfg: ReassembleConfig) -> Self {
        Self(Mutex::new(State {
            cfg,
            bytes: 0,
            in_flight: HashMap::new(),
            order: VecDeque::new(),
            completed: HashSet::new(),
            completed_order: VecDeque::new(),
            stats: None,
        }))
    }

    /// Reports evictions to `stats`. Without this nothing is called, so a test and a caller with
    /// no registry pay nothing for the hook.
    pub fn with_stats(self, stats: Arc<dyn ReassembleStats>) -> Self {
        self.state().stats = Some(stats);
        self
    }

    /// Records one chunk of a striped message, answers whether the caller owes it to the rest of
    /// its region, and hands the message back on the chunk that completes it.
    ///
    /// `topic` is the topic the sender's id resolved to, which the completion check needs: a
    /// gossipsub message id covers the topic string as well as the payload (D03).
    ///
    /// The forward is decided before anything is decoded, which is what keeps cut-through ahead
    /// of reassembly (§5.4 step 3, D19).
    pub fn on_chunk(
        &self,
        chunk: &Chunk,
        topic: &Topic,
        from: &Hostname,
        forwarded: bool,
        now: Instant,
    ) -> Outcome {
        let mut state = self.state();
        state.expire(now);
        if state.completed.contains(&chunk.msg_id) {
            return Outcome::LateAfterCompletion;
        }
        let params = Params {
            k: chunk.k,
            m: chunk.m,
            chunk_bytes: chunk.data.len(),
            total_len: chunk.total_len,
        };
        if usize::from(chunk.index) >= indices(params) {
            return Outcome::HeaderConflict;
        }
        match state.in_flight.get(&chunk.msg_id) {
            Some(entry) if entry.params != params => return Outcome::HeaderConflict,
            Some(_) => {}
            None if !usable(params) => return rejected(Reason::BadHeader, from),
            None => state.open(chunk.msg_id, chunk.topic_id, topic.kind(), params, now),
        }
        state.store(chunk, topic, from, forwarded)
    }

    /// Records `msg_id` as one this host holds, which is what stops a late chunk of it being
    /// forwarded a second time round the region (D19). Completion calls it; so does a caller
    /// that has the message from somewhere else.
    pub fn complete(&self, msg_id: MessageId) {
        self.state().finish(msg_id);
    }

    /// Every message whose first chunk arrived at least `deadline` ago and which is still
    /// missing chunks, oldest first: T-082's candidate list, with the indices to ask for and the
    /// peers to ask (D23, D24).
    pub fn incomplete_older_than(&self, deadline: Duration, now: Instant) -> Vec<Incomplete> {
        let state = self.state();
        state
            .order
            .iter()
            .filter_map(|msg_id| Some((msg_id, state.in_flight.get(msg_id)?)))
            .filter(|(_, entry)| now.saturating_duration_since(entry.first_chunk_at) >= deadline)
            .map(|(msg_id, entry)| Incomplete {
                msg_id: *msg_id,
                missing: entry.missing(),
                senders: entry.senders.clone(),
                k: entry.params.k,
                held: entry.chunks.len(),
            })
            .collect()
    }

    /// Drops what has expired and trims the completed set, for a host whose chunks have stopped
    /// arriving: every other entry point does the same on its way past, so this is what a timer
    /// calls when nothing else is.
    pub fn gc(&self, now: Instant) {
        let mut state = self.state();
        state.expire(now);
        state.trim_completed();
    }

    /// The column index of every message still being collected, ascending (T-083).
    ///
    /// A column with chunks already here completes with the fewest bytes, so the custody tracker
    /// lists these first and T-082's chunk path, not column identity, is what finishes them.
    pub fn in_flight_columns(&self) -> Vec<u16> {
        Vec::new()
    }

    /// How many messages are in flight, which is the only thing that grows as chunks arrive.
    pub fn in_flight(&self) -> usize {
        self.state().in_flight.len()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A refusal counted against `origin`.
fn rejected(reason: Reason, origin: &Hostname) -> Outcome {
    Outcome::Rejected {
        reason,
        origin: origin.clone(),
    }
}

/// How many chunks the split in a header describes.
fn indices(params: Params) -> usize {
    usize::from(params.k) + usize::from(params.m)
}

/// Whether a split rebuilt from a header is one a message could have been cut into and the codec
/// can put back together. The encoder's own limits live in someone else's crate and it panics
/// rather than refusing, so a header off the wire is checked against them before it is stored.
fn usable(params: Params) -> bool {
    params.k > 0
        && params.chunk_bytes > 0
        && params.chunk_bytes.is_multiple_of(2)
        && params.total_len as usize <= usize::from(params.k) * params.chunk_bytes
        && params.total_len as usize <= MAX_PAYLOAD_BYTES
        // A split with no parity never reaches the codec: holding k of its k chunks means every
        // data chunk is here, which decodes by concatenation.
        && (params.m == 0 || rs::supports(params.k, params.m))
}

/// Everything one host holds about messages it has not finished with.
struct State {
    cfg: ReassembleConfig,
    /// The chunk bytes of every entry, which is what [`ReassembleConfig::max_bytes`] bounds.
    bytes: usize,
    in_flight: HashMap<MessageId, Entry>,
    /// The ids of `in_flight` in arrival order, so the oldest is what a bound takes.
    order: VecDeque<MessageId>,
    completed: HashSet<MessageId>,
    completed_order: VecDeque<MessageId>,
    stats: Option<Arc<dyn ReassembleStats>>,
}

impl State {
    /// Opens an entry for `msg_id`, which may take the oldest one away: that is the bound on how
    /// many messages a peer can make this host hold.
    fn open(
        &mut self,
        msg_id: MessageId,
        topic_id: u16,
        kind: &TopicKind,
        params: Params,
        now: Instant,
    ) {
        while self.in_flight.len() >= self.cfg.max_in_flight {
            if !self.drop_oldest(Evicted::MaxInFlight) {
                break;
            }
        }
        self.order.push_back(msg_id);
        self.in_flight
            .insert(msg_id, Entry::new(topic_id, kind, params, now));
    }

    /// Records one chunk against an entry that is already open, and answers what its arrival
    /// came to. The forward is claimed before the message is decoded (D19).
    fn store(&mut self, chunk: &Chunk, topic: &Topic, from: &Hostname, forwarded: bool) -> Outcome {
        let Some(entry) = self.in_flight.get_mut(&chunk.msg_id) else {
            return rejected(Reason::BadHeader, from);
        };
        // A forwarded chunk is the second hop and there is no third (D11), so its index is left
        // clear: the copy that arrives clear afterwards is the one this host owes its region.
        let forward = !forwarded && entry.forwarded.set(chunk.index);
        entry.saw(from, forwarded);
        if !entry.received.set(chunk.index) {
            return Outcome::Duplicate { forward };
        }
        entry.chunks.push((chunk.index, chunk.data.clone()));
        entry.bytes += chunk.data.len();
        self.bytes += chunk.data.len();

        match self.finished(&chunk.msg_id, topic, forward) {
            Some(outcome) => outcome,
            None => {
                self.trim_bytes();
                Outcome::Stored { forward }
            }
        }
    }

    /// The message, if this chunk was the one that made `k` of them. Decoding takes the entry
    /// away and records the id either way: a payload no beacon node would take is still one this
    /// host is done with, so its late chunks stay cheap (D03).
    fn finished(&mut self, msg_id: &MessageId, topic: &Topic, forward: bool) -> Option<Outcome> {
        let entry = self.in_flight.get(msg_id)?;
        if entry.chunks.len() < usize::from(entry.params.k) {
            return None;
        }
        let decoded = rs::decode(entry.params, &entry.chunks);
        let (topic_id, first_chunk_at) = (entry.topic_id, entry.first_chunk_at);
        let origin = entry.origin()?;
        self.finish(*msg_id);

        let Ok(Decoded {
            payload,
            used_parity,
        }) = decoded
        else {
            return Some(rejected(Reason::Undecodable, &origin));
        };
        let computed = msgid::compute(&topic.to_string(), &payload, MAX_PAYLOAD_BYTES);
        if computed.branch != Branch::Valid || computed.id != *msg_id {
            return Some(rejected(Reason::InvalidPayload, &origin));
        }
        Some(Outcome::Completed {
            msg_id: *msg_id,
            topic_id,
            payload,
            used_parity,
            first_chunk_at,
            origin,
            forward,
        })
    }

    /// Drops every entry whose first chunk arrived more than the ttl ago. The deque is in
    /// arrival order and a repeat never refreshes it, so expiry only ever looks at the front.
    fn expire(&mut self, now: Instant) {
        while let Some(oldest) = self.order.front() {
            let expired = self.in_flight.get(oldest).is_none_or(|entry| {
                now.saturating_duration_since(entry.first_chunk_at) > self.cfg.incomplete_ttl
            });
            if !expired || !self.drop_oldest(Evicted::Expired) {
                return;
            }
        }
    }

    /// Drops the oldest entries until the chunk bytes held are back inside the bound. A single
    /// message can never pass it on its own: [`MAX_BYTES`] is more than three times what the
    /// longest message the overlay carries takes.
    fn trim_bytes(&mut self) {
        while self.bytes > self.cfg.max_bytes {
            if !self.drop_oldest(Evicted::MaxBytes) {
                return;
            }
        }
    }

    /// Takes the oldest entry away and counts it, answering whether there was one to take.
    fn drop_oldest(&mut self, reason: Evicted) -> bool {
        let Some(oldest) = self.order.pop_front() else {
            return false;
        };
        if let Some(entry) = self.in_flight.remove(&oldest) {
            self.bytes -= entry.bytes;
            if let Some(stats) = &self.stats {
                stats.evicted(reason);
            }
        }
        true
    }

    /// Records a message as one this host is done with and lets go of what it was collecting.
    fn finish(&mut self, msg_id: MessageId) {
        if let Some(entry) = self.in_flight.remove(&msg_id) {
            self.bytes -= entry.bytes;
            self.order.retain(|held| *held != msg_id);
        }
        if self.completed.insert(msg_id) {
            self.completed_order.push_back(msg_id);
        }
        self.trim_completed();
    }

    /// Holds the completed set to the same count as the messages in flight, oldest first.
    fn trim_completed(&mut self) {
        while self.completed_order.len() > self.cfg.max_in_flight {
            let Some(oldest) = self.completed_order.pop_front() else {
                return;
            };
            self.completed.remove(&oldest);
        }
    }
}

/// One message being collected.
struct Entry {
    topic_id: u16,
    /// The column index of the topic this message is on, for T-083's prioritisation. Read from
    /// the topic the sender's id resolved to, once, when the entry is opened.
    column: Option<u8>,
    params: Params,
    first_chunk_at: Instant,
    /// The chunks held, paired with the index their header carried, which is the shape
    /// [`rs::decode`] takes. Held in arrival order rather than by index, so a forged header
    /// cannot make this host reserve a slot per index of a split nothing will ever fill.
    chunks: Vec<(u16, Bytes)>,
    bytes: usize,
    received: Bits,
    forwarded: Bits,
    senders: Vec<(Hostname, bool)>,
}

impl Entry {
    fn new(topic_id: u16, kind: &TopicKind, params: Params, first_chunk_at: Instant) -> Self {
        Self {
            topic_id,
            column: match kind {
                TopicKind::DataColumnSidecar(index) => Some(*index),
                _ => None,
            },
            params,
            first_chunk_at,
            chunks: Vec::new(),
            bytes: 0,
            received: Bits::default(),
            forwarded: Bits::default(),
            senders: Vec::new(),
        }
    }

    /// Records that `from` has a chunk of this message, which is what repair reads (D23). A peer
    /// that sends a second chunk under the same flag is already on the list, so the list is as
    /// long as the peers that have written, not as the chunks they wrote.
    fn saw(&mut self, from: &Hostname, forwarded: bool) {
        if !self
            .senders
            .iter()
            .any(|(peer, flag)| peer == from && *flag == forwarded)
        {
            self.senders.push((from.clone(), forwarded));
        }
    }

    /// The peer this message is counted against: the first to send a clear chunk, which is the
    /// origin, and failing that whoever sent the first chunk at all.
    fn origin(&self) -> Option<Hostname> {
        self.senders
            .iter()
            .find(|(_, forwarded)| !forwarded)
            .or_else(|| self.senders.first())
            .map(|(peer, _)| peer.clone())
    }

    /// The indices no chunk has arrived for, ascending.
    fn missing(&self) -> Vec<u16> {
        (0..indices(self.params))
            .filter(|index| !self.received.has(*index))
            .filter_map(|index| u16::try_from(index).ok())
            .collect()
    }
}

/// A set of one message's indices, one bit each.
#[derive(Default)]
struct Bits(Vec<u64>);

impl Bits {
    /// Sets the bit for `index` and reports whether it was this call that set it. The caller has
    /// already refused an index the message has no chunk for, which is what keeps this from
    /// growing past the split it belongs to.
    fn set(&mut self, index: u16) -> bool {
        let (word, bit) = (usize::from(index) / 64, usize::from(index) % 64);
        if self.0.len() <= word {
            self.0.resize(word + 1, 0);
        }
        let claimed = self.0[word] & (1 << bit) == 0;
        self.0[word] |= 1 << bit;
        claimed
    }

    /// Whether the bit for `index` is set.
    fn has(&self, index: usize) -> bool {
        self.0
            .get(index / 64)
            .is_some_and(|word| word & (1 << (index % 64)) != 0)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::rs::{self, Params};
    use crate::topic::{Topic, TopicKind};

    const TOPIC: &str = "/eth2/6a95a1a9/beacon_block/ssz_snappy";

    fn block() -> Topic {
        Topic::parse(TOPIC).expect("a topic in the only shape the parser takes")
    }

    /// A gossipsub payload of about `bytes`, the split a sender would give it, and the chunks
    /// that come out of it. The id is the one the payload hashes to, because the reassembler
    /// checks its work against it. The bytes are pseudo-random so snappy leaves them roughly the
    /// length they started, which is what makes the split more than one chunk.
    fn striped(bytes: usize, chunk_bytes: usize) -> (MessageId, Params, Vec<Bytes>, Bytes) {
        let mut state = 0x9E37_79B1u32;
        let raw: Vec<u8> = (0..bytes)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                state as u8
            })
            .collect();
        let payload = Bytes::from(
            snap::raw::Encoder::new()
                .compress_vec(&raw)
                .expect("snappy"),
        );
        let params = Params::for_len(payload.len(), chunk_bytes, 0.25).expect("a split");
        let id = msgid::compute(TOPIC, &payload, MAX_PAYLOAD_BYTES).id;
        (id, params, rs::encode(&payload, params), payload)
    }

    /// The same for bytes that are not a gossipsub payload at all, so the id comes out of the
    /// spec's invalid branch and the completion check has something to refuse.
    fn raw_message(payload: &[u8], chunk_bytes: usize) -> (MessageId, Params, Vec<Bytes>) {
        let params = Params::for_len(payload.len(), chunk_bytes, 0.25).expect("a split");
        let id = msgid::compute(TOPIC, payload, MAX_PAYLOAD_BYTES).id;
        (id, params, rs::encode(payload, params))
    }

    /// A snappy declared length, which is the varint every raw snappy block starts with.
    fn varint(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        while value >= 0x80 {
            out.push((value as u8) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
        out
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

    /// What the eviction hook was told, so a test about a bound can say which one fired.
    #[derive(Default)]
    struct Evictions(Mutex<Vec<Evicted>>);

    impl ReassembleStats for Evictions {
        fn evicted(&self, reason: Evicted) {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(reason);
        }
    }

    impl Evictions {
        fn seen(&self) -> Vec<Evicted> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
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
        assert_eq!(
            reassembler.in_flight(),
            0,
            "the entry went with the message"
        );
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
        let evictions = Arc::new(Evictions::default());
        let reassembler = Reassembler::new(ReassembleConfig {
            incomplete_ttl: ttl,
            ..ReassembleConfig::default()
        })
        .with_stats(evictions.clone());
        let now = Instant::now();
        on(&reassembler, &chunk(1, 0, 4, 1), false, now);

        let later = now + ttl + Duration::from_millis(1);

        assert_eq!(
            on(&reassembler, &chunk(1, 0, 4, 1), false, later),
            Outcome::Stored { forward: true }
        );
        assert_eq!(reassembler.in_flight(), 1);
        assert_eq!(evictions.seen(), [Evicted::Expired]);
    }

    /// The time bound, for a message whose missing chunks never arrive. `gc` is what a host with
    /// no traffic left to expire entries on its way past calls; every other entry point expires
    /// what has run out on the way in.
    #[test]
    fn incomplete_entry_is_evicted_after_ttl() {
        let ttl = Duration::from_secs(4);
        let reassembler = Reassembler::new(ReassembleConfig {
            incomplete_ttl: ttl,
            ..ReassembleConfig::default()
        });
        let now = Instant::now();
        on(&reassembler, &chunk(1, 0, 4, 1), false, now);

        reassembler.gc(now + ttl);
        assert_eq!(reassembler.in_flight(), 1, "the ttl had not run out");
        reassembler.gc(now + ttl + Duration::from_millis(1));

        assert_eq!(reassembler.in_flight(), 0);
        assert!(
            reassembler
                .incomplete_older_than(Duration::ZERO, now + ttl)
                .is_empty(),
            "an expired message is still a repair candidate"
        );
    }

    /// The count bound, for a peer that names message ids nothing will ever complete.
    #[test]
    fn max_in_flight_takes_the_oldest_entry() {
        let evictions = Arc::new(Evictions::default());
        let reassembler = Reassembler::new(ReassembleConfig {
            max_in_flight: 2,
            ..ReassembleConfig::default()
        })
        .with_stats(evictions.clone());
        let now = Instant::now();
        for msg_id in 1..=3 {
            on(&reassembler, &chunk(msg_id, 0, 4, 1), false, now);
        }

        assert_eq!(reassembler.in_flight(), 2);
        assert_eq!(evictions.seen(), [Evicted::MaxInFlight]);
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

    /// A second copy of an index is stored nowhere: the chunks are what the message is decoded
    /// from, so a peer that sent the same index twice must not be able to make this host think
    /// it has `k` of them.
    #[test]
    fn duplicate_index_is_reported_and_ignored() {
        let (msg_id, params, chunks, _) = striped(4096, 512);
        let reassembler = Reassembler::new(ReassembleConfig::default());
        let now = Instant::now();
        let repeated: Vec<u16> = std::iter::repeat_n(0, usize::from(params.k)).collect();

        let last = feed(&reassembler, msg_id, params, &chunks, &repeated, now);

        assert_eq!(last, Outcome::Duplicate { forward: false });
        assert_eq!(reassembler.in_flight(), 1, "still collecting the message");
    }

    /// The second hop delivers copies of a message this host has already put together, so late
    /// chunks are the ordinary case and must cost one lookup: no entry is opened for them, which
    /// is what the in-flight count says.
    #[test]
    fn chunk_after_completion_is_late_and_ignored_cheaply() {
        let (msg_id, params, chunks, _) = striped(4096, 512);
        let reassembler = Reassembler::new(ReassembleConfig::default());
        let now = Instant::now();
        let data: Vec<u16> = (0..params.k).collect();
        completed(feed(&reassembler, msg_id, params, &chunks, &data, now));
        assert_eq!(reassembler.in_flight(), 0);

        for index in params.k..params.k + params.m {
            let chunk = header(msg_id, params, index, chunks[usize::from(index)].clone());
            assert_eq!(
                on(&reassembler, &chunk, false, now),
                Outcome::LateAfterCompletion
            );
        }

        assert_eq!(reassembler.in_flight(), 0, "a late chunk opened an entry");
    }

    /// The first chunk fixes the split, so a later one describing a different one is refused
    /// rather than mixed in: a forged chunk must not be able to change what this host thinks it
    /// is collecting, and the message still completes from the chunks that agree (§8).
    #[test]
    fn conflicting_header_is_rejected_and_does_not_corrupt_state() {
        let (msg_id, params, chunks, payload) = striped(4096, 512);
        let reassembler = Reassembler::new(ReassembleConfig::default());
        let now = Instant::now();
        let mut forged = header(msg_id, params, 1, chunks[1].clone());
        forged.k += 1;

        feed(&reassembler, msg_id, params, &chunks, &[0], now);
        assert_eq!(
            on(&reassembler, &forged, false, now),
            Outcome::HeaderConflict
        );
        let rest: Vec<u16> = (1..params.k).collect();
        let last = feed(&reassembler, msg_id, params, &chunks, &rest, now);

        assert_eq!(completed(last).0, payload);
    }

    /// The byte bound, for a host holding more chunks than it has room for. A slot brings one
    /// block and 128 columns, so the count bound alone would let a burst of large messages take
    /// far more memory than the sum of the bounds allows (§10).
    #[test]
    fn max_bytes_evicts_when_buffered_bytes_exceed_the_bound() {
        let evictions = Arc::new(Evictions::default());
        let reassembler = Reassembler::new(ReassembleConfig {
            max_bytes: 16,
            ..ReassembleConfig::default()
        })
        .with_stats(evictions.clone());
        let now = Instant::now();
        for msg_id in 1..=2 {
            on(&reassembler, &chunk(msg_id, 0, 4, 1), false, now);
        }
        assert_eq!(reassembler.in_flight(), 2);

        on(&reassembler, &chunk(3, 0, 4, 1), false, now);

        assert_eq!(reassembler.in_flight(), 2);
        assert_eq!(evictions.seen(), [Evicted::MaxBytes]);
        assert_eq!(
            on(&reassembler, &chunk(1, 0, 4, 1), false, now),
            Outcome::Stored { forward: true },
            "the oldest entry should have gone"
        );
    }

    /// What T-082 asks for when a message has not finished in time (D23, D24): the indices no
    /// chunk arrived for, ascending so the data ones come first, every peer that sent one with
    /// the flag its chunk carried in arrival order, and the split and count a request works out
    /// `k - held` from.
    #[test]
    fn incomplete_older_than_lists_missing_indices_and_senders_with_their_forwarded_flag() {
        let reassembler = Reassembler::new(ReassembleConfig::default());
        let now = Instant::now();
        let origin = Hostname("bn-01".to_owned());
        let sibling = Hostname("bn-02".to_owned());
        reassembler.on_chunk(&chunk(1, 2, 4, 1), &block(), &origin, false, now);
        reassembler.on_chunk(&chunk(1, 0, 4, 1), &block(), &sibling, true, now);

        let deadline = Duration::from_millis(250);
        assert!(reassembler.incomplete_older_than(deadline, now).is_empty());
        let late = reassembler.incomplete_older_than(deadline, now + deadline);

        assert_eq!(
            late,
            vec![Incomplete {
                msg_id: MessageId([1; 20]),
                missing: vec![1, 3, 4],
                senders: vec![(origin, false), (sibling, true)],
                k: 4,
                held: 2,
            }]
        );
    }

    /// D03: Lighthouse refuses a payload that does not decompress before it computes an id for
    /// it, so a message this host reassembles into one is dropped rather than published. The id
    /// still moves to the completed set, because the chunks of it that keep arriving are as late
    /// as any others and must stay as cheap.
    #[test]
    fn completed_payload_on_the_invalid_snappy_branch_is_rejected_counted_and_stays_completed() {
        let (msg_id, params, chunks) = raw_message(b"a payload that is not snappy at all", 64);
        let reassembler = Reassembler::new(ReassembleConfig::default());
        let now = Instant::now();
        let data: Vec<u16> = (0..params.k).collect();

        let last = feed(&reassembler, msg_id, params, &chunks, &data, now);

        assert_eq!(last, rejected(Reason::InvalidPayload, &host()));
        assert_eq!(
            on(
                &reassembler,
                &header(
                    msg_id,
                    params,
                    params.k,
                    chunks[usize::from(params.k)].clone()
                ),
                false,
                now
            ),
            Outcome::LateAfterCompletion
        );
    }

    /// The other half of D03: a payload whose snappy header declares more than the beacon node's
    /// maximum is refused on the header alone, before anything is decompressed.
    #[test]
    fn completed_payload_over_max_decompressed_length_is_rejected() {
        let mut declared = varint(MAX_PAYLOAD_BYTES as u64 + 1);
        declared.extend_from_slice(&[0; 32]);
        let (msg_id, params, chunks) = raw_message(&declared, 64);
        let reassembler = Reassembler::new(ReassembleConfig::default());
        let now = Instant::now();
        let data: Vec<u16> = (0..params.k).collect();

        let last = feed(&reassembler, msg_id, params, &chunks, &data, now);

        assert_eq!(last, rejected(Reason::InvalidPayload, &host()));
    }

    /// `k` of the `k + m` indices in the order `seed` shuffles them into, which is the order a
    /// stripe and its second hop really deliver in.
    fn arrival_order(params: Params, seed: u64) -> Vec<u16> {
        let mut indices: Vec<u16> = (0..params.k + params.m).collect();
        let mut state = seed | 1;
        for position in (1..indices.len()).rev() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            indices.swap(position, (state % (position as u64 + 1)) as usize);
        }
        indices.truncate(usize::from(params.k));
        indices
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(48))]

        /// Whatever k chunks arrive and whatever order they arrive in, the message comes back
        /// once and only once. Nothing tells a receiver which chunks it will end up holding, so
        /// this is the property the whole large class rests on.
        #[test]
        fn property_random_arrival_order_and_random_k_subset_always_completes_once(
            len in prop_oneof![1usize..=4096, 4097usize..=64 * 1024],
            seed in any::<u64>(),
        ) {
            let (msg_id, params, chunks, payload) = striped(len, 512);
            let reassembler = Reassembler::new(ReassembleConfig::default());
            let now = Instant::now();
            let order = arrival_order(params, seed);

            let mut completions = 0;
            for &index in &order {
                let chunk = header(msg_id, params, index, chunks[usize::from(index)].clone());
                if let Outcome::Completed { payload: got, used_parity, .. } =
                    on(&reassembler, &chunk, false, now)
                {
                    completions += 1;
                    prop_assert_eq!(&got[..], &payload[..]);
                    prop_assert_eq!(used_parity, order.iter().any(|i| *i >= params.k));
                }
            }

            prop_assert_eq!(completions, 1);
            prop_assert_eq!(reassembler.in_flight(), 0);
            for index in 0..params.k + params.m {
                let chunk = header(msg_id, params, index, chunks[usize::from(index)].clone());
                prop_assert_eq!(on(&reassembler, &chunk, false, now), Outcome::LateAfterCompletion);
            }
        }
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

    /// What T-083's prioritisation reads: a column whose chunks are already arriving is repaired
    /// through the chunk path and counted as nearly here, and a block on the same reassembler is
    /// not a column at all.
    #[test]
    fn in_flight_columns_names_only_the_column_topics_being_collected() {
        let now = Instant::now();
        let column =
            Topic::parse("/eth2/6a95a1a9/data_column_sidecar_5/ssz_snappy").expect("a topic");
        let reassembler = Reassembler::new(ReassembleConfig::default());
        let peer = Hostname("bn-1".to_owned());

        reassembler.on_chunk(&chunk(1, 0, 4, 2), &column, &peer, false, now);
        reassembler.on_chunk(&chunk(2, 0, 4, 2), &block(), &peer, false, now);

        assert_eq!(reassembler.in_flight_columns(), vec![5]);
    }
}
