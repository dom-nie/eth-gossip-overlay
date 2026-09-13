//! The payloads of large messages this host has just taken, kept long enough to answer a peer's
//! repair request for one (§5.6).
//!
//! Repair needs two things and this is the second of them. Who to ask comes free from the chunks
//! that already arrived, which the reassembler records as it goes (D23); nothing announces what a
//! host holds and there is no `HAVE` frame. What is left is the bytes, and the seen cache keeps
//! only ids, so a large message is kept whole here for as long as a peer can still ask for it.
//!
//! Two places insert, both on a large-class first arrival: T-016 as a message arrives from the
//! beacon node, and T-074's reassembler when a striped message completes. T-032's whole-message
//! delivery does not. Chunk repair never asks such a host, because it sent nobody a chunk and is
//! nobody's candidate (D23), and `receive.rs` says at that site why column repair under MD-06
//! does not change that.
//!
//! A column is asked for by `(block_root, index)` rather than by message id, because a host that
//! never saw the column has no id for it (T-083). A block is asked for by its root alone, which is
//! how the beacon node's own lookups name one (T-085). Both keys are part of the entry, so they go
//! when the entry goes.
//!
//! `now` is a parameter rather than a clock of its own, so nothing here reads a time the caller
//! did not give it: every insert site already holds the injected clock, and a test drives expiry
//! from a `FakeClock` of its own.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::custody::ColumnStats;
use crate::events::hex;
use crate::header::{Header, HeaderDecoder};
use crate::msgid::MessageId;
use crate::topic::Topic;

/// A slot on every network the sidecar has seen. The window is stated in slots because that is
/// the unit the traffic arrives in and the unit an operator reasons about.
pub const SLOT: Duration = Duration::from_secs(12);

/// What one slot of large-class traffic comes to at §10's sizes: one 200 KB block and 128 data
/// columns of about 40 KB each, which is 5.2 MiB. Payloads are kept whole rather than as chunks,
/// so unlike the reassembler's bound there is no parity to leave room for.
pub const SLOT_BYTES: usize = 200 * 1024 + 128 * 40 * 1024;

/// How many slots the store holds for repair alone (§5.6): the same minute the seen cache
/// remembers an id for, so a peer that has not yet forgotten a message finds its bytes here.
pub const RECENT_SLOTS: u32 = 5;

/// How long a payload can still be asked for with only repair to serve.
pub const RECENT_TTL: Duration = window_ttl(RECENT_SLOTS);

/// Payload bytes one host keeps for repair alone. T-076's memory budget table takes this row
/// from here; T-085's by-root cache widens the window past it and prices the difference.
pub const RECENT_MAX_BYTES: usize = window_bytes(RECENT_SLOTS);

/// How long `slots` slots take to arrive, which is how long the last of them has to stay.
pub const fn window_ttl(slots: u32) -> Duration {
    Duration::from_secs(slots as u64 * SLOT.as_secs())
}

/// What `slots` slots of large-class traffic come to at §10's sizes.
pub const fn window_bytes(slots: u32) -> usize {
    slots as usize * SLOT_BYTES
}

/// How a payload is named by the consensus object inside it: a block by its own root, a column by
/// the root of the block it belongs to and its index, which is also its subnet.
type RootKey = ([u8; 32], Option<u8>);

struct Entry {
    topic: Topic,
    payload: Bytes,
    at: Instant,
    by_root: Option<RootKey>,
}

/// The large messages this host took recently, oldest first, bounded by the bytes they come to.
///
/// Nothing here refreshes: an entry keeps the arrival time of the insert that created it, so the
/// queue stays in insertion order and both bounds only ever look at its front.
pub struct RecentLarge {
    ttl: Duration,
    max_bytes: usize,
    bytes: usize,
    entries: HashMap<MessageId, Entry>,
    order: VecDeque<MessageId>,
    by_root: HashMap<RootKey, MessageId>,
}

impl RecentLarge {
    /// A store that forgets a payload `ttl` after it arrived and never holds more than
    /// `max_bytes` of them. The sidecar passes [`RECENT_TTL`] and [`RECENT_MAX_BYTES`]; a test
    /// passes less so the bound is reachable without a slot's traffic.
    pub fn new(ttl: Duration, max_bytes: usize) -> Self {
        Self {
            ttl,
            max_bytes,
            bytes: 0,
            entries: HashMap::new(),
            order: VecDeque::new(),
            by_root: HashMap::new(),
        }
    }

    /// Keeps `payload` under `msg_id`. An id already held is left as it arrived, so a second
    /// insert neither charges the bound again nor extends the minute.
    ///
    /// Nothing is decoded here. The header is read by [`SharedRecentLarge::insert`] once this
    /// lock is back, because a block's SSZ is milliseconds of work and the responder and the
    /// other two insert sites are waiting on the same mutex (§7, T-083).
    ///
    /// A payload larger than the whole bound takes the store down to itself and then goes too,
    /// which is the bound holding rather than a case to special-case: nothing this host accepts
    /// off the wire is that size.
    pub fn insert(&mut self, msg_id: MessageId, topic: Topic, payload: Bytes, now: Instant) {
        self.expire(now);
        if self.entries.contains_key(&msg_id) {
            return;
        }
        self.bytes += payload.len();
        self.entries.insert(
            msg_id,
            Entry {
                topic,
                payload,
                at: now,
                by_root: None,
            },
        );
        self.order.push_back(msg_id);
        while self.bytes > self.max_bytes && self.pop_oldest() {}
    }

    /// The topic and bytes held for `msg_id`, for a responder about to answer a repair request
    /// with them. Expiry happens on `insert` and `gc`, not here, so an entry past its minute
    /// that neither has removed yet still answers.
    pub fn get(&self, msg_id: &MessageId) -> Option<(Topic, Bytes)> {
        self.entries
            .get(msg_id)
            .map(|entry| (entry.topic.clone(), entry.payload.clone()))
    }

    /// Records that the message held under `msg_id` is the column `index` of `block_root`, so a
    /// peer that never saw the column can still ask for it (T-083). Answers the message already
    /// holding the key when the claim is refused, which a caller counts and names (T-087,
    /// T-090); `None` is the key taken.
    pub fn index_column(
        &mut self,
        block_root: [u8; 32],
        index: u8,
        msg_id: MessageId,
    ) -> Option<MessageId> {
        self.index((block_root, Some(index)), msg_id)
    }

    /// Records that the message held under `msg_id` is the block whose root is `block_root`, which
    /// is how the beacon node's own by-root lookups name one (T-085). Answers as
    /// [`index_column`](Self::index_column) does.
    pub fn index_block(&mut self, block_root: [u8; 32], msg_id: MessageId) -> Option<MessageId> {
        self.index((block_root, None), msg_id)
    }

    /// Which message is column `index` of `block_root`, for a caller that then reads it with
    /// [`get`](Self::get).
    pub fn get_by_column(&self, block_root: [u8; 32], index: u8) -> Option<MessageId> {
        self.by_root.get(&(block_root, Some(index))).copied()
    }

    /// Which message is the block whose root is `block_root`, read the same way.
    pub fn get_by_block(&self, block_root: [u8; 32]) -> Option<MessageId> {
        self.by_root.get(&(block_root, None)).copied()
    }

    /// Files `msg_id` under `key`. An id the store no longer holds is ignored: there would be
    /// nothing for the key to resolve to.
    ///
    /// A key already pointing at another message is left alone. The root comes from a header a
    /// peer chose and nothing has proved it, so a second payload claiming an identity this host
    /// already holds is a claim, not a correction; taking it would let one forged sidecar decide
    /// what every peer is served under that name (MD-06). First writer wins, and the entry goes
    /// with its payload when the minute or the byte bound takes it.
    fn index(&mut self, key: RootKey, msg_id: MessageId) -> Option<MessageId> {
        let entry = self.entries.get_mut(&msg_id)?;
        if let Some(held) = self.by_root.get(&key).filter(|held| **held != msg_id) {
            return Some(*held);
        }
        if let Some(previous) = entry.by_root.replace(key) {
            self.by_root.remove(&previous);
        }
        self.by_root.insert(key, msg_id);
        None
    }

    /// Drops every entry past its minute now, for a caller that wants the memory back between
    /// inserts. `insert` does the same sweep on its own before adding.
    pub fn gc(&mut self, now: Instant) {
        self.expire(now);
    }

    fn expire(&mut self, now: Instant) {
        while self
            .order
            .front()
            .and_then(|id| self.entries.get(id))
            .is_some_and(|entry| entry.at + self.ttl <= now)
        {
            self.pop_oldest();
        }
    }

    // mutants::skip: expire drains through this until the front is unexpired, so a pop_oldest
    // that does not pop loops forever. The mutant hangs the suite instead of failing it, and no
    // test can tell the difference.
    #[cfg_attr(test, mutants::skip)]
    fn pop_oldest(&mut self) -> bool {
        let Some(id) = self.order.pop_front() else {
            return false;
        };
        let Some(entry) = self.entries.remove(&id) else {
            return true;
        };
        self.bytes -= entry.payload.len();
        if let Some(key) = entry.by_root {
            self.by_root.remove(&key);
        }
        true
    }
}

/// One [`RecentLarge`] shared by the three insert sites, which are in different crates: T-016's
/// inbound path in `overlay-bn`, and T-074's completion and T-032's whole delivery in
/// `overlay-transport`. Every method takes the lock for that one call and releases it before
/// returning, so the store is never held across an `await` and no decode runs under it.
#[derive(Clone)]
pub struct SharedRecentLarge {
    store: Arc<Mutex<RecentLarge>>,
    /// Beside the mutex rather than inside it, so a decode never runs under the lock (T-083).
    decoder: Option<Arc<dyn HeaderDecoder>>,
    stats: Arc<dyn ColumnStats>,
}

impl SharedRecentLarge {
    /// Wraps `store` so clones of the handle share it.
    pub fn new(store: RecentLarge) -> Self {
        Self {
            store: Arc::new(Mutex::new(store)),
            decoder: None,
            stats: Arc::new(()),
        }
    }

    /// Counts the refusals the column index makes, which is one of the two series column repair
    /// adds (§12, T-087). Without one the refusal still happens and nothing is counted.
    pub fn with_column_stats(mut self, stats: Arc<dyn ColumnStats>) -> Self {
        self.stats = stats;
        self
    }

    /// Reads the header of every payload stored through this handle, which is what fills the
    /// column index and what T-044's event names a slot from (T-083). Without one nothing is
    /// decoded and the store behaves as it did before column repair existed.
    pub fn with_decoder(mut self, decoder: Arc<dyn HeaderDecoder>) -> Self {
        self.decoder = Some(decoder);
        self
    }

    /// The header of `ssz` as this handle's decoder reads it, with nothing stored: the read
    /// [`insert`](Self::insert) makes once the lock is back, for a payload that must not go in.
    /// A repair answer takes this path, so the line naming its slot is still written while the
    /// served bytes can never claim a column on the host they were served to (D39).
    pub fn header_of(&self, topic: &Topic, ssz: &[u8]) -> Option<Header> {
        self.decoder.as_ref()?.header(topic, ssz)
    }

    /// [`RecentLarge::insert`] under the lock, then the header of `ssz` outside it.
    ///
    /// `ssz` is the decompressed payload, which every caller already has: the overlay receive
    /// path decompressed it to compute the message id and the beacon node's path had it
    /// validated. The decode runs after the lock is back, so the only thing held across it is
    /// a `HashMap` insert.
    ///
    /// The header comes back whatever the store did with the payload. What a message says about
    /// itself is not the store's to decide: the custody tracker's record of a column arriving,
    /// and T-044's line naming the slot, are owed for a payload the byte bound turned away as
    /// much as for one it kept.
    pub fn insert(
        &self,
        msg_id: MessageId,
        topic: Topic,
        payload: Bytes,
        ssz: Option<&[u8]>,
        now: Instant,
    ) -> Option<Header> {
        self.lock().insert(msg_id, topic.clone(), payload, now);
        let header = self.header_of(&topic, ssz?)?;
        // A no-op for an id the store no longer holds, which is what an entry the byte bound took
        // comes to.
        match header {
            Header::Column {
                index, block_root, ..
            } => self.index_column(block_root, index, msg_id),
            Header::Block { root, .. } => self.index_block(root, msg_id),
        }
        Some(header)
    }

    /// [`RecentLarge::get`] under the lock.
    pub fn get(&self, msg_id: &MessageId) -> Option<(Topic, Bytes)> {
        self.lock().get(msg_id)
    }

    /// [`RecentLarge::index_column`] under the lock. A refusal is counted and named: `held` is
    /// the id this host goes on answering with, and its `first_arrival` line says which peer
    /// sent it, which is what the roster fence needs and a counter cannot give (T-090).
    pub fn index_column(&self, block_root: [u8; 32], index: u8, msg_id: MessageId) {
        let Some(held) = self.lock().index_column(block_root, index, msg_id) else {
            return;
        };
        tracing::warn!(
            block_root = %hex(block_root),
            index,
            %held,
            refused = %msg_id,
            "a second payload claims a column this host already holds"
        );
        self.stats.index_conflict();
    }

    /// [`RecentLarge::index_block`] under the lock.
    pub fn index_block(&self, block_root: [u8; 32], msg_id: MessageId) {
        self.lock().index_block(block_root, msg_id);
    }

    /// [`RecentLarge::get_by_column`] under the lock.
    pub fn get_by_column(&self, block_root: [u8; 32], index: u8) -> Option<MessageId> {
        self.lock().get_by_column(block_root, index)
    }

    /// [`RecentLarge::get_by_block`] under the lock.
    pub fn get_by_block(&self, block_root: [u8; 32]) -> Option<MessageId> {
        self.lock().get_by_block(block_root)
    }

    /// [`RecentLarge::gc`] under the lock.
    pub fn gc(&self, now: Instant) {
        self.lock().gc(now);
    }

    fn lock(&self) -> MutexGuard<'_, RecentLarge> {
        // Nothing that runs under this lock can panic, so a poisoned store cannot happen; if one
        // ever did, its containers would still be consistent and losing every repair answer
        // would be the worse failure.
        self.store.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use bytes::Bytes;

    use crate::custody::ColumnStats;
    use crate::header::{Header, HeaderDecoder};
    use crate::msgid::MessageId;
    use crate::recent::{
        RECENT_MAX_BYTES, RECENT_SLOTS, RECENT_TTL, RecentLarge, SLOT, SLOT_BYTES,
        SharedRecentLarge, window_bytes, window_ttl,
    };
    use crate::testlog::LOG;
    use crate::time::{Clock, FakeClock};
    use crate::topic::Topic;

    const TOPIC: &str = "/eth2/6a95a1a9/beacon_block/ssz_snappy";

    fn id(byte: u8) -> MessageId {
        MessageId([byte; 20])
    }

    fn topic() -> Topic {
        Topic::parse(TOPIC).expect("a topic in the only shape the parser takes")
    }

    /// A payload of `len` bytes, distinct per `byte` so a test can tell two of them apart.
    fn payload(byte: u8, len: usize) -> Bytes {
        Bytes::from(vec![byte; len])
    }

    fn store(max_bytes: usize) -> RecentLarge {
        RecentLarge::new(Duration::from_secs(60), max_bytes)
    }

    #[test]
    fn recent_store_returns_inserted_payload() {
        let clock = FakeClock::new();
        let mut recent = store(1024);

        recent.insert(id(1), topic(), payload(1, 200), clock.now());

        assert_eq!(recent.get(&id(1)), Some((topic(), payload(1, 200))));
        assert_eq!(recent.get(&id(2)), None);
    }

    #[test]
    fn recent_store_evicts_oldest_when_over_byte_bound() {
        let clock = FakeClock::new();
        let mut recent = store(250);

        for byte in [1, 2, 3] {
            recent.insert(id(byte), topic(), payload(byte, 100), clock.now());
            clock.advance(Duration::from_secs(1));
        }

        assert_eq!(recent.get(&id(1)), None);
        assert!(recent.get(&id(2)).is_some());
        assert!(recent.get(&id(3)).is_some());
    }

    /// The window is stated in slots, and both bounds follow it: at two slots a third slot's
    /// traffic pushes the first out on bytes, and two slots of clock takes the rest on time
    /// (T-085). Whatever an operator configures is what the store holds.
    #[test]
    fn store_window_evicts_beyond_configured_slots() {
        let clock = FakeClock::new();
        let mut recent = RecentLarge::new(window_ttl(2), window_bytes(2));

        for byte in [1, 2, 3] {
            recent.insert(id(byte), topic(), payload(byte, SLOT_BYTES), clock.now());
        }

        assert_eq!(
            recent.get(&id(1)),
            None,
            "a third slot did not evict the first"
        );
        assert!(recent.get(&id(2)).is_some());
        assert!(recent.get(&id(3)).is_some());

        clock.advance(window_ttl(2));
        recent.gc(clock.now());
        assert_eq!(recent.get(&id(3)), None);
    }

    /// The number the `by_root_cache` row of T-076's table is recorded from: a store configured
    /// for the shipped sixteen-slot window, filled with sixteen slots of §10's traffic, one
    /// 200 KB block and 128 columns of 40 KB per slot.
    ///
    /// It holds all of it and nothing above the bound, so the row is the payload bytes and the
    /// index beside them is the 2064 entries this prints, at roughly 300 bytes each between the
    /// two maps and the queue. That is under a percent of the row and is why the row does not
    /// carry it.
    ///
    /// Ignored because it allocates the 83 MiB it is measuring. Run it when the row moves:
    ///
    /// ```sh
    /// cargo test -p overlay-core --lib memory_budget_test -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "allocates sixteen slots of block and column payloads"]
    fn memory_budget_test_16_slots_of_full_blocks_and_columns_stays_under_documented_bound() {
        const SLOTS: u32 = 16;
        const BLOCK_BYTES: usize = 200 * 1024;
        const COLUMN_BYTES: usize = 40 * 1024;
        const COLUMNS: u8 = 128;

        // One slot every twelve seconds, so the sixteenth arrives exactly as the window's own
        // minute and a bit runs out and none of it has expired yet.
        let clock = FakeClock::new();
        let mut recent = RecentLarge::new(window_ttl(SLOTS), window_bytes(SLOTS));
        let mut ids = Vec::new();
        for slot in 0..SLOTS {
            for object in 0..=u32::from(COLUMNS) {
                let mut bytes = [0; 20];
                bytes[..4].copy_from_slice(&(slot * 1000 + object).to_le_bytes());
                let id = MessageId(bytes);
                let len = match object {
                    0 => BLOCK_BYTES,
                    _ => COLUMN_BYTES,
                };
                recent.insert(id, topic(), Bytes::from(vec![7; len]), clock.now());
                ids.push(id);
            }
            clock.advance(SLOT);
        }

        let held: Vec<usize> = ids
            .iter()
            .filter_map(|id| recent.get(id))
            .map(|(_, payload)| payload.len())
            .collect();
        let bytes: usize = held.iter().sum();
        println!(
            "{SLOTS} slots: {} entries, {bytes} bytes ({:.1} MiB), bound {} bytes",
            held.len(),
            bytes as f64 / (1024.0 * 1024.0),
            window_bytes(SLOTS),
        );

        assert_eq!(
            held.len(),
            ids.len(),
            "the window dropped a slot it was sized for"
        );
        assert_eq!(bytes, window_bytes(SLOTS));
    }

    /// The shipped store is five slots, which is what §5.6 asks for and what T-076's table has
    /// always priced.
    #[test]
    fn the_repair_window_is_five_slots() {
        assert_eq!(RECENT_TTL, window_ttl(RECENT_SLOTS));
        assert_eq!(RECENT_MAX_BYTES, window_bytes(RECENT_SLOTS));
        assert_eq!(RECENT_TTL, Duration::from_secs(60));
    }

    #[test]
    fn recent_store_entries_expire_after_ttl() {
        let clock = FakeClock::new();
        let mut recent = store(1024);
        recent.insert(id(1), topic(), payload(1, 200), clock.now());

        clock.advance(Duration::from_secs(60) - Duration::from_millis(1));
        recent.gc(clock.now());
        assert!(recent.get(&id(1)).is_some());

        clock.advance(Duration::from_millis(1));
        recent.gc(clock.now());
        assert_eq!(recent.get(&id(1)), None);
    }

    /// Room for two payloads and three inserts of two ids. A repeat that charged the bound again
    /// would push the first one out.
    #[test]
    fn second_insert_of_the_same_id_does_not_double_count_bytes() {
        let clock = FakeClock::new();
        let mut recent = store(200);

        recent.insert(id(1), topic(), payload(1, 100), clock.now());
        recent.insert(id(1), topic(), payload(1, 100), clock.now());
        recent.insert(id(2), topic(), payload(2, 100), clock.now());

        assert!(recent.get(&id(1)).is_some());
        assert!(recent.get(&id(2)).is_some());
    }

    #[test]
    fn column_identity_resolves_to_the_message_and_expires_with_it() {
        let clock = FakeClock::new();
        let mut recent = store(1024);
        let root = [7; 32];
        recent.insert(id(1), topic(), payload(1, 200), clock.now());

        recent.index_column(root, 42, id(1));
        assert_eq!(recent.get_by_column(root, 42), Some(id(1)));
        assert_eq!(recent.get_by_column(root, 41), None);

        clock.advance(Duration::from_secs(60));
        recent.gc(clock.now());

        assert_eq!(recent.get_by_column(root, 42), None);
        assert_eq!(recent.get(&id(1)), None);
    }

    const COLUMN_TOPIC: &str = "/eth2/6a95a1a9/data_column_sidecar_5/ssz_snappy";

    /// Stands in for `overlay_bn::decode::Headers`, which is behind a feature this crate cannot
    /// turn on. What is under test here is the store calling a decoder and filing what it says,
    /// not what the real one reads out of SSZ; T-083's tests in `overlay-bn` cover that.
    struct FakeDecoder;

    impl HeaderDecoder for FakeDecoder {
        fn header(&self, topic: &Topic, _: &[u8]) -> Option<Header> {
            match topic.to_string().as_str() {
                COLUMN_TOPIC => Some(Header::Column {
                    slot: 42,
                    index: 5,
                    block_root: [9; 32],
                }),
                TOPIC => Some(Header::Block {
                    slot: 42,
                    root: [8; 32],
                }),
                _ => None,
            }
        }
    }

    #[test]
    fn recent_store_indexes_column_payloads_by_block_root_and_index() {
        let clock = FakeClock::new();
        let recent = SharedRecentLarge::new(store(1024)).with_decoder(Arc::new(FakeDecoder));
        let column = Topic::parse(COLUMN_TOPIC).expect("a topic the parser takes");
        let ssz = payload(1, 200);

        let header = recent.insert(id(1), column, ssz.clone(), Some(&ssz), clock.now());

        assert_eq!(
            header,
            Some(Header::Column {
                slot: 42,
                index: 5,
                block_root: [9; 32],
            })
        );
        assert_eq!(recent.get_by_column([9; 32], 5), Some(id(1)));

        // A block is not a column: it reads as a block and is filed under its own root.
        assert_eq!(
            recent.insert(id(2), topic(), payload(2, 200), Some(&ssz), clock.now()),
            Some(Header::Block {
                slot: 42,
                root: [8; 32]
            })
        );
        assert_eq!(recent.get_by_column([8; 32], 5), None);

        // An id the store already holds is still read: what a payload says about itself does not
        // depend on whether the bound had room for it.
        let column = Topic::parse(COLUMN_TOPIC).expect("a topic the parser takes");
        assert_eq!(
            recent.insert(id(1), column, ssz.clone(), Some(&ssz), clock.now()),
            header
        );
    }

    /// A block goes in under its own root, so the by-root cache can answer for it the way it
    /// answers for a column (T-085). The claim rule is the column's: whoever gets there first
    /// keeps the key, because nothing here has checked a proposer or a signature (MD-06).
    #[test]
    fn recent_store_indexes_block_payloads_by_their_root() {
        let clock = FakeClock::new();
        let recent = SharedRecentLarge::new(store(1024)).with_decoder(Arc::new(FakeDecoder));
        let ssz = payload(1, 200);

        let header = recent.insert(id(1), topic(), ssz.clone(), Some(&ssz), clock.now());

        assert_eq!(
            header,
            Some(Header::Block {
                slot: 42,
                root: [8; 32]
            })
        );
        assert_eq!(recent.get_by_block([8; 32]), Some(id(1)));
        assert_eq!(recent.get_by_block([7; 32]), None);
        // A block root and a column index are different keys, not one namespace.
        assert_eq!(recent.get_by_column([8; 32], 0), None);

        recent.insert(id(2), topic(), payload(2, 200), Some(&ssz), clock.now());
        assert_eq!(recent.get_by_block([8; 32]), Some(id(1)));
    }

    /// The propagation vector MD-06 named, closed at the one place it opens. A column's root is
    /// a claim in a header nobody verified, so a second payload claiming a column this host
    /// already holds must not take the key from the first: whoever holds it answers every peer
    /// that asks for that column. Two payloads claiming one column is nothing an honest fleet
    /// produces, so the refusal is counted as well as made.
    #[test]
    fn index_column_refuses_to_replace_a_live_mapping_with_a_different_id() {
        let clock = FakeClock::new();
        let conflicts = Arc::new(Conflicts::default());
        let recent = SharedRecentLarge::new(store(1024)).with_column_stats(conflicts.clone());
        let root = [7; 32];
        recent.insert(id(1), topic(), payload(1, 200), None, clock.now());
        recent.insert(id(2), topic(), payload(2, 200), None, clock.now());

        recent.index_column(root, 42, id(1));
        recent.index_column(root, 42, id(2));

        assert_eq!(recent.get_by_column(root, 42), Some(id(1)));
        assert_eq!(conflicts.count(), 1);
    }

    /// The refusal names both ids, so an operator can join `held` to its `first_arrival` line
    /// and read which peer sent the payload this host answers for the column with (T-090).
    #[test]
    fn index_column_refusal_names_both_ids() {
        let mark = LOG.len();
        let clock = FakeClock::new();
        let recent = SharedRecentLarge::new(store(1024));
        let root = [0x33; 32];
        recent.insert(id(0x11), topic(), payload(0x11, 200), None, clock.now());
        recent.insert(id(0x22), topic(), payload(0x22, 200), None, clock.now());

        recent.index_column(root, 42, id(0x11));
        recent.index_column(root, 42, id(0x22));

        let line = LOG
            .since(mark)
            .lines()
            .find(|line| line.contains(&format!("refused={}", id(0x22))))
            .unwrap_or_default()
            .to_owned();
        assert!(line.contains("WARN"), "{line}");
        assert!(line.contains(&format!("held={}", id(0x11))), "{line}");
        assert!(
            line.contains(&format!("block_root={}", "33".repeat(32))),
            "{line}"
        );
        assert!(line.contains("index=42"), "{line}");
    }

    /// Counts the refusals, which is `column_index_conflict_total` (§12).
    #[derive(Default)]
    struct Conflicts(AtomicU64);

    impl Conflicts {
        fn count(&self) -> u64 {
            self.0.load(Ordering::Relaxed)
        }
    }

    impl ColumnStats for Conflicts {
        fn topic_mismatch(&self) {}

        fn index_conflict(&self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
}
