//! Which data columns this host's beacon node wants for a slot, which have arrived, and which
//! to ask a peer for first once the deadline has passed (§5.6, §6.4, D23, MD-06).
//!
//! Every fact in here comes from the beacon node's own event stream and from nowhere else:
//! `block_gossip` for a block the node accepted, `data_column_sidecar` for a column it holds.
//! `overlay_bn::events` is the only writer, which is what MD-06 asks for. A payload a peer sent
//! decodes without being authentic, so a tracker fed from the receive path is a tracker a roster
//! peer writes, and column repair's inputs would be exactly the bytes an attacker controls.
//!
//! Expected columns are the beacon node's own column subnets (T-014, D06), which only names a
//! set of columns while one subnet is one column.
//!
//! Nothing here is a socket or a channel: one call answers what is missing and in what order,
//! and T-082's scheduler turns that into requests.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::watch;

use crate::spec::SpecSnapshot;
use crate::topic::{SubscriptionSets, TopicKind};

/// How many blocks of column state a host keeps.
///
/// Long enough that a block still under repair is still tracked (repair gives up 1.5 s after the
/// deadline, D24) and short enough that the whole structure is a handful of bitsets. The beacon
/// node opens every entry, so nothing a peer sends can push the newest ones out and one bound
/// over all of them is enough.
pub const TRACKED_BLOCKS: usize = 4;

/// The counters column repair adds, all of which read zero on an honest fleet (§12). The binary
/// implements this on its metrics; a caller that wants no series passes `()`.
pub trait ColumnStats: Send + Sync {
    /// A beacon node whose column subnets do not name its columns, so nothing says which columns
    /// it wants and column repair idles.
    fn topic_mismatch(&self);
}

impl ColumnStats for () {
    fn topic_mismatch(&self) {}
}

/// A set of column indices.
///
/// A `bool` per index rather than packed bits: at the largest `NUMBER_OF_COLUMNS` anyone runs
/// the whole set is a few hundred bytes and a host holds [`TRACKED_BLOCKS`] of them, so packing
/// would buy nothing a reader does not pay for.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BitSet(Vec<bool>);

impl BitSet {
    /// An empty set with room for indices `0..len`, which is `NUMBER_OF_COLUMNS` everywhere but
    /// a test.
    pub fn new(len: usize) -> Self {
        Self(vec![false; len])
    }

    /// Adds `index`. An index past the set's size is not a column this host can hold and is
    /// dropped rather than growing the set.
    pub fn insert(&mut self, index: u16) {
        if let Some(slot) = self.0.get_mut(usize::from(index)) {
            *slot = true;
        }
    }

    /// Whether `index` is in the set.
    pub fn contains(&self, index: u16) -> bool {
        self.0.get(usize::from(index)).copied().unwrap_or(false)
    }

    /// The indices in the set, ascending.
    pub fn iter(&self) -> impl Iterator<Item = u16> + '_ {
        self.0
            .iter()
            .enumerate()
            .filter(|(_, held)| **held)
            .filter_map(|(index, _)| u16::try_from(index).ok())
    }
}

/// The columns of one block this host is still short of, in the order to repair them (D23).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColumnGap {
    /// The block the columns belong to, which is how a peer that never saw them is asked.
    pub block_root: [u8; 32],
    /// Every expected column that has not arrived, in repair order.
    pub missing: Vec<u16>,
    /// How many expected columns have arrived, which is what the threshold is counted against.
    pub have_count: usize,
}

/// A block, as everything here names one: its slot and its root together.
///
/// Two blocks can exist for one slot, from a reorg or from a proposer that equivocated, and the
/// root is what a column belongs to. Keying on both is what stops one block's columns clearing
/// what the other is owed.
type BlockKey = (u64, [u8; 32]);

/// What one host knows about the columns of the blocks its beacon node has seen.
pub struct CustodyTracker {
    columns: usize,
    threshold: usize,
    conforming: bool,
    blocks: HashMap<BlockKey, Block>,
    /// The keys of `blocks` in the order they were opened, so the bound takes the oldest.
    order: VecDeque<BlockKey>,
}

struct Block {
    expected: BitSet,
    have: BitSet,
    seen_at: Option<Instant>,
}

impl CustodyTracker {
    /// A tracker sized by `spec`, which is mainnet until the beacon node answers (CL-N3).
    pub fn new(spec: &SpecSnapshot) -> Self {
        let mut tracker = Self {
            columns: 0,
            threshold: 0,
            conforming: false,
            blocks: HashMap::new(),
            order: VecDeque::new(),
        };
        tracker.on_spec(spec);
        tracker
    }

    /// Resizes to a new snapshot and rechecks that one column subnet is one column.
    ///
    /// A column count that moved makes every set the wrong shape, so what is tracked goes with
    /// it rather than being reinterpreted under the new size.
    ///
    /// A snapshot where the two counts disagree makes "the subnets the beacon node subscribes
    /// to" stop naming a set of columns, and there is nothing to guess from, so column repair
    /// idles until a conforming snapshot arrives and says so once at error level.
    pub fn on_spec(&mut self, spec: &SpecSnapshot) {
        let columns = usize::try_from(spec.number_of_columns).unwrap_or(0);
        self.conforming = spec.data_column_sidecar_subnet_count == spec.number_of_columns;
        if !self.conforming {
            tracing::error!(
                number_of_columns = spec.number_of_columns,
                data_column_sidecar_subnet_count = spec.data_column_sidecar_subnet_count,
                "column repair is idle: a column subnet is not a column on this network"
            );
        }
        if columns != self.columns {
            self.blocks.clear();
            self.order.clear();
        }
        self.columns = columns;
        self.threshold = columns / 2;
    }

    /// Whether the last snapshot named one column per subnet, which is what makes the beacon
    /// node's subscriptions a set of columns at all.
    pub fn conforming(&self) -> bool {
        self.conforming
    }

    /// Whether the beacon node has reported holding column `index` of `block_root`, whichever
    /// slot it named. This is what a responder answers a column request on: the store's bytes
    /// are a peer's, and this is the beacon node's own word.
    pub fn holds(&self, block_root: [u8; 32], index: u16) -> bool {
        self.blocks
            .iter()
            .any(|((_, root), block)| *root == block_root && block.have.contains(index))
    }

    /// How many columns the beacon node needs before it can reconstruct and import (§2).
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// The columns the beacon node is subscribed to, as a set this tracker's size (T-014, D06).
    pub fn expected_columns(&self, sets: &SubscriptionSets) -> BitSet {
        self.column_set(
            sets.advertised
                .iter()
                .filter_map(|topic| match topic.kind() {
                    TopicKind::DataColumnSidecar(index) => Some(u16::from(*index)),
                    _ => None,
                }),
        )
    }

    /// `indices` as a set sized by the snapshot, which is how the reassembler's open columns
    /// reach [`missing_past_deadline`](Self::missing_past_deadline).
    pub fn column_set(&self, indices: impl IntoIterator<Item = u16>) -> BitSet {
        let mut set = BitSet::new(self.columns);
        for index in indices {
            set.insert(index);
        }
        set
    }

    /// Records that the beacon node accepted a block for `slot` at `now` and that `expected`
    /// columns are owed for it. The deadline every gap is measured from starts here.
    pub fn on_block(&mut self, slot: u64, root: [u8; 32], expected: BitSet, now: Instant) {
        let block = self.open((slot, root));
        block.expected = expected;
        block.seen_at = Some(now);
        self.trim();
    }

    /// Records that the beacon node holds column `index` of `block_root` for `slot`.
    ///
    /// A column that arrives before its block opens the entry, because the beacon node verifies
    /// a column on its own and does not wait for the block; the block is what puts a deadline on
    /// it, so nothing is repaired until one has been seen.
    pub fn on_column(&mut self, slot: u64, index: u16, block_root: [u8; 32]) {
        self.open((slot, block_root)).have.insert(index);
        self.trim();
    }

    /// Every block whose deadline has passed and which is still missing an expected column, with
    /// the columns to repair in the order to repair them.
    ///
    /// The threshold is not read here. It is how many of the columns listed are worth asking
    /// for, which is the scheduler's to spend (T-082's `tick_columns`), not a reason to leave a
    /// block out of the answer.
    ///
    /// `in_flight` is the columns the reassembler already holds chunks of. They are listed first
    /// because they complete with the fewest bytes, so the first `threshold - have_count` of
    /// `missing` are the cheapest way to the import threshold; the never-seen ones follow by
    /// index, which is the only order there is when nothing announces who holds what (D23).
    pub fn missing_past_deadline(
        &self,
        deadline: Duration,
        now: Instant,
        in_flight: &BitSet,
    ) -> Vec<ColumnGap> {
        if !self.conforming {
            return Vec::new();
        }
        let mut gaps: Vec<(BlockKey, ColumnGap)> = self
            .blocks
            .iter()
            .filter_map(|(key, block)| Some((*key, block.gap(key.1, deadline, now, in_flight)?)))
            .collect();
        gaps.sort_by_key(|(key, _)| *key);
        gaps.into_iter().map(|(_, gap)| gap).collect()
    }

    /// The entry for `key`, opening one if this host has none.
    fn open(&mut self, key: BlockKey) -> &mut Block {
        let columns = self.columns;
        self.blocks.entry(key).or_insert_with(|| {
            self.order.push_back(key);
            Block::new(columns)
        })
    }

    /// Keeps the newest [`TRACKED_BLOCKS`] entries by the order they were opened.
    fn trim(&mut self) {
        while self.blocks.len() > TRACKED_BLOCKS {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.blocks.remove(&oldest);
        }
    }
}

impl Block {
    fn gap(
        &self,
        root: [u8; 32],
        deadline: Duration,
        now: Instant,
        in_flight: &BitSet,
    ) -> Option<ColumnGap> {
        let seen_at = self.seen_at?;
        if now.saturating_duration_since(seen_at) < deadline {
            return None;
        }
        let wanted = |index: &u16| !self.have.contains(*index);
        let mut missing: Vec<u16> = self
            .expected
            .iter()
            .filter(wanted)
            .filter(|index| in_flight.contains(*index))
            .collect();
        missing.extend(
            self.expected
                .iter()
                .filter(wanted)
                .filter(|index| !in_flight.contains(*index)),
        );
        (!missing.is_empty()).then_some(ColumnGap {
            block_root: root,
            missing,
            have_count: self
                .have
                .iter()
                .filter(|index| self.expected.contains(*index))
                .count(),
        })
    }

    fn new(columns: usize) -> Self {
        Self {
            expected: BitSet::new(columns),
            have: BitSet::new(columns),
            seen_at: None,
        }
    }
}

/// One [`CustodyTracker`] shared by the event-stream task that writes it and the repair task
/// that reads it.
///
/// Every method takes the lock for one call and gives it back, so nothing here is held across an
/// `await`, the same rule [`SharedRecentLarge`](crate::recent::SharedRecentLarge) keeps.
///
/// The write side is [`on_block`](Self::on_block) and [`on_column`](Self::on_column), and
/// `overlay_bn::events` is the only caller of either. Reading the beacon node's subscriptions
/// here rather than at the call site is what keeps that true: the writer needs nothing but the
/// two numbers the event carried.
#[derive(Clone)]
pub struct SharedCustody(Arc<Shared>);

struct Shared {
    spec: watch::Receiver<SpecSnapshot>,
    sets: watch::Receiver<SubscriptionSets>,
    stats: Arc<dyn ColumnStats>,
    state: Mutex<State>,
}

/// The tracker and the snapshot it was last sized by, so a resize happens once per change
/// rather than once per call.
struct State {
    spec: SpecSnapshot,
    tracker: CustodyTracker,
}

impl SharedCustody {
    /// A tracker sized by whatever `spec` holds now, expecting whatever `sets` says the beacon
    /// node is subscribed to when a block arrives.
    pub fn new(
        spec: watch::Receiver<SpecSnapshot>,
        sets: watch::Receiver<SubscriptionSets>,
        stats: Arc<dyn ColumnStats>,
    ) -> Self {
        let snapshot = *spec.borrow();
        let state = State {
            spec: snapshot,
            tracker: CustodyTracker::new(&snapshot),
        };
        if !state.tracker.conforming() {
            stats.topic_mismatch();
        }
        Self(Arc::new(Shared {
            spec,
            sets,
            stats,
            state: Mutex::new(state),
        }))
    }

    /// One `block_gossip` event: the beacon node's gossip verification accepted this block.
    pub fn on_block(&self, slot: u64, root: [u8; 32], now: Instant) {
        let sets = self.0.sets.borrow().clone();
        let mut state = self.lock();
        let expected = state.tracker.expected_columns(&sets);
        state.tracker.on_block(slot, root, expected, now);
    }

    /// One `data_column_sidecar` event: the beacon node has verified this column.
    pub fn on_column(&self, slot: u64, index: u8, block_root: [u8; 32]) {
        self.lock()
            .tracker
            .on_column(slot, u16::from(index), block_root);
    }

    /// [`CustodyTracker::missing_past_deadline`] under the lock.
    pub fn gaps(&self, deadline: Duration, now: Instant, in_flight: &BitSet) -> Vec<ColumnGap> {
        self.lock()
            .tracker
            .missing_past_deadline(deadline, now, in_flight)
    }

    /// [`CustodyTracker::threshold`] under the lock.
    pub fn threshold(&self) -> usize {
        self.lock().tracker.threshold()
    }

    /// [`CustodyTracker::holds`] under the lock.
    pub fn holds(&self, block_root: [u8; 32], index: u8) -> bool {
        self.lock().tracker.holds(block_root, u16::from(index))
    }

    /// [`CustodyTracker::column_set`] under the lock.
    pub fn column_set(&self, indices: impl IntoIterator<Item = u16>) -> BitSet {
        self.lock().tracker.column_set(indices)
    }

    /// The state, resized first if the beacon node has reported a different snapshot since it
    /// was last touched. Every method goes through here, so a network whose column count moves
    /// under a running sidecar is noticed on the next event or the next tick, whichever comes
    /// first.
    fn lock(&self) -> MutexGuard<'_, State> {
        // Nothing that runs under this lock can panic, so a poisoned tracker cannot happen; if
        // one ever did, its sets would still be consistent and idling column repair for the life
        // of the process would be the worse failure.
        let mut state = self.0.state.lock().unwrap_or_else(PoisonError::into_inner);
        let snapshot = *self.0.spec.borrow();
        if state.spec != snapshot {
            state.spec = snapshot;
            state.tracker.on_spec(&snapshot);
            if !state.tracker.conforming() {
                self.0.stats.topic_mismatch();
            }
        }
        state
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;
    use crate::testlog::LOG;
    use crate::time::{Clock, FakeClock};
    use crate::topic::Topic;

    const DEADLINE: Duration = Duration::from_millis(250);

    /// The block every test here tracks.
    const ROOT: [u8; 32] = [7; 32];

    /// What `overlay_bn::spec::MAINNET` holds, written out here because this crate does not
    /// carry the beacon node's compiled defaults and a tracker has to be sized by something.
    fn mainnet() -> SpecSnapshot {
        SpecSnapshot {
            data_column_sidecar_subnet_count: 128,
            number_of_columns: 128,
            number_of_custody_groups: 128,
            custody_requirement: 4,
            max_payload_size: 10_485_760,
            seconds_per_slot: 12,
            slots_per_epoch: 32,
        }
    }

    /// A beacon node subscribed to the column subnets `indices` names and to nothing else.
    fn subscribed(indices: &[u16]) -> SubscriptionSets {
        let advertised = indices
            .iter()
            .map(|index| {
                Topic::parse(&format!(
                    "/eth2/6a95a1a9/data_column_sidecar_{index}/ssz_snappy"
                ))
                .expect("a topic in the only shape the parser takes")
            })
            .collect();
        SubscriptionSets {
            advertised,
            ..SubscriptionSets::default()
        }
    }

    /// A tracker at mainnet with a block for slot 1 seen now, expecting `indices`.
    fn tracking(clock: &FakeClock, indices: &[u16]) -> CustodyTracker {
        let mut tracker = CustodyTracker::new(&mainnet());
        let expected = tracker.expected_columns(&subscribed(indices));
        tracker.on_block(1, ROOT, expected, clock.now());
        tracker
    }

    fn gaps(tracker: &CustodyTracker, clock: &FakeClock) -> Vec<ColumnGap> {
        let none = tracker.column_set([]);
        tracker.missing_past_deadline(DEADLINE, clock.now(), &none)
    }

    /// Expected columns are the beacon node's own column subnets and nothing else (T-014, D06):
    /// a subnet it does not subscribe to is a column no repair should ever ask for.
    #[test]
    fn on_block_sets_expected_columns_from_subscriptions() {
        let clock = FakeClock::new();
        let tracker = tracking(&clock, &[0, 3, 7]);
        clock.advance(DEADLINE);

        assert_eq!(
            gaps(&tracker, &clock),
            vec![ColumnGap {
                block_root: ROOT,
                missing: vec![0, 3, 7],
                have_count: 0,
            }]
        );
    }

    /// A column the beacon node has verified is one no peer needs to be asked for, and it counts
    /// towards the half a node needs before it can reconstruct the rest (§2).
    #[test]
    fn on_column_clears_its_expectation() {
        let clock = FakeClock::new();
        let mut tracker = tracking(&clock, &[0, 3, 7]);
        clock.advance(DEADLINE);

        tracker.on_column(1, 3, ROOT);

        let reported = gaps(&tracker, &clock);
        let [gap] = reported.as_slice() else {
            panic!("one block is being tracked");
        };
        assert_eq!(gap.missing, vec![0, 7]);
        assert_eq!(gap.have_count, 1);
    }

    /// The deadline is what makes repair a tail backstop rather than a second delivery path: a
    /// column still on its way is one no peer should be asked for yet (§5.6, D24).
    #[test]
    fn missing_past_deadline_lists_gaps_only_after_deadline() {
        let clock = FakeClock::new();
        let tracker = tracking(&clock, &[0, 3, 7]);

        clock.advance(DEADLINE - Duration::from_millis(1));
        assert_eq!(gaps(&tracker, &clock), Vec::new());

        clock.advance(Duration::from_millis(1));
        assert_eq!(gaps(&tracker, &clock).len(), 1);
    }

    /// The ticket's worked example. Sixty columns are here, three more have chunks in flight and
    /// sixty-five were never seen, so the first three repairs are the three that finish with the
    /// fewest bytes and the rest go by index. The two groups are built from the highest and the
    /// lowest indices, so listing them in the order they were declared would not pass.
    #[test]
    fn prioritisation_puts_partially_received_columns_first_then_lowest_index() {
        let clock = FakeClock::new();
        let all: Vec<u16> = (0..128).collect();
        let mut tracker = tracking(&clock, &all);

        let partly_here = [5u16, 17, 90];
        let never_seen: Vec<u16> = {
            let mut highest: Vec<u16> = all
                .iter()
                .copied()
                .filter(|index| !partly_here.contains(index))
                .rev()
                .take(65)
                .collect();
            highest.sort_unstable();
            highest
        };
        for index in all
            .iter()
            .filter(|index| !partly_here.contains(index) && !never_seen.contains(index))
        {
            tracker.on_column(1, *index, ROOT);
        }
        let in_flight = tracker.column_set(partly_here);
        clock.advance(DEADLINE);

        let reported = tracker.missing_past_deadline(DEADLINE, clock.now(), &in_flight);

        let [gap] = reported.as_slice() else {
            panic!("one block is being tracked");
        };
        assert_eq!(gap.have_count, 60);
        assert_eq!(gap.missing[..3], [5, 17, 90]);
        assert_eq!(gap.missing[3..], never_seen);
    }

    /// The count the scheduler spends its budget against is how far this beacon node is from
    /// reconstructing, and that is counted in the columns it custodies. A beacon node holds
    /// columns outside its own subnets too, from its execution layer and from its own proposals;
    /// counting those would have the scheduler stop repairing before the node can import.
    #[test]
    fn have_count_ignores_columns_outside_the_expected_set() {
        let clock = FakeClock::new();
        let mut tracker = tracking(&clock, &[0, 3, 7]);
        clock.advance(DEADLINE);

        tracker.on_column(1, 3, ROOT);
        tracker.on_column(1, 42, ROOT);

        let reported = gaps(&tracker, &clock);
        let [gap] = reported.as_slice() else {
            panic!("one block is being tracked");
        };
        assert_eq!(gap.have_count, 1);
        assert_eq!(gap.missing, vec![0, 7]);
    }

    /// CL-N3: every column number comes from the beacon node. A network with twice mainnet's
    /// columns has twice the threshold and a set with room for an index mainnet has no column
    /// for, and nothing in this crate says 64 or 128.
    #[test]
    fn threshold_and_bitset_size_come_from_the_spec_snapshot() {
        let wide = SpecSnapshot {
            data_column_sidecar_subnet_count: 256,
            number_of_columns: 256,
            ..mainnet()
        };
        let clock = FakeClock::new();

        let mut tracker = CustodyTracker::new(&wide);
        assert_eq!(tracker.threshold(), 128);
        let expected = tracker.expected_columns(&subscribed(&[200]));
        assert!(expected.contains(200));
        tracker.on_block(1, ROOT, expected, clock.now());
        tracker.on_column(1, 200, ROOT);
        clock.advance(DEADLINE);
        assert_eq!(gaps(&tracker, &clock), Vec::new());

        let mainnet = CustodyTracker::new(&mainnet());
        assert_eq!(mainnet.threshold(), 64);
        assert!(!mainnet.expected_columns(&subscribed(&[200])).contains(200));
    }

    /// CL-N3's assertion. Expected columns are the beacon node's column subnets, so a network
    /// where a subnet is not a column leaves nothing to derive them from. The tracker says so
    /// once and reports nothing rather than repairing columns it guessed at.
    #[test]
    fn subnet_count_mismatch_logs_an_error_and_idles_column_repair() {
        let clock = FakeClock::new();
        let mark = LOG.len();
        let stats = Arc::new(CountingColumns::default());
        let custody = SharedCustody::new(
            watch::Sender::new(SpecSnapshot {
                data_column_sidecar_subnet_count: 64,
                number_of_columns: 128,
                ..mainnet()
            })
            .subscribe(),
            watch::Sender::new(subscribed(&[0, 3, 7])).subscribe(),
            stats.clone(),
        );
        custody.on_block(1, ROOT, clock.now());
        clock.advance(DEADLINE);

        let none = custody.column_set([]);
        assert_eq!(custody.gaps(DEADLINE, clock.now(), &none), Vec::new());

        let errors = LOG
            .since(mark)
            .lines()
            .filter(|line| line.contains("column repair is idle"))
            .count();
        assert_eq!(errors, 1);
        assert_eq!(stats.mismatches(), 1);
    }

    /// Counts the two series column repair adds, which are zero on an honest fleet (§12).
    #[derive(Default)]
    struct CountingColumns(AtomicU64);

    impl CountingColumns {
        fn mismatches(&self) -> u64 {
            self.0.load(Ordering::Relaxed)
        }
    }

    impl ColumnStats for CountingColumns {
        fn topic_mismatch(&self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
}
