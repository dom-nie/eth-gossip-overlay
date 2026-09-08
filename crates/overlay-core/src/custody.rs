//! Which data columns this host's beacon node wants for a slot, which have arrived, and which
//! to ask a peer for first once the deadline has passed (§5.6, §6.4, D23).
//!
//! A beacon node imports a block once it holds half the columns and can reconstruct the rest
//! (§2), so the numbers that matter are `NUMBER_OF_COLUMNS`, which sizes every set here, and
//! half of it, which is the point at which repairing another column stops helping. Both come
//! from the spec snapshot (CL-N3) and neither is written down in this crate.
//!
//! Expected columns are the beacon node's own column subnets, which only names a column while
//! one subnet is one column. [`CustodyTracker::on_spec`] asserts that on every snapshot and
//! idles rather than guess when it does not hold.
//!
//! Nothing here is a socket or a channel: one call answers what is missing and in what order,
//! and T-082's scheduler turns that into requests.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::header::Header;
use crate::spec::SpecSnapshot;
use crate::topic::{Topic, TopicKind};

/// How many slots of column state a host keeps. Long enough that a block still under repair is
/// still tracked (repair gives up 1.5 s after the deadline, D24) and short enough that the whole
/// structure is a handful of bitsets whatever the beacon node does.
pub const TRACKED_SLOTS: usize = 4;

/// A set of column indices.
///
/// A `bool` per index rather than packed bits: at the largest `NUMBER_OF_COLUMNS` anyone runs
/// the whole set is a few hundred bytes and a host holds [`TRACKED_SLOTS`] of them, so packing
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
    /// dropped rather than growing the set, so a payload claiming one costs nothing.
    pub fn insert(&mut self, index: u16) -> bool {
        match self.0.get_mut(usize::from(index)) {
            Some(slot) => {
                *slot = true;
                true
            }
            None => false,
        }
    }

    /// Whether `index` is in the set.
    pub fn contains(&self, index: u16) -> bool {
        self.0.get(usize::from(index)).copied().unwrap_or(false)
    }

    /// How many indices are in the set.
    pub fn count(&self) -> usize {
        self.0.iter().filter(|held| **held).count()
    }

    /// How many indices the set has room for.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the set has room for nothing, which is what a tracker sized by a snapshot with
    /// no columns in it holds.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
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
    /// Every expected column that has not arrived: the ones already partly here first, lowest
    /// index among them, then the ones never seen at all, lowest first.
    pub missing: Vec<u16>,
    /// How many expected columns have arrived, which is what the threshold is counted against.
    pub have_count: usize,
}

/// What one host knows about the columns of the slots it has seen.
pub struct CustodyTracker {
    columns: usize,
    threshold: usize,
    conforming: bool,
    slots: HashMap<u64, Block>,
}

struct Block {
    root: Option<[u8; 32]>,
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
            slots: HashMap::new(),
        };
        tracker.on_spec(spec);
        tracker
    }

    /// Resizes to a new snapshot and rechecks that one column subnet is one column.
    ///
    /// A snapshot where the two disagree makes "the subnets the beacon node subscribes to" stop
    /// naming a set of columns, and there is nothing to guess from, so column repair idles until
    /// a conforming snapshot arrives and says so once at error level.
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
            self.slots.clear();
        }
        self.columns = columns;
        self.threshold = columns / 2;
    }

    /// How many columns the beacon node needs before it can reconstruct and import (§2).
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// The columns the beacon node is subscribed to, as a set this tracker's size (T-014, D06).
    pub fn expected_columns(&self, advertised: &BTreeSet<Topic>) -> BitSet {
        self.column_set(advertised.iter().filter_map(|topic| match topic.kind() {
            TopicKind::DataColumnSidecar(index) => Some(u16::from(*index)),
            _ => None,
        }))
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

    /// Records that a block for `slot` was seen at `now` and that `expected` columns are owed
    /// for it. The deadline every gap is measured from starts here.
    pub fn on_block(&mut self, slot: u64, root: [u8; 32], expected: BitSet, now: Instant) {
        let columns = self.columns;
        let block = self
            .slots
            .entry(slot)
            .or_insert_with(|| Block::new(columns));
        block.root = Some(root);
        block.expected = expected;
        block.seen_at = Some(now);
        self.trim();
    }

    /// Records that column `index` of `block_root` arrived for `slot`.
    ///
    /// A column that arrives before its block opens the slot, because the columns of a block do
    /// not wait for it; the block is what puts a deadline on the slot, so nothing is repaired
    /// until one has been seen.
    pub fn on_column(&mut self, slot: u64, index: u16, block_root: [u8; 32]) {
        let columns = self.columns;
        let block = self
            .slots
            .entry(slot)
            .or_insert_with(|| Block::new(columns));
        block.root.get_or_insert(block_root);
        block.have.insert(index);
        self.trim();
    }

    /// Every block whose deadline has passed and which is still short of the threshold, with the
    /// columns to repair in the order to repair them.
    ///
    /// `in_flight` is the columns the reassembler already holds chunks of. They are listed first
    /// because they complete with the fewest bytes, so the first `threshold - have_count` of
    /// `missing` are the cheapest way to the import threshold; the never-seen ones follow by
    /// index, which is the only order there is when nothing announces who holds what (D23).
    pub fn missing_past_deadline(
        &mut self,
        deadline: Duration,
        now: Instant,
        in_flight: &BitSet,
    ) -> Vec<ColumnGap> {
        if !self.conforming {
            return Vec::new();
        }
        let mut gaps: Vec<(u64, ColumnGap)> = self
            .slots
            .iter()
            .filter_map(|(slot, block)| Some((*slot, block.gap(deadline, now, in_flight)?)))
            .collect();
        gaps.sort_by_key(|(slot, _)| *slot);
        gaps.into_iter().map(|(_, gap)| gap).collect()
    }

    /// Keeps the newest [`TRACKED_SLOTS`] slots and drops the rest. A slot the fleet has moved
    /// past is one no repair can still help, and the bound holds however far apart the slots a
    /// beacon node reports are.
    fn trim(&mut self) {
        if self.slots.len() <= TRACKED_SLOTS {
            return;
        }
        let mut slots: Vec<u64> = self.slots.keys().copied().collect();
        slots.sort_unstable();
        for slot in slots.iter().take(slots.len() - TRACKED_SLOTS) {
            self.slots.remove(slot);
        }
    }
}

impl Block {
    fn gap(&self, deadline: Duration, now: Instant, in_flight: &BitSet) -> Option<ColumnGap> {
        let root = self.root?;
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
            have_count: self.have.count(),
        })
    }

    fn new(columns: usize) -> Self {
        Self {
            root: None,
            expected: BitSet::new(columns),
            have: BitSet::new(columns),
            seen_at: None,
        }
    }
}

/// One [`CustodyTracker`] shared by the sites that fill it and the task that reads it.
///
/// Every method takes the lock for one call and gives it back, so nothing here is held across an
/// `await`, the same rule [`SharedRecentLarge`](crate::recent::SharedRecentLarge) keeps.
///
/// The expected set lives beside the tracker because the three sites that see a header do not
/// all have the beacon node's subscriptions: the repair task has them and refreshes it, and
/// `on_block` reads whatever the latest refresh left, which is what "evaluated when the block is
/// seen" comes to.
#[derive(Clone)]
pub struct SharedCustody(Arc<Mutex<Shared>>);

struct Shared {
    spec: SpecSnapshot,
    tracker: CustodyTracker,
    expected: BitSet,
}

impl SharedCustody {
    /// A tracker sized by `spec`, expecting nothing until the first refresh.
    pub fn new(spec: &SpecSnapshot) -> Self {
        let tracker = CustodyTracker::new(spec);
        Self(Arc::new(Mutex::new(Shared {
            spec: *spec,
            expected: BitSet::new(0),
            tracker,
        })))
    }

    /// Takes the current spec snapshot and the beacon node's advertised set.
    ///
    /// The snapshot is only handed on when it has changed, so a network whose subnet count does
    /// not match its column count says so once rather than once a tick.
    pub fn refresh(&self, spec: &SpecSnapshot, advertised: &BTreeSet<Topic>) {
        let mut shared = self.lock();
        if shared.spec != *spec {
            shared.spec = *spec;
            shared.tracker.on_spec(spec);
        }
        shared.expected = shared.tracker.expected_columns(advertised);
    }

    /// One header read at a recent-store insert, from any of its three sites.
    pub fn observe(&self, header: Header, now: Instant) {
        let mut shared = self.lock();
        match header {
            Header::Block { slot, root } => {
                let expected = shared.expected.clone();
                shared.tracker.on_block(slot, root, expected, now);
            }
            Header::Column {
                slot,
                index,
                block_root,
            } => shared.tracker.on_column(slot, u16::from(index), block_root),
        }
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

    /// [`CustodyTracker::column_set`] under the lock.
    pub fn column_set(&self, indices: impl IntoIterator<Item = u16>) -> BitSet {
        self.lock().tracker.column_set(indices)
    }

    fn lock(&self) -> MutexGuard<'_, Shared> {
        // Nothing that runs under this lock can panic, so a poisoned tracker cannot happen; if
        // one ever did, its sets would still be consistent and idling column repair for the life
        // of the process would be the worse failure.
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testlog::LOG;
    use crate::time::{Clock, FakeClock};

    const DEADLINE: Duration = Duration::from_millis(250);

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

    const ROOT: [u8; 32] = [7; 32];

    fn column_topics(indices: &[u16]) -> BTreeSet<Topic> {
        indices
            .iter()
            .map(|index| {
                Topic::parse(&format!(
                    "/eth2/6a95a1a9/data_column_sidecar_{index}/ssz_snappy"
                ))
                .expect("a topic in the only shape the parser takes")
            })
            .collect()
    }

    /// A tracker at mainnet with a block for slot 1 seen now, expecting `indices`.
    fn tracking(clock: &FakeClock, indices: &[u16]) -> CustodyTracker {
        let mut tracker = CustodyTracker::new(&mainnet());
        let expected = tracker.expected_columns(&column_topics(indices));
        tracker.on_block(1, ROOT, expected, clock.now());
        tracker
    }

    fn gaps(tracker: &mut CustodyTracker, clock: &FakeClock) -> Vec<ColumnGap> {
        let none = BitSet::new(mainnet().number_of_columns as usize);
        tracker.missing_past_deadline(DEADLINE, clock.now(), &none)
    }

    #[test]
    fn on_block_sets_expected_columns_from_subscriptions() {
        let clock = FakeClock::new();
        let mut tracker = tracking(&clock, &[0, 3, 7]);
        clock.advance(DEADLINE);

        assert_eq!(
            gaps(&mut tracker, &clock),
            vec![ColumnGap {
                block_root: ROOT,
                missing: vec![0, 3, 7],
                have_count: 0,
            }]
        );
    }

    #[test]
    fn on_column_clears_its_expectation() {
        let clock = FakeClock::new();
        let mut tracker = tracking(&clock, &[0, 3, 7]);
        clock.advance(DEADLINE);

        tracker.on_column(1, 3, ROOT);

        let reported = gaps(&mut tracker, &clock);
        let [gap] = reported.as_slice() else {
            panic!("one block is being tracked");
        };
        assert_eq!(gap.missing, vec![0, 7]);
        assert_eq!(gap.have_count, 1);
    }

    #[test]
    fn missing_past_deadline_lists_gaps_only_after_deadline() {
        let clock = FakeClock::new();
        let mut tracker = tracking(&clock, &[0, 3, 7]);

        clock.advance(DEADLINE - Duration::from_millis(1));
        assert_eq!(gaps(&mut tracker, &clock), Vec::new());

        clock.advance(Duration::from_millis(1));
        assert_eq!(gaps(&mut tracker, &clock).len(), 1);
    }

    /// The ticket's worked example. Sixty columns are here, three more have chunks in flight and
    /// sixty-five were never seen, so the first three repairs are the three that finish with the
    /// fewest bytes and the rest go by index. The two groups are built from the highest and the
    /// lowest indices, so listing them in the order they were declared would not pass.
    #[test]
    fn prioritisation_puts_partially_received_columns_first_then_lowest_index() {
        let clock = FakeClock::new();
        let all: Vec<u16> = (0..128).collect();
        let mut tracker = CustodyTracker::new(&mainnet());
        let expected = tracker.expected_columns(&column_topics(&all));
        tracker.on_block(1, ROOT, expected, clock.now());

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
        let mut in_flight = BitSet::new(all.len());
        for index in partly_here {
            in_flight.insert(index);
        }
        clock.advance(DEADLINE);

        let reported = tracker.missing_past_deadline(DEADLINE, clock.now(), &in_flight);

        let [gap] = reported.as_slice() else {
            panic!("one block is being tracked");
        };
        assert_eq!(gap.have_count, 60);
        assert_eq!(gap.missing[..3], [5, 17, 90]);
        assert_eq!(gap.missing[3..], never_seen);
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
        let expected = tracker.expected_columns(&column_topics(&[200]));
        assert!(expected.contains(200));
        tracker.on_block(1, ROOT, expected, clock.now());
        tracker.on_column(1, 200, ROOT);
        clock.advance(DEADLINE);
        assert_eq!(
            tracker.missing_past_deadline(DEADLINE, clock.now(), &BitSet::new(256)),
            Vec::new()
        );

        let mainnet = CustodyTracker::new(&mainnet());
        assert_eq!(mainnet.threshold(), 64);
        assert!(
            !mainnet
                .expected_columns(&column_topics(&[200]))
                .contains(200)
        );
    }

    /// CL-N3's assertion. Expected columns are the beacon node's column subnets, so a network
    /// where a subnet is not a column leaves nothing to derive them from. The tracker says so
    /// once and reports nothing rather than repairing columns it guessed at.
    #[test]
    fn subnet_count_mismatch_logs_an_error_and_idles_column_repair() {
        let clock = FakeClock::new();
        let mark = LOG.len();
        let mut tracker = CustodyTracker::new(&SpecSnapshot {
            data_column_sidecar_subnet_count: 64,
            number_of_columns: 128,
            ..mainnet()
        });
        let expected = tracker.expected_columns(&column_topics(&[0, 3, 7]));
        tracker.on_block(1, ROOT, expected, clock.now());
        clock.advance(DEADLINE);

        assert_eq!(gaps(&mut tracker, &clock), Vec::new());

        let errors = LOG
            .since(mark)
            .lines()
            .filter(|line| line.contains("column repair is idle"))
            .count();
        assert_eq!(errors, 1);
    }

    /// The bound on what a host keeps: a slot the fleet has moved several past is one no repair
    /// can still help, so it goes and the newest [`TRACKED_SLOTS`] stay.
    #[test]
    fn gaps_are_garbage_collected_after_n_slots() {
        let clock = FakeClock::new();
        let mut tracker = CustodyTracker::new(&mainnet());
        let expected = tracker.expected_columns(&column_topics(&[0, 3, 7]));
        for slot in 1..=(TRACKED_SLOTS as u64 + 1) {
            tracker.on_block(slot, ROOT, expected.clone(), clock.now());
        }
        clock.advance(DEADLINE);

        assert_eq!(gaps(&mut tracker, &clock).len(), TRACKED_SLOTS);
    }
}
