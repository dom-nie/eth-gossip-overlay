//! What one sibling may make this host fan out (DX-N3, OPS-N2).
//!
//! A second hop is work a peer asks this host to do: a `RELAY` batch it re-fans in its own
//! region (T-063), a chunk it forwards to the rest of its region (T-073). A peer that asks for
//! far more of it than a slot's traffic can account for is either broken or hostile, and the
//! answer to both is the same: deliver what arrived locally, do not fan it out, and count it.
//! A peer that keeps it up for more than [`SUSTAINED_VIOLATION`] loses the connection and comes
//! back through the ordinary reconnect backoff.
//!
//! Nothing in v1 charges the bucket, because nothing in v1 fans out what it receives (§3
//! principle 1). It is built, tested and wired into the receiver here so that T-063 and T-073
//! have one budget to charge rather than one each.
//!
//! `now` is a parameter everywhere, so the bucket holds no clock and a test drives it with plain
//! `Instant` arithmetic.

use std::path::Path;
use std::time::{Duration, Instant};

use crate::pubqueue::{PUBLISH_LARGE_LANE_BYTES, PUBLISH_SMALL_LANE_ENTRIES};
use crate::ratelimit::TokenBucket;
use crate::reassemble;
use crate::seen::SEEN_CAPACITY;

/// How long a peer may stay over its budget before the connection is closed with
/// `RateExceeded` (DX-N3).
pub const SUSTAINED_VIOLATION: Duration = Duration::from_secs(10);

/// What one slot of large-class traffic is taken to be: a block plus 128 data columns with
/// parity, at T-071's sizes. An estimate the budget is derived from, not a limit anything is
/// measured against.
pub const LARGE_BYTES_PER_SLOT_ESTIMATE: usize = 6 * 1024 * 1024;

/// Which second hop the bytes were for, the `kind` label of `fanout_suppressed_total`.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum FanoutKind {
    /// A `RELAY` batch to re-fan inside this host's region (T-063).
    Relay,
    /// A chunk to forward to the rest of this host's region (T-073).
    Chunk,
}

impl FanoutKind {
    /// The label value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Relay => "relay",
            Self::Chunk => "chunk",
        }
    }
}

/// What a charge came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Charge {
    /// The bucket had the bytes. Fan the traffic out.
    Allowed,
    /// It did not. Deliver locally, fan nothing out, and count
    /// `fanout_suppressed_total{peer, kind}`.
    Suppressed,
    /// It has not had them for more than [`SUSTAINED_VIOLATION`]. The same as `Suppressed`, and
    /// the receiver closes the connection with `RateExceeded`.
    CloseRateExceeded,
}

/// One peer's fan-out budget: a token bucket over the bytes that trigger a second hop, and how
/// long the peer has been over it.
#[derive(Clone, Debug)]
pub struct FanoutBudget {
    bucket: TokenBucket,
    violation_since: Option<Instant>,
}

impl FanoutBudget {
    /// The budget a peer gets, from the fleet it is part of.
    ///
    /// Capacity is one slot's worth of what a single sibling can honestly make this host fan
    /// out: four times the share of a slot's large-class traffic that falls to one host, rounded
    /// up to whole chunks because a chunk is the unit anything arrives in. Refill is that
    /// capacity per slot, so a peer at the expected rate never runs dry and one at four times it
    /// is over budget inside a slot.
    ///
    /// ```text
    /// capacity = ceil(4 * LARGE_BYTES_PER_SLOT_ESTIMATE / roster_size / chunk_bytes) * chunk_bytes
    /// refill   = capacity / slot_secs bytes per second, rounded down
    /// ```
    ///
    /// A roster of one, a chunk size of zero or a slot of zero seconds are not configurations
    /// this sidecar runs, but they are arithmetic this must not divide by, so each floor is 1.
    pub fn default_for(
        roster_size: usize,
        chunk_bytes: usize,
        slot_secs: u64,
        now: Instant,
    ) -> Self {
        let chunk_bytes = chunk_bytes.max(1) as u64;
        let share = (4 * LARGE_BYTES_PER_SLOT_ESTIMATE / roster_size.max(1)) as u64;
        let capacity = share.div_ceil(chunk_bytes) * chunk_bytes;
        Self::new(capacity / slot_secs.max(1), capacity, now)
    }

    /// A budget of `capacity` bytes refilling at `per_second`, for a caller that has the two
    /// numbers already. [`default_for`](Self::default_for) is what the sidecar wires; a test
    /// reaches the bound with a bucket it can empty in one batch instead of a slot's traffic.
    pub fn new(per_second: u64, capacity: u64, now: Instant) -> Self {
        Self {
            bucket: TokenBucket::new(per_second, capacity, now),
            violation_since: None,
        }
    }

    /// Takes `bytes` out of the bucket, refilled up to `now`.
    ///
    /// `kind` is the `fanout_suppressed_total{peer, kind}` label the caller counts a refusal
    /// under. One bucket covers every kind: the budget is what one peer may make this host fan
    /// out, however it asked.
    pub fn charge(&mut self, _kind: FanoutKind, bytes: usize, now: Instant) -> Charge {
        if self.bucket.try_take(bytes as u64, now) {
            self.violation_since = None;
            return Charge::Allowed;
        }
        let since = *self.violation_since.get_or_insert(now);
        if now.saturating_duration_since(since) > SUSTAINED_VIOLATION {
            Charge::CloseRateExceeded
        } else {
            Charge::Suppressed
        }
    }
}

/// The cgroup v2 file holding the memory ceiling this process runs under. Absent on a host
/// without cgroup v2, which includes every developer machine that is not Linux.
const CGROUP_MEMORY_MAX: &str = "/sys/fs/cgroup/memory.max";

/// What one seen-cache entry costs: the 20-byte id in the set, the same id and an `Instant` in
/// the order queue, and the slack a hash table carries around its live entries.
pub const SEEN_ENTRY_BYTES: u64 = 64;

/// What one queued small message is taken to cost: §10's ~240-byte attestation with the frame
/// header and allocator rounding around it. An estimate the budget is derived from, not a limit
/// anything is measured against.
pub const SMALL_MESSAGE_BYTES: u64 = 512;

/// What one message in flight costs beside its chunks: a `(index, Bytes)` pair per chunk, which
/// is a hundred and ten of them for a 200 KB block at the shipped chunk size, plus the two
/// index bitmaps, the peers that sent a chunk, and the map and deque entries holding it all.
pub const REASSEMBLY_ENTRY_BYTES: u64 = 4096;

/// The headroom OPS-N4 asks the budget to leave under `MemoryMax`, as a percentage.
pub const HEADROOM_PERCENT: u64 = 25;

/// The per-peer send-lane bounds (T-033). They live in `overlay-transport`, which this crate
/// must not depend on, so the wiring passes them in rather than this reaching for them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SendLaneBounds {
    /// Frames one peer's small lane holds before it drops.
    pub small_frames: usize,
    /// Bytes one peer's large lane holds before it drops.
    pub large_bytes: usize,
    /// Bytes every peer's large lanes hold between them, which is the process-wide cap.
    pub large_bytes_max: usize,
}

/// What the sidecar's bounded structures hold at once in the worst case, which is the number an
/// operator sizes `MemoryMax` against (OPS-N4).
///
/// Every row is a structure with a bound in code, so the sum is a ceiling rather than a
/// measurement: nothing here grows with traffic. T-076 owns the table in `docs/performance.md`
/// and adds a row as each remaining structure lands (the recent store, the by-root cache,
/// gossipsub's duplicate cache and message cache, and the QUIC receive windows once it sets
/// them); this release has the four that exist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryBudget {
    /// Each structure's worst case, in the order the startup line prints them.
    pub rows: Vec<(&'static str, u64)>,
    /// The rows added up.
    pub bounded_bytes: u64,
    /// [`bounded_bytes`](Self::bounded_bytes) plus [`HEADROOM_PERCENT`], which is what a
    /// `MemoryMax` has to hold.
    pub total_bytes: u64,
}

impl MemoryBudget {
    /// The budget for a fleet of `roster_size` hosts, this one included.
    pub fn compute(roster_size: usize, lanes: SendLaneBounds) -> Self {
        let peers = roster_size.saturating_sub(1) as u64;
        let rows = vec![
            ("seen_cache", SEEN_CAPACITY as u64 * SEEN_ENTRY_BYTES),
            (
                "publish_queue",
                PUBLISH_SMALL_LANE_ENTRIES as u64 * SMALL_MESSAGE_BYTES
                    + PUBLISH_LARGE_LANE_BYTES as u64,
            ),
            (
                "reassembler",
                reassemble::MAX_BYTES as u64
                    + reassemble::MAX_IN_FLIGHT as u64 * REASSEMBLY_ENTRY_BYTES,
            ),
            (
                "peer_send_lanes",
                peers * lanes.small_frames as u64 * SMALL_MESSAGE_BYTES
                    + (peers * lanes.large_bytes as u64).min(lanes.large_bytes_max as u64),
            ),
        ];
        let bounded_bytes = rows.iter().map(|(_, bytes)| bytes).sum();
        Self {
            bounded_bytes,
            total_bytes: bounded_bytes + bounded_bytes * HEADROOM_PERCENT / 100,
            rows,
        }
    }
}

/// The memory ceiling this process runs under, from cgroup v2. `None` where the file is absent
/// or holds `max`, which is a host with no ceiling to compare the budget against.
// mutants::skip: the whole body is one absolute path no test can stage, and what the answer is
// on the machine running the suite is the machine's, not the code's. `read_memory_max` is the
// half that decides anything and it is under test with a file of its own.
#[cfg_attr(test, mutants::skip)]
pub fn cgroup_memory_max() -> Option<u64> {
    read_memory_max(Path::new(CGROUP_MEMORY_MAX))
}

/// [`cgroup_memory_max`] with the path passed in, so a test can stage a file without a cgroup.
pub fn read_memory_max(path: &Path) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Logs the budget at info and warns when it does not fit under `limit`.
///
/// A warning is all it is: a sidecar that would exceed its ceiling still starts, because the
/// estimate is a worst case that a real fleet does not reach, and refusing to start would take
/// a beacon node's overlay away over arithmetic.
pub fn check(budget: &MemoryBudget, limit: Option<u64>) {
    let ceiling = limit.map_or_else(|| "none".to_owned(), |bytes| bytes.to_string());
    tracing::info!(
        bounded_bytes = budget.bounded_bytes,
        total_bytes = budget.total_bytes,
        headroom_percent = HEADROOM_PERCENT,
        memory_max = ceiling,
        rows = ?budget.rows,
        "memory budget"
    );
    if limit.is_some_and(|limit| budget.total_bytes > limit) {
        tracing::warn!(
            total_bytes = budget.total_bytes,
            memory_max = ceiling,
            "memory budget is above the cgroup limit; raise MemoryMax or shrink the roster"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testlog::LOG;

    /// A fleet the size of the motivating deployment, at T-033's lane bounds.
    fn budget() -> MemoryBudget {
        MemoryBudget::compute(
            200,
            SendLaneBounds {
                small_frames: 600,
                large_bytes: 1024 * 1024,
                large_bytes_max: 64 * 1024 * 1024,
            },
        )
    }

    /// OPS-N4: the line goes out either way, because an operator sizing `MemoryMax` needs the
    /// number whether or not it currently fits. The warning is what an alert is written against,
    /// so it has to be absent when the budget does fit and absent again when there is no ceiling
    /// to compare it with, which is every host without cgroup v2 and every cgroup set to `max`.
    #[test]
    fn memory_budget_warns_only_when_above_cgroup_max() {
        let budget = budget();
        let over = budget.total_bytes - 1;
        let under = budget.total_bytes;

        let mark = LOG.len();
        check(&budget, Some(over));
        let above = LOG.since(mark);
        assert!(above.contains("memory budget"), "{above}");
        assert!(above.contains(&budget.total_bytes.to_string()), "{above}");
        assert!(above.contains(&over.to_string()), "{above}");
        assert!(above.contains("WARN"), "{above}");

        let mark = LOG.len();
        check(&budget, Some(under));
        let fits = LOG.since(mark);
        assert!(fits.contains(&budget.total_bytes.to_string()), "{fits}");
        assert!(!fits.contains("WARN"), "{fits}");

        let mark = LOG.len();
        check(&budget, None);
        let unlimited = LOG.since(mark);
        assert!(unlimited.contains("none"), "{unlimited}");
        assert!(!unlimited.contains("WARN"), "{unlimited}");
    }

    /// The `None` cases, which is what a host without cgroup v2 and a cgroup with no ceiling
    /// both look like. Every developer machine that is not Linux is the first of them.
    #[test]
    fn memory_max_is_none_without_a_file_and_without_a_ceiling() {
        let dir = tempfile::tempdir().unwrap();
        let unlimited = dir.path().join("memory.max");
        std::fs::write(&unlimited, "max\n").unwrap();
        let numeric = dir.path().join("limited");
        std::fs::write(&numeric, "536870912\n").unwrap();

        assert_eq!(read_memory_max(&dir.path().join("absent")), None);
        assert_eq!(read_memory_max(&unlimited), None);
        assert_eq!(read_memory_max(&numeric), Some(536_870_912));
    }

    /// The rows are what T-076's table grows from, so the sum has to be the rows and the total
    /// has to be the sum plus exactly the headroom OPS-N4 asks for.
    #[test]
    fn memory_budget_totals_the_rows_and_adds_the_headroom() {
        let budget = budget();

        assert_eq!(budget.rows.len(), 4);
        assert!(budget.rows.iter().any(|(name, _)| *name == "reassembler"));
        assert_eq!(
            budget.bounded_bytes,
            budget.rows.iter().map(|(_, bytes)| bytes).sum::<u64>()
        );
        assert_eq!(
            budget.total_bytes,
            budget.bounded_bytes * (100 + HEADROOM_PERCENT) / 100
        );
    }

    /// The per-peer lanes are the only row a roster changes, and the process-wide cap is what
    /// keeps a large fleet from multiplying its way past the budget (DX-N4).
    #[test]
    fn peer_send_lanes_grow_with_the_roster_up_to_the_process_cap() {
        let lanes = SendLaneBounds {
            small_frames: 600,
            large_bytes: 1024 * 1024,
            large_bytes_max: 8 * 1024 * 1024,
        };
        let row = |roster: usize| {
            MemoryBudget::compute(roster, lanes)
                .rows
                .iter()
                .find(|(name, _)| *name == "peer_send_lanes")
                .map(|(_, bytes)| *bytes)
                .unwrap()
        };

        assert_eq!(row(1), 0, "a fleet of one has no peers to queue for");
        assert!(row(5) > row(2));
        assert_eq!(
            row(200) - row(100),
            100 * 600 * SMALL_MESSAGE_BYTES,
            "past the cap only the small lanes still grow"
        );
    }

    /// The label an alert is keyed on (§12), so the strings are pinned rather than derived.
    #[test]
    fn fanout_kinds_are_the_metric_labels_they_are_counted_under() {
        assert_eq!(FanoutKind::Relay.as_str(), "relay");
        assert_eq!(FanoutKind::Chunk.as_str(), "chunk");
    }

    /// The connection goes only once a peer has been over budget for longer than the bound, so
    /// a peer that recovers exactly at it keeps its connection. The close costs a reconnect and
    /// a backoff, and a burst that lands on the boundary has not earned one.
    #[test]
    fn a_violation_closes_only_after_it_has_lasted_longer_than_the_bound() {
        let went_over = Instant::now();
        let mut budget = FanoutBudget::default_for(200, 2048, 12, went_over);
        let over_budget = 4 * 1024 * 1024;

        assert_eq!(
            budget.charge(FanoutKind::Chunk, over_budget, went_over),
            Charge::Suppressed
        );
        assert_eq!(
            budget.charge(
                FanoutKind::Chunk,
                over_budget,
                went_over + SUSTAINED_VIOLATION
            ),
            Charge::Suppressed
        );
        assert_eq!(
            budget.charge(
                FanoutKind::Chunk,
                over_budget,
                went_over + SUSTAINED_VIOLATION + Duration::from_nanos(1)
            ),
            Charge::CloseRateExceeded
        );
    }

    /// A peer that comes back inside its budget starts a fresh window, so drifting in and out of
    /// it over a slot never adds up to a close.
    #[test]
    fn a_charge_that_fits_clears_the_violation() {
        let went_over = Instant::now();
        let mut budget = FanoutBudget::default_for(200, 2048, 12, went_over);
        let over_budget = 4 * 1024 * 1024;

        assert_eq!(
            budget.charge(FanoutKind::Chunk, over_budget, went_over),
            Charge::Suppressed
        );
        assert_eq!(
            budget.charge(FanoutKind::Chunk, 1, went_over),
            Charge::Allowed
        );
        assert_eq!(
            budget.charge(
                FanoutKind::Chunk,
                over_budget,
                went_over + SUSTAINED_VIOLATION + Duration::from_secs(1)
            ),
            Charge::Suppressed
        );
    }

    /// A slot's traffic in one burst goes through, and the byte after it does not until the
    /// bucket has refilled. The numbers are the arithmetic in [`FanoutBudget::default_for`] for
    /// a 200-host fleet at T-071's chunk size and mainnet's slot: 4 x 6 MiB over 200 hosts is
    /// 125,829 bytes, which is 62 whole 2 KiB chunks, refilled over twelve seconds.
    #[test]
    fn fanout_budget_allows_a_slot_burst_then_suppresses_and_refills() {
        let slot_start = Instant::now();
        let mut budget = FanoutBudget::default_for(200, 2048, 12, slot_start);

        assert_eq!(
            budget.charge(FanoutKind::Chunk, 62 * 2048, slot_start),
            Charge::Allowed
        );
        assert_eq!(
            budget.charge(FanoutKind::Chunk, 1, slot_start),
            Charge::Suppressed
        );

        let a_second_later = slot_start + Duration::from_secs(1);
        assert_eq!(
            budget.charge(FanoutKind::Relay, 62 * 2048 / 12, a_second_later),
            Charge::Allowed
        );
        assert_eq!(
            budget.charge(FanoutKind::Relay, 1, a_second_later),
            Charge::Suppressed
        );
    }
}
