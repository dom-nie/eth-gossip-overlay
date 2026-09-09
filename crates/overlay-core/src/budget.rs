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

use crate::config::Config;
use crate::pubqueue::{PUBLISH_LARGE_LANE_BYTES, PUBLISH_SMALL_LANE_ENTRIES};
use crate::ratelimit::TokenBucket;
use crate::reassemble;
use crate::recent::RECENT_MAX_BYTES;
use crate::seen::{SEEN_CAPACITY, SEEN_TTL};

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

/// The ceiling the shipped unit sets, `MemoryMax=1G` in
/// `deploy/systemd/eth-gossip-overlay.service`. What the budget is sized against on a host with
/// no cgroup file to read; a test in `eth-gossip-overlay` holds the unit to it.
///
/// It was 512M until MD-05. Nothing in Architecture.md or the panel record ever justified that
/// number, and the bounds it had to hold, D17's lanes and CL-N5's caches and DX-N3's windows,
/// each did; at 512M the rows for a 200-host fleet did not fit and the largest roster that did
/// was 181.
pub const MEMORY_MAX_DEFAULT: u64 = 1024 * 1024 * 1024;

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

/// How long gossipsub's duplicate cache holds a message id, as a multiple of [`SEEN_TTL`]:
/// CL-N5 set `duplicate_cache_time` to twice the seen cache, so at the same arrival rate it
/// holds twice as many ids.
pub const GOSSIPSUB_DUPLICATE_CACHE_MULTIPLE: u64 = 2;

/// How long gossipsub's message cache holds a whole message: `history_length` heartbeats of one
/// second each (CL-N5). Both numbers live in `overlay-bn`, which links libp2p and this crate
/// must not, so a test there holds the two parameters to these.
pub const GOSSIPSUB_HISTORY_SECS: u64 = 5;

/// What one QUIC stream may hold unread (DX-N3), and the floor the derived connection window
/// can never go below: a connection allowed less than one stream's worth would stall the single
/// stream it is carrying. It lives here rather than beside the rest of the transport parameters
/// because the budget's arithmetic is written against it and `overlay-core` links no quinn.
pub const STREAM_RECEIVE_WINDOW: u64 = 1024 * 1024;

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
/// measurement: nothing here grows with traffic. `docs/performance.md` carries the same table
/// generated from here. One row reads zero because the structure it names has not been built:
/// `by_root_cache` is T-085's, and that ticket fills its own row in rather than adding one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryBudget {
    /// Each structure's worst case, in the order the startup line prints them.
    pub rows: Vec<(&'static str, u64)>,
    /// The rows added up.
    pub bounded_bytes: u64,
    /// [`bounded_bytes`](Self::bounded_bytes) plus [`HEADROOM_PERCENT`], which is what a
    /// `MemoryMax` has to hold.
    pub total_bytes: u64,
    /// The ceiling the rows were derived against, from the cgroup or [`MEMORY_MAX_DEFAULT`].
    pub limit: u64,
    /// How many hosts the roster held, this one included.
    pub roster_len: usize,
    /// The per-connection QUIC receive window the rows leave room for (DX-N3). What
    /// `overlay-transport` puts on every connection, and what the `quic_receive_windows` row is
    /// this many times over.
    pub receive_window: u64,
}

impl MemoryBudget {
    /// The budget for a fleet of `roster_len` hosts, this one included, under a ceiling of
    /// `memory_max` bytes.
    pub fn compute(
        cfg: &Config,
        roster_len: usize,
        memory_max: u64,
        lanes: SendLaneBounds,
    ) -> Self {
        // Every row below is constants. `cfg` is here because the row that will read a key is
        // T-085's by-root cache, so that ticket adds a row rather than changes this signature.
        let _ = cfg;
        let peers = roster_len.saturating_sub(1) as u64;
        let mut rows = vec![
            ("seen_cache", SEEN_CAPACITY as u64 * SEEN_ENTRY_BYTES),
            ("recent_store", RECENT_MAX_BYTES as u64),
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
            ("gossipsub", gossipsub_caches()),
            // T-085's window is a config key that does not exist yet. The row is here at zero so
            // the table names the structure and that ticket has a place to put its arithmetic.
            ("by_root_cache", 0),
        ];
        // DX-N3 derives the one parameter that is not a constant: whatever the rows above leave
        // under the usable limit, shared out over the roster. The QUIC row below is that share
        // times the peers, so the remainder is spent once and never counted twice.
        let receive_window = usable(memory_max)
            .saturating_sub(rows.iter().map(|(_, bytes)| bytes).sum())
            / roster_len.max(1) as u64;
        let receive_window = receive_window.max(STREAM_RECEIVE_WINDOW);
        rows.push(("quic_receive_windows", peers * receive_window));

        let bounded_bytes = rows.iter().map(|(_, bytes)| bytes).sum();
        Self {
            bounded_bytes,
            total_bytes: bounded_bytes + bounded_bytes * HEADROOM_PERCENT / 100,
            rows,
            limit: memory_max,
            roster_len,
            receive_window,
        }
    }
}

/// What the rows may add up to: the limit less [`HEADROOM_PERCENT`], which is the 0.8 of
/// `MemoryMax` DX-N3 derives the receive window against. It is the same arithmetic
/// [`MemoryBudget::total_bytes`] runs the other way, so a budget that spends exactly this fits
/// exactly.
pub fn usable(memory_max: u64) -> u64 {
    memory_max * 100 / (100 + HEADROOM_PERCENT)
}

/// What gossipsub holds beside the sidecar's own structures (CL-N5): message ids in the
/// duplicate cache, and whole messages in the message cache.
///
/// Neither has a capacity bound, so both are the arrival rate times how long they keep an
/// entry. The rate is the one the seen cache is sized for, [`SEEN_CAPACITY`] entries over
/// [`SEEN_TTL`], since every message the beacon node forwards crosses the link once.
fn gossipsub_caches() -> u64 {
    let per_second = SEEN_CAPACITY as u64 / SEEN_TTL.as_secs().max(1);
    SEEN_CAPACITY as u64 * GOSSIPSUB_DUPLICATE_CACHE_MULTIPLE * SEEN_ENTRY_BYTES
        + per_second * GOSSIPSUB_HISTORY_SECS * SMALL_MESSAGE_BYTES
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

/// The ceiling to size the budget against: the cgroup's where there is one, and the shipped
/// unit's [`MEMORY_MAX_DEFAULT`] otherwise. An operator who runs the sidecar outside the unit
/// with no cgroup gets the number the documentation is written against rather than none.
pub fn memory_max() -> u64 {
    cgroup_memory_max().unwrap_or(MEMORY_MAX_DEFAULT)
}

/// Logs the budget at info and warns when it does not fit under the ceiling it was derived
/// against.
///
/// A warning is all it is: a sidecar that would exceed its ceiling still starts, because the
/// estimate is a worst case that a real fleet does not reach, and refusing to start would take
/// a beacon node's overlay away over arithmetic.
pub fn check(budget: &MemoryBudget) {
    tracing::info!(
        bounded_bytes = budget.bounded_bytes,
        total_bytes = budget.total_bytes,
        headroom_percent = HEADROOM_PERCENT,
        memory_max = budget.limit,
        roster = budget.roster_len,
        receive_window = budget.receive_window,
        rows = ?budget.rows,
        "memory budget"
    );
    if budget.total_bytes > budget.limit {
        tracing::warn!(
            total_bytes = budget.total_bytes,
            memory_max = budget.limit,
            roster = budget.roster_len,
            receive_window = budget.receive_window,
            "memory budget is above the limit: the QUIC receive window is already at its floor \
             for this roster, so raise MemoryMax or shrink the roster"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recent;
    use crate::testlog::LOG;

    /// T-033's lane bounds, which are what the wiring passes.
    const LANES: SendLaneBounds = SendLaneBounds {
        small_frames: 600,
        large_bytes: 1024 * 1024,
        large_bytes_max: 64 * 1024 * 1024,
    };

    /// The budget for a fleet of `roster` hosts under the shipped unit's ceiling.
    fn budget_for(roster: usize) -> MemoryBudget {
        MemoryBudget::compute(&Config::default(), roster, MEMORY_MAX_DEFAULT, LANES)
    }

    /// A fleet the size of the motivating deployment.
    fn budget() -> MemoryBudget {
        budget_for(200)
    }

    /// OPS-N4: the line goes out either way, because an operator sizing `MemoryMax` needs the
    /// number whether or not it currently fits. The warning is what an alert is written against,
    /// so it has to be absent while the budget fits.
    #[test]
    fn memory_budget_warns_only_when_it_is_over_the_limit() {
        let fits = budget_for(20);
        let mark = LOG.len();
        check(&fits);
        let under = LOG.since(mark);
        assert!(under.contains("memory budget"), "{under}");
        assert!(under.contains(&fits.total_bytes.to_string()), "{under}");
        assert!(under.contains(&fits.limit.to_string()), "{under}");
        assert!(!under.contains("WARN"), "{under}");

        // A roster far past what the other rows leave room for, so the receive window is at its
        // floor and the rows no longer fit under the ceiling they were derived against.
        let overflows = budget_for(4000);
        let mark = LOG.len();
        check(&overflows);
        let over = LOG.since(mark);
        assert!(over.contains("WARN"), "{over}");
        assert!(over.contains("4000"), "{over}");
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

    /// What every bounded structure holds at the shipped defaults for the fleet §2 describes,
    /// row by row, so a default that moves fails here naming itself rather than only moving the
    /// total. The numbers are the ones `docs/performance.md` prints.
    const AT_TWO_HUNDRED_HOSTS: &[(&str, u64)] = &[
        ("seen_cache", 12_800_000),
        ("recent_store", 27_238_400),
        ("publish_queue", 35_651_584),
        ("reassembler", 35_651_584),
        ("peer_send_lanes", 128_241_664),
        ("gossipsub", 34_132_480),
        ("by_root_cache", 0),
        ("quic_receive_windows", 582_351_212),
    ];

    /// OPS-N4's whole point: every bounded structure at its worst case, summed, fits under the
    /// ceiling with the headroom the design asks for. This test failing is the signal that a
    /// default somewhere grew, which is why it names the row and the difference rather than
    /// only the total.
    #[test]
    fn memory_budget_at_defaults_fits_under_eighty_percent_of_memory_max() {
        let budget = budget();

        let names: Vec<&str> = budget.rows.iter().map(|(name, _)| *name).collect();
        let wanted: Vec<&str> = AT_TWO_HUNDRED_HOSTS.iter().map(|(name, _)| *name).collect();
        assert_eq!(names, wanted, "the table is missing a row or has a new one");
        for ((name, bytes), (_, was)) in budget.rows.iter().zip(AT_TWO_HUNDRED_HOSTS) {
            assert_eq!(
                bytes,
                was,
                "{name} is {bytes} bytes, was {was}: {} by {}",
                if bytes > was { "grew" } else { "shrank" },
                bytes.abs_diff(*was)
            );
        }

        let usable = usable(MEMORY_MAX_DEFAULT);
        assert!(
            budget.bounded_bytes <= usable,
            "the rows come to {} bytes, {} over the {usable} the {} MiB limit leaves after \
             {HEADROOM_PERCENT}% headroom",
            budget.bounded_bytes,
            budget.bounded_bytes - usable,
            MEMORY_MAX_DEFAULT / (1024 * 1024),
        );
    }

    /// The bytes of one row of `budget`.
    fn row(budget: &MemoryBudget, name: &str) -> u64 {
        budget
            .rows
            .iter()
            .find(|(row, _)| *row == name)
            .map(|(_, bytes)| *bytes)
            .unwrap_or_else(|| panic!("the budget has no {name} row"))
    }

    /// OPS-N4: the by-root cache is a row of the one budget and turning it on is what fills it
    /// (T-085). The row is what the configured window adds on top of the five slots the repair
    /// store holds anyway, so the two rows together are the store's real bound and no byte is
    /// counted twice. The QUIC window is the remainder, so what an operator pays for the cache
    /// is a smaller window per connection rather than a larger total.
    #[test]
    fn enabling_the_cache_adds_its_row_to_the_startup_budget() {
        let off = budget();
        let mut on = Config::default();
        on.bn.by_root_cache.enabled = true;
        let on = MemoryBudget::compute(&on, 200, MEMORY_MAX_DEFAULT, LANES);

        assert_eq!(row(&off, "by_root_cache"), 0, "the cache ships off");
        let window = recent::window_bytes(Config::default().bn.by_root_cache.slots) as u64;
        assert_eq!(
            row(&on, "by_root_cache"),
            window - RECENT_MAX_BYTES as u64,
            "the row is the window less the five slots repair already holds"
        );
        assert_eq!(
            row(&off, "recent_store"),
            row(&on, "recent_store"),
            "the repair row does not move"
        );
        assert_eq!(
            off.receive_window - on.receive_window,
            row(&on, "by_root_cache") / 200,
            "the cache is paid for out of the derived receive window"
        );
        assert!(on.receive_window >= STREAM_RECEIVE_WINDOW);
    }

    /// The rows are what T-076's table grows from, so the sum has to be the rows and the total
    /// has to be the sum plus exactly the headroom OPS-N4 asks for.
    #[test]
    fn memory_budget_totals_the_rows_and_adds_the_headroom() {
        let budget = budget();

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
            MemoryBudget::compute(&Config::default(), roster, MEMORY_MAX_DEFAULT, lanes)
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
