//! The one line per large message that the canary is judged on (§12, D32).
//!
//! An event is an ordinary `tracing` record: same subscriber, same stream, same format as every
//! other log line, told apart by its `event` field. Fleet spread and overlay win rate are then
//! Loki queries over `| json | event="first_arrival"` joined by message id across hosts, with no
//! second writer to configure and no metric label carrying a message id. `docs/events.md` holds
//! the schema and the queries.
//!
//! The subscriber itself belongs to the binary (`eth_gossip_overlay::logging`); emitting is plain
//! `tracing`, so the two callsites in `overlay-bn` and `overlay-transport` reach it without
//! either of them depending on the binary crate.

use std::collections::BTreeMap;
use std::fmt::Write;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::watch;

use crate::header::Header;
use crate::msgid::MessageId;
use crate::roster::{Hostname, SelfIdentity};
use crate::spec::SpecSnapshot;
use crate::time::Clock;
use crate::topic::{Class, Topic};

/// Where events go. Ordinary logs keep their module target, so a reader can select on either
/// the target or the `event` field.
const TARGET: &str = "overlay::event";

/// The `event` field of an arrival.
const FIRST_ARRIVAL: &str = "first_arrival";

/// The `event` field of an import.
const IMPORT: &str = "import";

/// What a host with no site label logs, matching the metrics convention that an absent label
/// is the empty string and never a literal like `none`.
const ABSENT_SITE: &str = "";

/// One message reaching this host for the first time.
///
/// Built at whichever of the two receive paths won, and only for a message the seen cache had
/// not held: a duplicate is the same message arriving again, which the spread query would
/// count as a second host.
pub struct FirstArrival<'a> {
    /// The gossipsub message id, which is what joins this line to the same message on every
    /// other host.
    pub id: MessageId,
    /// The transport class. Only [`Class::Large`] is logged.
    pub class: Class,
    /// The topic the message arrived on.
    pub topic: &'a Topic,
    /// Who this host is, which the query groups and compares by.
    pub node: &'a SelfIdentity,
    /// When it arrived, read from the injected clock at the earliest point on the path.
    pub at: SystemTime,
    /// Which side it came in on.
    pub source: Source<'a>,
    /// What the payload's header said, when there was a decoder to read it (T-083). A build
    /// without the `column-repair` feature has none, and the line carries no slot.
    pub header: Option<Header>,
}

/// The side a message arrived from. Win rate is the share of these that are
/// [`Overlay`](Self::Overlay).
pub enum Source<'a> {
    /// The beacon node forwarded it over the local gossipsub link.
    Bn,
    /// A fleet peer sent it over the overlay.
    Overlay {
        /// The roster hostname of the peer whose stream carried it.
        origin: &'a Hostname,
    },
}

/// Logs `arrival`, unless it is small class.
///
/// Two `tracing` calls rather than one with an `Option`, so a line from the beacon node has no
/// `origin_peer` key at all instead of a null one that every query would have to filter.
pub fn emit_first_arrival(arrival: &FirstArrival<'_>) {
    let class = match arrival.class {
        // Small messages travel batched and number in the tens of thousands a slot; the class
        // that decides the canary is the large one (§13).
        Class::Small => return,
        Class::Large => "large",
    };
    let node = arrival.node;
    let site = node.site.as_deref().unwrap_or(ABSENT_SITE);
    let first_arrival_ns = epoch_nanos(arrival.at);
    // One arm per combination of what the line carries, rather than one call with `Option`
    // fields: a line from the beacon node has no `origin_peer` key at all instead of a null one
    // every query would have to filter, and a payload with no header carries no `slot` key.
    macro_rules! arrival {
        ($($rest:tt)*) => {
            tracing::info!(
                target: TARGET,
                event = FIRST_ARRIVAL,
                msg_id = %arrival.id,
                class,
                topic = %arrival.topic,
                node = %node.hostname,
                region = %node.region,
                site,
                first_arrival_ns,
                $($rest)*
            )
        };
    }
    match (&arrival.source, arrival.header) {
        (Source::Bn, None) => arrival!(source = "bn"),
        (Source::Bn, Some(header)) => arrival!(
            source = "bn",
            slot = header.slot(),
            block_root = %hex(header.block_root()),
        ),
        (Source::Overlay { origin }, None) => arrival!(
            source = "overlay",
            origin_peer = %origin,
        ),
        (Source::Overlay { origin }, Some(header)) => arrival!(
            source = "overlay",
            origin_peer = %origin,
            slot = header.slot(),
            block_root = %hex(header.block_root()),
        ),
    }
}

/// One block the beacon node has imported, and what this host knows about when the block first
/// went past it.
///
/// Telemetry and nothing else. §2's point is that the 200 to 500 ms `newPayload` and column
/// verification take is time the overlay cannot win back, and an operator who cannot see it per
/// host cannot tell how much of the gain is being spent there.
pub struct ImportEvent<'a> {
    /// The slot the block was proposed for.
    pub slot: u64,
    /// The block's root. T-083 puts the same root on the arrival line, in the same rendering, so
    /// the two events join on it.
    pub block_root: [u8; 32],
    /// When the beacon node reported the import, read from the injected clock.
    pub imported_at: SystemTime,
    /// When the block first reached this host, if it did. `None` is a block the overlay missed
    /// entirely, which is worth knowing about.
    pub first_arrival_at: Option<SystemTime>,
    /// Which side got there first, when there was an arrival to say.
    pub source: Option<Source<'a>>,
    /// Arrival to import in milliseconds, measured on the monotonic clock rather than by
    /// subtracting the two wall readings, which a clock step would corrupt.
    pub lag_ms: Option<u64>,
}

/// Logs `import`.
///
/// One arm per combination for the same reason [`emit_first_arrival`] has them: a block with no
/// arrival record carries no lag, no arrival and no source key at all rather than three null
/// ones, and a line from the beacon node has no `origin_peer`.
pub fn emit_import(import: &ImportEvent<'_>) {
    let slot = import.slot;
    let block_root = hex(import.block_root);
    let imported_ns = epoch_nanos(import.imported_at);
    macro_rules! import {
        ($($rest:tt)*) => {
            tracing::info!(
                target: TARGET,
                event = IMPORT,
                slot,
                block_root = %block_root,
                imported_ns,
                $($rest)*
            )
        };
    }
    let (Some(at), Some(source), Some(lag_ms)) =
        (import.first_arrival_at, &import.source, import.lag_ms)
    else {
        return import!(matched = false);
    };
    let first_arrival_ns = epoch_nanos(at);
    match source {
        Source::Bn => import!(matched = true, first_arrival_ns, lag_ms, source = "bn"),
        Source::Overlay { origin } => import!(
            matched = true,
            first_arrival_ns,
            lag_ms,
            source = "overlay",
            origin_peer = %origin,
        ),
    }
}

/// How many slots of arrival records to keep: long enough that a block cannot still be waiting
/// to be imported, short enough that the map stays a handful of entries.
const RETENTION_SLOTS: u64 = 8;

/// When a block first reached this host, and over which side.
struct Arrival {
    /// The wall reading, which is the only form that means anything on another host.
    at: SystemTime,
    /// The same moment on the monotonic clock. The lag is measured on this one, because
    /// subtracting two wall readings gives whatever a clock step did to them in between.
    seen: Instant,
    /// The peer whose stream carried it, or `None` when the beacon node's own gossip won.
    origin: Option<Hostname>,
}

/// Which blocks reached this host lately, so an import event can be turned into a lag.
///
/// It lives here rather than beside the event stream that reads it because both receive paths
/// file into it, and one of them is in `overlay-transport`, which has never heard of the beacon
/// node.
pub struct Arrivals {
    clock: Arc<dyn Clock>,
    spec: watch::Receiver<SpecSnapshot>,
    seen: Mutex<BTreeMap<[u8; 32], Arrival>>,
}

impl Arrivals {
    /// An empty keeper. `spec` is read fresh on every use, so a beacon node that reports a
    /// different `SECONDS_PER_SLOT` changes the retention window without anything reconnecting.
    pub fn new(clock: Arc<dyn Clock>, spec: watch::Receiver<SpecSnapshot>) -> Self {
        Self {
            clock,
            spec,
            seen: Mutex::new(BTreeMap::new()),
        }
    }

    /// Files the arrival of `block_root`. A block that arrives again keeps the record it already
    /// has, which is the one a lag is worth measuring from.
    pub fn arrived(&self, block_root: [u8; 32], source: &Source<'_>) {
        let arrival = Arrival {
            at: self.clock.wall(),
            seen: self.clock.now(),
            origin: match source {
                Source::Bn => None,
                Source::Overlay { origin } => Some((*origin).clone()),
            },
        };
        let mut seen = self.seen();
        self.prune(&mut seen, arrival.seen);
        seen.entry(block_root).or_insert(arrival);
    }

    /// Files what a receive path just took in, if it was a block.
    ///
    /// The two paths hand over whatever T-083's decoder read, which is `None` on a build without
    /// it and a column as often as a block. A column carries its block's root, but a host that
    /// only ever saw columns did not carry the block, and measuring the block's lag from one
    /// would credit the overlay with a block the beacon node fetched itself.
    pub fn saw(&self, header: Option<Header>, source: &Source<'_>) {
        if let Some(Header::Block { root, .. }) = header {
            self.arrived(root, source);
        }
    }

    /// Logs the import of the block at `slot` and says whether an arrival record matched it.
    pub fn imported(&self, slot: u64, block_root: [u8; 32]) -> bool {
        let now = self.clock.now();
        let mut seen = self.seen();
        self.prune(&mut seen, now);
        let arrival = seen.get(&block_root);
        emit_import(&ImportEvent {
            slot,
            block_root,
            imported_at: self.clock.wall(),
            first_arrival_at: arrival.map(|arrival| arrival.at),
            source: arrival.map(|arrival| match &arrival.origin {
                None => Source::Bn,
                Some(origin) => Source::Overlay { origin },
            }),
            lag_ms: arrival.map(|arrival| {
                u64::try_from(now.saturating_duration_since(arrival.seen).as_millis())
                    .unwrap_or(u64::MAX)
            }),
        });
        arrival.is_some()
    }

    /// Drops the records the retention window no longer covers. Both entry points call it, so a
    /// beacon node that has stopped importing still lets the map empty out.
    fn prune(&self, seen: &mut BTreeMap<[u8; 32], Arrival>, now: Instant) {
        let window = Duration::from_secs(RETENTION_SLOTS * self.spec.borrow().seconds_per_slot);
        seen.retain(|_, arrival| now.saturating_duration_since(arrival.seen) <= window);
    }

    fn seen(&self) -> MutexGuard<'_, BTreeMap<[u8; 32], Arrival>> {
        // A poisoned lock is a panic in another holder. The records are still records, and
        // losing import telemetry is not worth spreading a panic into a receive path.
        self.seen.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A root as the 64 hex characters every other tool prints it as, without the `0x` the log's
/// other identifiers do not carry either.
pub(crate) fn hex(root: [u8; 32]) -> String {
    root.iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Nanoseconds since the Unix epoch, the one form of a timestamp that compares across hosts.
/// A clock reading before 1970 or past 2554 answers 0: a host that far out is not producing a
/// spread number anyone can use, and a missing line would hide that it took part at all.
fn epoch_nanos(at: SystemTime) -> u64 {
    at.duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|since| u64::try_from(since.as_nanos()).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use crate::time::FakeClock;

    use super::*;
    use crate::header::Header;
    use crate::msgid::MessageId;
    use crate::roster::{Hostname, Region, SelfIdentity};
    use crate::testlog::LOG;
    use crate::topic::{Class, Topic};

    /// A moment with a nanosecond part, so a truncating conversion cannot pass.
    const AT_NANOS: u64 = 1_757_000_000_123_456_789;

    fn node() -> SelfIdentity {
        SelfIdentity {
            hostname: Hostname("bn-ams1-07".to_owned()),
            region: Region("eu".to_owned()),
            site: Some("ams1".to_owned()),
        }
    }

    fn block() -> Topic {
        Topic::parse("/eth2/00000000/beacon_block/ssz_snappy").unwrap()
    }

    /// The hex form of an id built from one repeated byte, which is how each test tells its own
    /// line apart from whatever else the suite logs in parallel.
    fn hex(byte: u8) -> String {
        format!("{byte:02x}").repeat(20)
    }

    /// The captured line carrying `id`, or an empty string if nothing did.
    fn line_with(mark: usize, id: &str) -> String {
        LOG.since(mark)
            .lines()
            .find(|line| line.contains(id))
            .unwrap_or_default()
            .to_owned()
    }

    #[test]
    fn a_first_arrival_from_the_bn_carries_every_field_of_the_schema() {
        let node = node();
        let topic = block();
        let mark = LOG.len();

        emit_first_arrival(&FirstArrival {
            id: MessageId([1; 20]),
            class: Class::Large,
            topic: &topic,
            node: &node,
            at: UNIX_EPOCH + Duration::from_nanos(AT_NANOS),
            source: Source::Bn,
            header: None,
        });

        let line = line_with(mark, &hex(1));
        assert!(line.contains("overlay::event"), "{line}");
        assert!(line.contains(r#"event="first_arrival""#), "{line}");
        assert!(line.contains(r#"class="large""#), "{line}");
        assert!(
            line.contains("topic=/eth2/00000000/beacon_block/ssz_snappy"),
            "{line}"
        );
        assert!(line.contains("node=bn-ams1-07"), "{line}");
        assert!(line.contains("region=eu"), "{line}");
        assert!(line.contains(r#"site="ams1""#), "{line}");
        assert!(
            line.contains(&format!("first_arrival_ns={AT_NANOS}")),
            "{line}"
        );
        assert!(line.contains(r#"source="bn""#), "{line}");
        assert!(!line.contains("origin_peer"), "{line}");
    }

    #[test]
    fn a_first_arrival_from_the_overlay_names_the_peer_it_came_from() {
        let node = node();
        let topic = block();
        let origin = Hostname("bn-fra1-02".to_owned());
        let mark = LOG.len();

        emit_first_arrival(&FirstArrival {
            id: MessageId([3; 20]),
            class: Class::Large,
            topic: &topic,
            node: &node,
            at: UNIX_EPOCH + Duration::from_nanos(AT_NANOS),
            source: Source::Overlay { origin: &origin },
            header: None,
        });

        let line = line_with(mark, &hex(3));
        assert!(line.contains(r#"source="overlay""#), "{line}");
        assert!(line.contains("origin_peer=bn-fra1-02"), "{line}");
    }

    /// A host with no site label logs an empty one, the same convention the metrics labels
    /// follow, so nothing has to read a literal like `none` as "absent".
    #[test]
    fn a_host_without_a_site_logs_an_empty_one() {
        let node = SelfIdentity {
            site: None,
            ..node()
        };
        let topic = block();
        let mark = LOG.len();

        emit_first_arrival(&FirstArrival {
            id: MessageId([4; 20]),
            class: Class::Large,
            topic: &topic,
            node: &node,
            at: UNIX_EPOCH + Duration::from_nanos(AT_NANOS),
            source: Source::Bn,
            header: None,
        });

        assert!(line_with(mark, &hex(4)).contains(r#"site="""#));
    }

    /// A block root of one repeated byte, rendered the way the arrival line renders it, so a
    /// query can join the two events on it.
    fn root(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    #[test]
    fn emits_import_line_with_lag_when_arrival_is_known() {
        let origin = Hostname("bn-fra1-02".to_owned());
        let imported_at = UNIX_EPOCH + Duration::from_nanos(AT_NANOS);
        let mark = LOG.len();

        emit_import(&ImportEvent {
            slot: 7_654_321,
            block_root: [0x5a; 32],
            imported_at,
            first_arrival_at: Some(imported_at - Duration::from_millis(312)),
            source: Some(Source::Overlay { origin: &origin }),
            lag_ms: Some(312),
        });

        let line = line_with(mark, &root(0x5a));
        assert!(line.contains("overlay::event"), "{line}");
        assert!(line.contains(r#"event="import""#), "{line}");
        assert!(line.contains("slot=7654321"), "{line}");
        assert!(line.contains("matched=true"), "{line}");
        assert!(line.contains(&format!("imported_ns={AT_NANOS}")), "{line}");
        assert!(
            line.contains(&format!("first_arrival_ns={}", AT_NANOS - 312_000_000)),
            "{line}"
        );
        assert!(line.contains("lag_ms=312"), "{line}");
        assert!(line.contains(r#"source="overlay""#), "{line}");
        assert!(line.contains("origin_peer=bn-fra1-02"), "{line}");
    }

    #[test]
    fn emits_import_line_with_matched_false_when_arrival_is_unknown() {
        let mark = LOG.len();

        emit_import(&ImportEvent {
            slot: 7_654_322,
            block_root: [0x6b; 32],
            imported_at: UNIX_EPOCH + Duration::from_nanos(AT_NANOS),
            first_arrival_at: None,
            source: None,
            lag_ms: None,
        });

        let line = line_with(mark, &root(0x6b));
        assert!(line.contains(r#"event="import""#), "{line}");
        assert!(line.contains("slot=7654322"), "{line}");
        assert!(line.contains("matched=false"), "{line}");
        assert!(!line.contains("first_arrival_ns"), "{line}");
        assert!(!line.contains("lag_ms"), "{line}");
        assert!(!line.contains("source"), "{line}");
    }

    #[test]
    fn a_small_class_arrival_is_not_logged() {
        let node = node();
        let topic = Topic::parse("/eth2/00000000/beacon_attestation_3/ssz_snappy").unwrap();
        let mark = LOG.len();

        emit_first_arrival(&FirstArrival {
            id: MessageId([2; 20]),
            class: Class::Small,
            topic: &topic,
            node: &node,
            at: UNIX_EPOCH + Duration::from_nanos(AT_NANOS),
            source: Source::Bn,
            header: None,
        });

        // Another test's line may land in the same slice, so the id is what rules this one out.
        assert!(line_with(mark, &hex(2)).is_empty());
    }

    /// T-083 gives the block topics a slot and a root, so an operator following one block across
    /// the fleet has the consensus name for it and not only the gossipsub id, and T-084's import
    /// event joins to these lines by the same root.
    #[test]
    fn first_arrival_events_for_blocks_carry_slot_and_root() {
        let node = node();
        let topic = block();
        let mark = LOG.len();

        emit_first_arrival(&FirstArrival {
            id: MessageId([5; 20]),
            class: Class::Large,
            topic: &topic,
            node: &node,
            at: UNIX_EPOCH + Duration::from_nanos(AT_NANOS),
            source: Source::Bn,
            header: Some(Header::Block {
                slot: 9_876,
                root: [0xab; 32],
            }),
        });

        let line = line_with(mark, &hex(5));
        assert!(line.contains("slot=9876"), "{line}");
        assert!(
            line.contains(&format!("block_root={}", "ab".repeat(32))),
            "{line}"
        );

        // A large message with no header keeps the schema it had: the keys are absent, not null.
        let mark = LOG.len();
        emit_first_arrival(&FirstArrival {
            id: MessageId([6; 20]),
            class: Class::Large,
            topic: &topic,
            node: &node,
            at: UNIX_EPOCH + Duration::from_nanos(AT_NANOS),
            source: Source::Bn,
            header: None,
        });
        let line = line_with(mark, &hex(6));
        assert!(!line.contains("slot="), "{line}");
        assert!(!line.contains("block_root="), "{line}");
    }

    /// A slot length to hold the window to, since the compiled mainnet values live in
    /// `overlay_bn::spec` and this crate is below it.
    fn slots_of(seconds: u64) -> watch::Sender<SpecSnapshot> {
        watch::Sender::new(SpecSnapshot {
            seconds_per_slot: seconds,
            ..SpecSnapshot::default()
        })
    }

    #[test]
    fn only_a_block_header_files_an_arrival() {
        let spec = slots_of(12);
        let arrivals = Arrivals::new(Arc::new(FakeClock::new()), spec.subscribe());

        arrivals.saw(
            Some(Header::Block {
                slot: 7,
                root: [0x77; 32],
            }),
            &Source::Bn,
        );
        arrivals.saw(
            Some(Header::Column {
                slot: 8,
                index: 3,
                block_root: [0x88; 32],
            }),
            &Source::Bn,
        );
        arrivals.saw(None, &Source::Bn);

        assert!(arrivals.imported(7, [0x77; 32]));
        // A column is not the block. Measuring the block's lag from a column's arrival would
        // credit the overlay with a block its beacon node got on its own.
        assert!(!arrivals.imported(8, [0x88; 32]));
    }

    #[test]
    fn arrival_records_older_than_eight_slots_are_dropped() {
        let clock = FakeClock::new();
        let spec = slots_of(12);
        let arrivals = Arrivals::new(Arc::new(clock.clone()), spec.subscribe());
        arrivals.arrived([0x33; 32], &Source::Bn);
        clock.advance(Duration::from_secs(10));
        arrivals.arrived([0x44; 32], &Source::Bn);

        clock.advance(Duration::from_secs(90));

        // Eight slots of twelve seconds is 96 s, so the older of the two is past it.
        assert!(!arrivals.imported(1, [0x33; 32]));
        assert!(arrivals.imported(2, [0x44; 32]));
    }

    #[test]
    fn retention_follows_the_spec_snapshot() {
        let clock = FakeClock::new();
        let spec = slots_of(12);
        let arrivals = Arrivals::new(Arc::new(clock.clone()), spec.subscribe());
        arrivals.arrived([0x55; 32], &Source::Bn);
        clock.advance(Duration::from_secs(50));
        assert!(arrivals.imported(1, [0x55; 32]));

        // Eight slots of six seconds is 48 s, which the record is already past.
        spec.send_replace(SpecSnapshot {
            seconds_per_slot: 6,
            ..SpecSnapshot::default()
        });

        assert!(!arrivals.imported(2, [0x55; 32]));
    }
}
