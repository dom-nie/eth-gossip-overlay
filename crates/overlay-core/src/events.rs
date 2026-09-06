//! The one line per large message that the canary is judged on (§12, D32).
//!
//! An event is an ordinary `tracing` record: same subscriber, same stream, same format as every
//! other log line, told apart by its `event` field. Fleet spread and overlay win rate are then
//! Loki queries over `| json | event="first_arrival"` joined by message id across hosts, with no
//! second writer to configure and no metric label carrying a message id. `docs/events.md` holds
//! the schema and the queries.
//!
//! The subscriber itself belongs to the binary (`fleet_overlay::logging`); emitting is plain
//! `tracing`, so the two callsites in `overlay-bn` and `overlay-transport` reach it without
//! either of them depending on the binary crate.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::msgid::MessageId;
use crate::roster::{Hostname, SelfIdentity};
use crate::topic::{Class, Topic};

/// Where events go. Ordinary logs keep their module target, so a reader can select on either
/// the target or the `event` field.
const TARGET: &str = "overlay::event";

/// The `event` field of an arrival. v3 adds `import` (T-084) next to it.
const FIRST_ARRIVAL: &str = "first_arrival";

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
    match arrival.source {
        Source::Bn => tracing::info!(
            target: TARGET,
            event = FIRST_ARRIVAL,
            msg_id = %arrival.id,
            class,
            topic = %arrival.topic,
            node = %node.hostname,
            region = %node.region,
            site,
            first_arrival_ns,
            source = "bn",
        ),
        Source::Overlay { origin } => tracing::info!(
            target: TARGET,
            event = FIRST_ARRIVAL,
            msg_id = %arrival.id,
            class,
            topic = %arrival.topic,
            node = %node.hostname,
            region = %node.region,
            site,
            first_arrival_ns,
            source = "overlay",
            origin_peer = %origin,
        ),
    }
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

    use super::*;
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
        });

        assert!(line_with(mark, &hex(4)).contains(r#"site="""#));
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
        });

        // Another test's line may land in the same slice, so the id is what rules this one out.
        assert!(line_with(mark, &hex(2)).is_empty());
    }
}
