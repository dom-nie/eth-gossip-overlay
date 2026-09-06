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

        let line = LOG.since(mark);
        assert!(line.contains("overlay::event"), "{line}");
        assert!(line.contains(r#"event="first_arrival""#), "{line}");
        assert!(line.contains(&format!("msg_id={}", "01".repeat(20))), "{line}");
        assert!(line.contains(r#"class="large""#), "{line}");
        assert!(
            line.contains("topic=/eth2/00000000/beacon_block/ssz_snappy"),
            "{line}"
        );
        assert!(line.contains("node=bn-ams1-07"), "{line}");
        assert!(line.contains("region=eu"), "{line}");
        assert!(line.contains(r#"site="ams1""#), "{line}");
        assert!(line.contains(&format!("first_arrival_ns={AT_NANOS}")), "{line}");
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

        let line = LOG.since(mark);
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

        assert!(LOG.since(mark).contains(r#"site="""#));
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
        assert!(!LOG.since(mark).contains(&"02".repeat(20)));
    }
}
