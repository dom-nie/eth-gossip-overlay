//! Architecture.md §12 is a contract. T-052's alert rules and the dashboard name these series
//! by hand, so a metric renamed or forgotten here breaks an alert nobody is watching. The list
//! below is a deliberate hand-copy of the §12 table: diffing it against what the registry holds
//! is the only thing that notices a rename on either side.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use eth_gossip_overlay::metrics::{BnInbound, Metrics, serve};
use eth_gossip_overlay::reload::{ReloadError, ReloadReport, ReloadStats, Trigger};
use overlay_bn::compat::{self, CompatStats};
use overlay_bn::inbound::InboundStats;
use overlay_bn::publish::PublishStats;
use overlay_core::budget::FanoutKind;
use overlay_core::lanes::LaneStats;
use overlay_core::pubqueue::{DropReason as QueueDropReason, QueueStats};
use overlay_core::roster::{Hostname, Region};
use overlay_core::seen::SeenStats;
use overlay_core::topic::Class;
use overlay_transport::fanout::{Direction, PeerLabels, TrafficStats};
use overlay_transport::manager::{ManagerStats, PeerCounts};
use overlay_transport::receive::ReceiveStats;
use overlay_transport::sender::{DropReason as SendDropReason, SenderStats};
use overlay_transport::subs::SubsStats;
use overlay_transport::tls::{FailureReason, HandshakeFailure, Role};
use prometheus::Registry;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Every await in this file is bounded: a test that hangs tells nobody anything.
const PATIENCE: Duration = Duration::from_secs(5);

/// The gossipsub half of the scrape, empty unless a test fills it.
fn no_gossipsub() -> Arc<Mutex<prometheus_client::registry::Registry>> {
    Arc::new(Mutex::new(prometheus_client::registry::Registry::default()))
}

/// One request over a fresh connection, returned as (status line, body). A broken fixture is
/// reported by panicking, which is what the unwraps here are.
#[allow(clippy::unwrap_used)]
async fn request(addr: SocketAddr, path: &str) -> (String, String) {
    let mut stream = timeout(PATIENCE, TcpStream::connect(addr))
        .await
        .unwrap()
        .unwrap();
    let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    timeout(PATIENCE, stream.write_all(req.as_bytes()))
        .await
        .unwrap()
        .unwrap();
    let mut raw = Vec::new();
    timeout(PATIENCE, stream.read_to_end(&mut raw))
        .await
        .unwrap()
        .unwrap();

    let raw = String::from_utf8(raw).unwrap();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap();
    let status = head.lines().next().unwrap().to_owned();
    (status, body.to_owned())
}

/// Every metric in the §12 table, with the `overlay_` prefix the table's heading states.
/// The BN echo counter CL-N4 struck out is deliberately absent, name and all: gossipsub's own
/// duplicate counter under `overlay_gossipsub_` is what measures the echo effect.
const SECTION_12: &[&str] = &[
    "overlay_bn_compat",
    "overlay_bn_connected",
    "overlay_bn_events_connected",
    "overlay_bn_events_dropped_total",
    "overlay_bn_events_lagged_total",
    "overlay_bn_info",
    "overlay_bn_subscriptions",
    "overlay_bn_trusted",
    "overlay_build_info",
    "overlay_busy_poll_enabled",
    "overlay_by_root_requests_total",
    "overlay_bytes_total",
    "overlay_chunks_received_total",
    "overlay_chunks_sent_total",
    "overlay_column_index_conflict_total",
    "overlay_column_topic_mismatch_total",
    "overlay_config_reload_total",
    "overlay_duplicates_dropped_total",
    "overlay_fanout_lane_dropped_total",
    "overlay_fanout_suppressed_total",
    "overlay_first_seen_total",
    "overlay_handshake_failures_total",
    "overlay_import_events_total",
    "overlay_invalid_payload_total",
    "overlay_io_thread_pinned",
    "overlay_messages_total",
    "overlay_parity_used_total",
    "overlay_peer_auth_via_previous_seed_total",
    "overlay_peer_queue_depth",
    "overlay_peer_queue_drops_total",
    "overlay_peers_connected",
    "overlay_peers_roster",
    "overlay_publish_errors_total",
    "overlay_publish_queue_drops_total",
    "overlay_publish_suppressed_total",
    "overlay_rate_limited_total",
    "overlay_reassembly_evicted_total",
    "overlay_reconstruct_seconds",
    "overlay_relay_same_region_total",
    "overlay_relayed_batches_total",
    "overlay_repair_requests_total",
    "overlay_roster_region_mismatch_total",
    "overlay_roster_reload_rejected_total",
    "overlay_seen_cache_evicted_total",
    "overlay_stale_dropped_total",
    "overlay_steering_applied",
    "overlay_unannounced_topic_total",
    "overlay_unknown_frame_type_total",
    "overlay_unknown_topic_id_total",
    "overlay_unknown_topic_kind_total",
    "overlay_unwanted_topic_total",
];

#[test]
fn every_metric_in_section_12_is_registered() {
    let registry = Registry::new();
    let metrics = Metrics::new(&registry).unwrap();

    let expected: BTreeSet<&str> = SECTION_12.iter().copied().collect();
    let registered: BTreeSet<&str> = metrics.registered_names().collect();

    let missing: Vec<&&str> = expected.difference(&registered).collect();
    let unexpected: Vec<&&str> = registered.difference(&expected).collect();

    assert!(missing.is_empty(), "in §12 but not registered: {missing:?}");
    assert!(
        unexpected.is_empty(),
        "registered but not in §12: {unexpected:?}"
    );
}

/// The label set §12 gives each metric, sorted. Hand-copied for the same reason as
/// [`SECTION_12`]: a label added or renamed on either side has to show up as a diff.
const LABELS: &[(&str, &[&str])] = &[
    ("overlay_bn_compat", &["state"]),
    ("overlay_bn_connected", &[]),
    ("overlay_bn_events_connected", &[]),
    ("overlay_bn_events_dropped_total", &["class"]),
    ("overlay_bn_events_lagged_total", &[]),
    ("overlay_bn_info", &["version"]),
    ("overlay_bn_subscriptions", &[]),
    ("overlay_bn_trusted", &[]),
    ("overlay_build_info", &["git_sha", "version"]),
    ("overlay_busy_poll_enabled", &[]),
    ("overlay_by_root_requests_total", &["outcome", "protocol"]),
    (
        "overlay_bytes_total",
        &["class", "direction", "peer", "region", "site"],
    ),
    ("overlay_chunks_received_total", &[]),
    ("overlay_chunks_sent_total", &[]),
    ("overlay_column_index_conflict_total", &[]),
    ("overlay_column_topic_mismatch_total", &[]),
    ("overlay_config_reload_total", &["outcome"]),
    ("overlay_duplicates_dropped_total", &["class", "source"]),
    ("overlay_fanout_lane_dropped_total", &["class"]),
    ("overlay_fanout_suppressed_total", &["kind", "peer"]),
    ("overlay_first_seen_total", &["class", "source"]),
    ("overlay_handshake_failures_total", &["reason", "role"]),
    ("overlay_import_events_total", &["matched"]),
    ("overlay_invalid_payload_total", &["peer"]),
    ("overlay_io_thread_pinned", &[]),
    (
        "overlay_messages_total",
        &["class", "direction", "peer", "region", "site"],
    ),
    ("overlay_parity_used_total", &[]),
    ("overlay_peer_auth_via_previous_seed_total", &["peer"]),
    ("overlay_peer_queue_depth", &["class", "peer", "unit"]),
    (
        "overlay_peer_queue_drops_total",
        &["class", "peer", "reason"],
    ),
    ("overlay_peers_connected", &["region", "site"]),
    ("overlay_peers_roster", &["region", "site"]),
    ("overlay_publish_errors_total", &["class", "reason"]),
    ("overlay_publish_queue_drops_total", &["class", "reason"]),
    ("overlay_publish_suppressed_total", &["class", "reason"]),
    ("overlay_rate_limited_total", &["class"]),
    ("overlay_reassembly_evicted_total", &["reason"]),
    ("overlay_reconstruct_seconds", &["class"]),
    ("overlay_relay_same_region_total", &["peer"]),
    ("overlay_relayed_batches_total", &[]),
    ("overlay_repair_requests_total", &["form", "outcome"]),
    ("overlay_roster_region_mismatch_total", &["peer"]),
    ("overlay_roster_reload_rejected_total", &[]),
    ("overlay_seen_cache_evicted_total", &["reason"]),
    ("overlay_stale_dropped_total", &["class", "reason"]),
    ("overlay_steering_applied", &["action"]),
    ("overlay_unannounced_topic_total", &[]),
    ("overlay_unknown_frame_type_total", &["peer"]),
    ("overlay_unknown_topic_id_total", &["peer"]),
    ("overlay_unknown_topic_kind_total", &["class"]),
    ("overlay_unwanted_topic_total", &["peer"]),
];

#[test]
fn label_names_match_spec_for_each_metric() {
    let registry = Registry::new();
    let metrics = Metrics::new(&registry).unwrap();

    assert_eq!(LABELS.len(), SECTION_12.len());
    for (metric, expected) in LABELS {
        let mut actual = metrics.label_names(metric).unwrap().to_vec();
        actual.sort();
        assert_eq!(actual, *expected, "{metric}");
    }
}

#[tokio::test]
async fn scrape_lines_carry_only_overlay_or_process_prefixes() {
    let registry = Registry::new();
    Metrics::new(&registry).unwrap();
    let (addr, _server) = serve("127.0.0.1:0".parse().unwrap(), registry, no_gossipsub())
        .await
        .unwrap();

    let (status, body) = request(addr, "/metrics").await;

    assert!(status.contains("200"), "{status}");
    let mut sample_lines = 0;
    for line in body.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        sample_lines += 1;
        assert!(
            line.starts_with("overlay_") || line.starts_with("process_"),
            "{line}"
        );
    }
    assert!(sample_lines > 0, "{body}");
}

#[tokio::test]
async fn scrape_appends_the_gossipsub_registry() {
    let registry = Registry::new();
    Metrics::new(&registry).unwrap();

    let gossipsub = no_gossipsub();
    let duplicates = prometheus_client::metrics::counter::Counter::<u64>::default();
    gossipsub
        .lock()
        .unwrap()
        .sub_registry_with_prefix("overlay_gossipsub")
        .register(
            "duplicates",
            "Duplicates gossipsub dropped.",
            duplicates.clone(),
        );
    duplicates.inc();

    let (addr, _server) = serve("127.0.0.1:0".parse().unwrap(), registry, gossipsub)
        .await
        .unwrap();
    let (_status, body) = request(addr, "/metrics").await;

    let samples: Vec<&str> = body
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    let gossipsub_at = samples
        .iter()
        .position(|line| line.starts_with("overlay_gossipsub_duplicates_total "))
        .unwrap_or_else(|| panic!("{body}"));
    let last_main = samples
        .iter()
        .rposition(|line| !line.starts_with("overlay_gossipsub_"))
        .unwrap_or_else(|| panic!("{body}"));
    assert!(gossipsub_at > last_main, "{body}");

    // OpenMetrics closes with `# EOF`; concatenating the other way round would put it mid-body
    // and Prometheus would stop reading there.
    assert_eq!(body.lines().last(), Some("# EOF"));
    for sample in samples {
        let (name, value) = sample
            .rsplit_once(' ')
            .unwrap_or_else(|| panic!("{sample}"));
        assert!(!name.is_empty(), "{sample}");
        assert!(value.parse::<f64>().is_ok(), "{sample}");
    }
}

#[tokio::test]
async fn unknown_path_returns_404() {
    let registry = Registry::new();
    Metrics::new(&registry).unwrap();
    let (addr, _server) = serve("127.0.0.1:0".parse().unwrap(), registry, no_gossipsub())
        .await
        .unwrap();

    let (status, body) = request(addr, "/").await;

    assert!(status.contains("404"), "{status}");
    assert!(!body.contains("overlay_build_info"), "{body}");
}

#[test]
fn histogram_buckets_cover_1ms_to_2s() {
    let registry = Registry::new();
    let metrics = Metrics::new(&registry).unwrap();
    metrics.reconstructed(Class::Large, Duration::from_millis(500));

    let families = registry.gather();
    let histogram = families
        .iter()
        .find(|family| family.name() == "overlay_reconstruct_seconds")
        .unwrap_or_else(|| panic!("the histogram has no series"));
    let bounds: Vec<f64> = histogram.get_metric()[0]
        .get_histogram()
        .get_bucket()
        .iter()
        .map(prometheus::proto::Bucket::upper_bound)
        .collect();

    assert_eq!(bounds.first().copied(), Some(0.001), "{bounds:?}");
    assert!(
        bounds.last().copied().unwrap_or_default() >= 2.0,
        "{bounds:?}"
    );
    let ratio = bounds[1] / bounds[0];
    for pair in bounds.windows(2) {
        assert!((pair[1] / pair[0] - ratio).abs() < 1e-9, "{bounds:?}");
    }
}

/// The value of one series, or `None` when the registry holds no such series. A missing series
/// and a zero are different answers here: the compat gauges are specified by which series exist.
#[allow(clippy::unwrap_used)]
fn sample(registry: &Registry, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
    let families = registry.gather();
    let family = families.iter().find(|family| family.name() == name)?;
    let metric = family.get_metric().iter().find(|metric| {
        metric.get_label().len() == labels.len()
            && labels.iter().all(|(key, value)| {
                metric
                    .get_label()
                    .iter()
                    .any(|label| label.name() == *key && label.value() == *value)
            })
    })?;
    Some(match family.get_field_type() {
        prometheus::proto::MetricType::GAUGE => metric.get_gauge().get_value(),
        _ => metric.get_counter().get_value(),
    })
}

/// How many series a metric currently has.
fn series(registry: &Registry, name: &str) -> usize {
    registry
        .gather()
        .iter()
        .find(|family| family.name() == name)
        .map_or(0, |family| family.get_metric().len())
}

fn hostname() -> Hostname {
    Hostname("bn-ams1-07".to_owned())
}

#[test]
fn seen_stats_counts_a_capacity_eviction() {
    let registry = Registry::new();
    let metrics = Metrics::new(&registry).unwrap();

    SeenStats::evicted_for_capacity(&metrics, 3);

    let evicted = sample(
        &registry,
        "overlay_seen_cache_evicted_total",
        &[("reason", "capacity")],
    );
    assert_eq!(evicted, Some(3.0));
}

#[test]
fn lane_stats_counts_bn_events_by_class_and_control() {
    let registry = Registry::new();
    let metrics = Metrics::new(&registry).unwrap();

    LaneStats::dropped(&metrics, Class::Large);
    LaneStats::control_dropped(&metrics);

    let dropped = |class| {
        sample(
            &registry,
            "overlay_bn_events_dropped_total",
            &[("class", class)],
        )
    };
    assert_eq!(dropped("large"), Some(1.0));
    assert_eq!(dropped("control"), Some(1.0));
    assert_eq!(dropped("small"), None);
}

#[test]
fn queue_stats_counts_a_publish_queue_drop() {
    let registry = Registry::new();
    let metrics = Metrics::new(&registry).unwrap();

    QueueStats::dropped(&metrics, Class::Small, QueueDropReason::Full);

    let dropped = sample(
        &registry,
        "overlay_publish_queue_drops_total",
        &[("class", "small"), ("reason", "full")],
    );
    assert_eq!(dropped, Some(1.0));
}

#[test]
fn publish_stats_counts_publishes_suppressions_and_errors() {
    let registry = Registry::new();
    let metrics = Metrics::new(&registry).unwrap();

    PublishStats::published(&metrics, Class::Large);
    PublishStats::suppressed_inject_off(&metrics, Class::Small);
    PublishStats::rate_limited(&metrics, Class::Small);
    PublishStats::error(&metrics, Class::Large, "no_subscribers");
    PublishStats::queue_drop(&metrics, Class::Large, QueueDropReason::Stale);

    // A publish into the beacon node has no overlay peer, so the peer labels are empty.
    let published = sample(
        &registry,
        "overlay_messages_total",
        &[
            ("direction", "bn_out"),
            ("class", "large"),
            ("peer", ""),
            ("region", ""),
            ("site", ""),
        ],
    );
    assert_eq!(published, Some(1.0));
    assert_eq!(
        sample(
            &registry,
            "overlay_publish_suppressed_total",
            &[("class", "small"), ("reason", "inject_off")]
        ),
        Some(1.0)
    );
    assert_eq!(
        sample(
            &registry,
            "overlay_rate_limited_total",
            &[("class", "small")]
        ),
        Some(1.0)
    );
    assert_eq!(
        sample(
            &registry,
            "overlay_publish_errors_total",
            &[("class", "large"), ("reason", "no_subscribers")]
        ),
        Some(1.0)
    );
    assert_eq!(
        sample(
            &registry,
            "overlay_publish_queue_drops_total",
            &[("class", "large"), ("reason", "stale")]
        ),
        Some(1.0)
    );
}

#[test]
fn compat_stats_keeps_one_state_at_one_and_one_version_series() {
    let registry = Registry::new();
    let metrics = Metrics::new(&registry).unwrap();

    assert_eq!(series(&registry, "overlay_bn_trusted"), 0);

    CompatStats::set_info(&metrics, "v8.2.2");
    CompatStats::set_info(&metrics, "v8.3.0");
    CompatStats::set_compat(&metrics, compat::STATE_UNTESTED);
    CompatStats::set_compat(&metrics, compat::STATE_SUPPORTED);
    CompatStats::set_trusted(&metrics, Some(true));

    assert_eq!(series(&registry, "overlay_bn_info"), 1);
    assert_eq!(
        sample(&registry, "overlay_bn_info", &[("version", "v8.3.0")]),
        Some(1.0)
    );
    // Every state stays on the scrape with one of them at 1, so an alert can say
    // `overlay_bn_compat{state="unsupported"} == 1` without absent() gymnastics and a state
    // going quiet reads differently from a dead scrape.
    assert_eq!(series(&registry, "overlay_bn_compat"), 4);
    for state in [
        compat::STATE_SUPPORTED,
        compat::STATE_UNTESTED,
        compat::STATE_UNSUPPORTED,
        compat::STATE_SIZE_MISMATCH,
    ] {
        let expected = f64::from(u8::from(state == compat::STATE_SUPPORTED));
        assert_eq!(
            sample(&registry, "overlay_bn_compat", &[("state", state)]),
            Some(expected),
            "{state}"
        );
    }
    assert_eq!(sample(&registry, "overlay_bn_trusted", &[]), Some(1.0));

    CompatStats::set_trusted(&metrics, None);

    assert_eq!(series(&registry, "overlay_bn_trusted"), 0);
}

#[test]
fn inbound_stats_labels_the_beacon_node_as_the_source() {
    let registry = Registry::new();
    let metrics = Arc::new(Metrics::new(&registry).unwrap());
    let inbound = BnInbound(Arc::clone(&metrics));

    inbound.duplicate(Class::Small);
    inbound.first_seen(Class::Large);
    inbound.dropped_full(Class::Large);
    inbound.unknown_kind(Class::Small);

    assert_eq!(
        sample(
            &registry,
            "overlay_duplicates_dropped_total",
            &[("class", "small"), ("source", "bn")]
        ),
        Some(1.0)
    );
    assert_eq!(
        sample(
            &registry,
            "overlay_first_seen_total",
            &[("class", "large"), ("source", "bn")]
        ),
        Some(1.0)
    );
    assert_eq!(
        sample(
            &registry,
            "overlay_fanout_lane_dropped_total",
            &[("class", "large")]
        ),
        Some(1.0)
    );
    assert_eq!(
        sample(
            &registry,
            "overlay_unknown_topic_kind_total",
            &[("class", "small")]
        ),
        Some(1.0)
    );
}

#[test]
fn manager_stats_counts_admission_and_replaces_the_peer_gauges() {
    let registry = Registry::new();
    let metrics = Metrics::new(&registry).unwrap();
    let peer = hostname();

    metrics.handshake_failure(HandshakeFailure {
        role: Role::Accept,
        reason: FailureReason::UnknownKey,
    });
    metrics.auth_via_previous_seed(&peer);
    metrics.roster_region_mismatch(&peer);
    metrics.unknown_frame_type(&peer);

    assert_eq!(
        sample(
            &registry,
            "overlay_handshake_failures_total",
            &[("role", "accept"), ("reason", "unknown_key")]
        ),
        Some(1.0)
    );
    for name in [
        "overlay_peer_auth_via_previous_seed_total",
        "overlay_roster_region_mismatch_total",
        "overlay_unknown_frame_type_total",
    ] {
        assert_eq!(
            sample(&registry, name, &[("peer", peer.0.as_str())]),
            Some(1.0)
        );
    }

    let mut counts = PeerCounts::new();
    counts.insert((Region("eu".to_owned()), Some("ams1".to_owned())), 7);
    metrics.peers_connected(&counts);
    // A region that goes away must take its series with it, or the health alert reads a count
    // from a roster that no longer has that region in it.
    let mut fewer = PeerCounts::new();
    fewer.insert((Region("us".to_owned()), None), 2);
    metrics.peers_connected(&fewer);

    assert_eq!(series(&registry, "overlay_peers_connected"), 1);
    assert_eq!(
        sample(
            &registry,
            "overlay_peers_connected",
            &[("region", "us"), ("site", "")]
        ),
        Some(2.0)
    );
}

#[test]
fn subs_stats_sets_the_subscription_gauge() {
    let registry = Registry::new();
    let metrics = Metrics::new(&registry).unwrap();

    SubsStats::bn_subscriptions(&metrics, 96);

    assert_eq!(
        sample(&registry, "overlay_bn_subscriptions", &[]),
        Some(96.0)
    );
}

#[test]
fn traffic_stats_counts_messages_and_bytes_per_peer() {
    let registry = Registry::new();
    let metrics = Metrics::new(&registry).unwrap();
    let peer = hostname();
    let region = Region("eu".to_owned());

    metrics.message(
        Direction::Out,
        Class::Large,
        PeerLabels {
            hostname: &peer,
            region: &region,
            site: None,
        },
        1500,
    );

    // A roster host with no site renders as an empty label, the same as the publish path's
    // absent peer: one rule, so the series never splits.
    let labels = &[
        ("direction", "out"),
        ("class", "large"),
        ("peer", peer.0.as_str()),
        ("region", "eu"),
        ("site", ""),
    ];
    assert_eq!(
        sample(&registry, "overlay_messages_total", labels),
        Some(1.0)
    );
    assert_eq!(
        sample(&registry, "overlay_bytes_total", labels),
        Some(1500.0)
    );
}

#[test]
fn receive_stats_labels_the_overlay_as_the_source() {
    let registry = Registry::new();
    let metrics = Metrics::new(&registry).unwrap();
    let peer = hostname();

    ReceiveStats::first_seen(&metrics, Class::Large);
    ReceiveStats::duplicate(&metrics, Class::Small);
    metrics.unknown_topic_id(&peer);
    metrics.unwanted_topic(&peer);
    metrics.invalid_payload(&peer);
    metrics.fanout_suppressed(&peer, FanoutKind::Chunk);

    assert_eq!(
        sample(
            &registry,
            "overlay_first_seen_total",
            &[("class", "large"), ("source", "overlay")]
        ),
        Some(1.0)
    );
    assert_eq!(
        sample(
            &registry,
            "overlay_duplicates_dropped_total",
            &[("class", "small"), ("source", "overlay")]
        ),
        Some(1.0)
    );
    for name in [
        "overlay_unknown_topic_id_total",
        "overlay_unwanted_topic_total",
        "overlay_invalid_payload_total",
    ] {
        assert_eq!(
            sample(&registry, name, &[("peer", peer.0.as_str())]),
            Some(1.0)
        );
    }
    assert_eq!(
        sample(
            &registry,
            "overlay_fanout_suppressed_total",
            &[("peer", peer.0.as_str()), ("kind", "chunk")]
        ),
        Some(1.0)
    );
}

#[test]
fn sender_stats_reports_queue_depth_in_both_units() {
    let registry = Registry::new();
    let metrics = Metrics::new(&registry).unwrap();
    let peer = hostname();

    metrics.queue_depth(&peer, Class::Small, 12, 4096);
    SenderStats::queue_drop(&metrics, &peer, Class::Small, SendDropReason::PeerDown);

    let depth = |unit| {
        sample(
            &registry,
            "overlay_peer_queue_depth",
            &[
                ("peer", peer.0.as_str()),
                ("class", "small"),
                ("unit", unit),
            ],
        )
    };
    assert_eq!(depth("frames"), Some(12.0));
    assert_eq!(depth("bytes"), Some(4096.0));
    assert_eq!(
        sample(
            &registry,
            "overlay_peer_queue_drops_total",
            &[
                ("peer", peer.0.as_str()),
                ("class", "small"),
                ("reason", "peer_down")
            ]
        ),
        Some(1.0)
    );
}

/// A report of one reload, which is all [`ReloadStats`] is given.
fn report(error: Option<ReloadError>) -> ReloadReport {
    ReloadReport {
        trigger: Trigger::Manual,
        applied: Vec::new(),
        restart_required: Vec::new(),
        error,
    }
}

#[test]
fn reload_stats_counts_the_outcome_and_a_rejected_roster() {
    let registry = Registry::new();
    let metrics = Metrics::new(&registry).unwrap();

    ReloadStats::reloaded(&metrics, &report(None));
    ReloadStats::reloaded(
        &metrics,
        &report(Some(ReloadError::RosterShrinkRejected {
            before: 10,
            after: 4,
        })),
    );

    let outcome = |outcome| {
        sample(
            &registry,
            "overlay_config_reload_total",
            &[("outcome", outcome)],
        )
    };
    assert_eq!(outcome("ok"), Some(1.0));
    assert_eq!(outcome("error"), Some(1.0));
    assert_eq!(
        sample(&registry, "overlay_roster_reload_rejected_total", &[]),
        Some(1.0)
    );
}

/// The process collector is Linux-only in the prometheus crate, so this is the one test the
/// workspace's other platforms skip rather than fake.
#[cfg(target_os = "linux")]
#[test]
fn process_collector_exports_resident_memory() {
    let registry = Registry::new();
    Metrics::new(&registry).unwrap();

    let rss = sample(&registry, "process_resident_memory_bytes", &[]);

    assert!(rss.unwrap_or_default() > 0.0, "{rss:?}");
}

/// Everything `tracing` writes in this binary. One process-wide subscriber rather than a
/// thread-scoped one: tracing caches a call site's interest from whichever dispatcher first
/// reaches it, so a `warn!` hit with no subscriber installed would stay silent afterwards.
static LOG: LazyLock<Log> = LazyLock::new(|| {
    let log = Log::default();
    let sink = log.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || sink.clone())
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);
    log
});

/// What the subscriber has written so far. A poisoned lock means another test already failed,
/// which the unwraps here report by panicking.
#[derive(Clone, Default)]
struct Log(Arc<Mutex<Vec<u8>>>);

#[allow(clippy::unwrap_used)]
impl Log {
    fn len(&self) -> usize {
        self.0.lock().unwrap().len()
    }

    fn since(&self, from: usize) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()[from..]).into_owned()
    }
}

#[allow(clippy::unwrap_used)]
impl std::io::Write for Log {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::Write::write(&mut *self.0.lock().unwrap(), buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn binding_off_loopback_logs_a_warning() {
    let mark = LOG.len();
    let registry = Registry::new();
    Metrics::new(&registry).unwrap();

    // TEST-NET-1, which no host has configured, so the warning is asserted without opening a
    // listener anyone else could reach. Whether the bind then succeeds is beside the point.
    let outcome = serve("192.0.2.1:0".parse().unwrap(), registry, no_gossipsub()).await;
    if let Ok((_, server)) = outcome {
        server.abort();
    }

    let logged = LOG.since(mark);
    assert!(logged.contains("not a loopback address"), "{logged}");
}
