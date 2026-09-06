//! Architecture.md §12 is a contract. T-052's alert rules and the dashboard name these series
//! by hand, so a metric renamed or forgotten here breaks an alert nobody is watching. The list
//! below is a deliberate hand-copy of the §12 table: diffing it against what the registry holds
//! is the only thing that notices a rename on either side.

use std::collections::BTreeSet;

use fleet_overlay::metrics::Metrics;
use prometheus::Registry;

/// Every metric in the §12 table, with the `overlay_` prefix the table's heading states.
/// `bn_echo_dropped_total` is deliberately absent: gossipsub's own duplicate counter under
/// `overlay_gossipsub_` measures the echo effect (CL-N4).
const SECTION_12: &[&str] = &[
    "overlay_bn_compat",
    "overlay_bn_connected",
    "overlay_bn_events_dropped_total",
    "overlay_bn_info",
    "overlay_bn_subscriptions",
    "overlay_bn_trusted",
    "overlay_build_info",
    "overlay_bytes_total",
    "overlay_chunks_received_total",
    "overlay_chunks_sent_total",
    "overlay_config_reload_total",
    "overlay_duplicates_dropped_total",
    "overlay_fanout_lane_dropped_total",
    "overlay_fanout_suppressed_total",
    "overlay_first_seen_total",
    "overlay_handshake_failures_total",
    "overlay_invalid_payload_total",
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
    "overlay_reconstruct_seconds",
    "overlay_relayed_batches_total",
    "overlay_repair_requests_total",
    "overlay_roster_region_mismatch_total",
    "overlay_roster_reload_rejected_total",
    "overlay_seen_cache_evicted_total",
    "overlay_stale_dropped_total",
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
    ("overlay_bn_events_dropped_total", &["class"]),
    ("overlay_bn_info", &["version"]),
    ("overlay_bn_subscriptions", &[]),
    ("overlay_bn_trusted", &[]),
    ("overlay_build_info", &["git_sha", "version"]),
    (
        "overlay_bytes_total",
        &["class", "direction", "peer", "region", "site"],
    ),
    ("overlay_chunks_received_total", &[]),
    ("overlay_chunks_sent_total", &[]),
    ("overlay_config_reload_total", &["outcome"]),
    ("overlay_duplicates_dropped_total", &["class", "source"]),
    ("overlay_fanout_lane_dropped_total", &["class"]),
    ("overlay_fanout_suppressed_total", &["kind", "peer"]),
    ("overlay_first_seen_total", &["class", "source"]),
    ("overlay_handshake_failures_total", &["reason", "role"]),
    ("overlay_invalid_payload_total", &["peer"]),
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
    ("overlay_reconstruct_seconds", &["class"]),
    ("overlay_relayed_batches_total", &[]),
    ("overlay_repair_requests_total", &[]),
    ("overlay_roster_region_mismatch_total", &["peer"]),
    ("overlay_roster_reload_rejected_total", &[]),
    ("overlay_seen_cache_evicted_total", &["reason"]),
    ("overlay_stale_dropped_total", &["class", "reason"]),
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
