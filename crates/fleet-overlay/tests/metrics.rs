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
    let registered = metrics.registered_names();
    let registered: BTreeSet<&str> = registered.iter().map(String::as_str).collect();

    let missing: Vec<&&str> = expected.difference(&registered).collect();
    let unexpected: Vec<&&str> = registered.difference(&expected).collect();

    assert!(missing.is_empty(), "in §12 but not registered: {missing:?}");
    assert!(
        unexpected.is_empty(),
        "registered but not in §12: {unexpected:?}"
    );
}
