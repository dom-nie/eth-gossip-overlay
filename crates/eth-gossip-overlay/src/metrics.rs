//! Every metric Architecture.md §12 names, in one place, with the producer crates reaching
//! them through the stats traits they defined rather than through `prometheus`. This is the
//! only crate that links `prometheus`; `overlay-bn` links `prometheus_client` for the one
//! registry it hands to gossipsub, which [`serve`] appends to the scrape.
//!
//! # The names here are a contract
//!
//! T-052's alert rules and dashboard are written against these exact series and are kept in
//! step by copying the constants below into them by hand. Renaming a constant silently breaks
//! an alert nobody is watching, so a rename means editing the §12 table, the alert rules and
//! the dashboard in the same change.
//!
//! # An absent site renders as the empty string
//!
//! `LivePeer::site` is optional, and §12 does not say what `site` should carry for a host that
//! has none. It is the empty string here, at every call site, because a label with an empty
//! value and an absent label are the same thing to Prometheus: `sum by (site)` puts the
//! siteless hosts in one bucket that reads as blank, and no real site can collide with it the
//! way one literally named `none` could. The same rule covers `peer` and `region` on the
//! publish path, where the counter describes the beacon node rather than an overlay peer.
//! A label that varied between call sites would split one series in two, so this is the rule
//! later tickets follow.
//!
//! # Metrics with no producer yet
//!
//! Several §12 series belong to components that land in v2 or v3. They are registered here at
//! zero so the names, the alert rules and the dashboard never wait on a later release; the
//! ticket that lands the component adds the handle and the trait that feeds it.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::CONTENT_TYPE;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use overlay_bn::compat::{self, CompatStats};
use overlay_bn::inbound::InboundStats;
use overlay_bn::publish::PublishStats;
use overlay_core::budget::FanoutKind;
use overlay_core::lanes::LaneStats;
use overlay_core::pubqueue::{DropReason as QueueDropReason, QueueStats};
use overlay_core::roster::Hostname;
use overlay_core::seen::SeenStats;
use overlay_core::topic::Class;
use overlay_transport::fanout::{Direction, PeerLabels, TrafficStats};
use overlay_transport::manager::{ManagerStats, PeerCounts};
use overlay_transport::receive::ReceiveStats;
use overlay_transport::sender::{DropReason as SendDropReason, SenderStats, StaleReason};
use overlay_transport::subs::SubsStats;
use overlay_transport::tls::HandshakeFailure;

use crate::reload::{ReloadError, ReloadReport, ReloadStats};
use prometheus::core::Collector;
use prometheus::{
    HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
    Result, TextEncoder,
};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

/// Overlay peers with a live connection, by the region and site they declared.
pub const PEERS_CONNECTED: &str = "overlay_peers_connected";
/// Roster hosts other than this one, by region and site. The ratio to [`PEERS_CONNECTED`] is
/// the overlay-health alert.
pub const PEERS_ROSTER: &str = "overlay_peers_roster";
/// 1 while the beacon node link is up.
pub const BN_CONNECTED: &str = "overlay_bn_connected";
/// Topics the beacon node is subscribed to, which is the size of the advertised set.
pub const BN_SUBSCRIPTIONS: &str = "overlay_bn_subscriptions";
/// The beacon node's version string, as the label of a single series at 1.
pub const BN_INFO: &str = "overlay_bn_info";
/// The compatibility verdict, one state at 1.
pub const BN_COMPAT: &str = "overlay_bn_compat";
/// 1 when the beacon node lists the sidecar as a trusted peer, 0 when it does not, and no
/// series at all while it has not said.
pub const BN_TRUSTED: &str = "overlay_bn_trusted";
/// Messages the swarm loop could not hand on because the lane was full.
pub const BN_EVENTS_DROPPED_TOTAL: &str = "overlay_bn_events_dropped_total";
/// Messages that crossed the overlay or went into the beacon node.
pub const MESSAGES_TOTAL: &str = "overlay_messages_total";
/// Payload bytes that crossed the overlay.
pub const BYTES_TOTAL: &str = "overlay_bytes_total";
/// Messages whose id the seen cache did not hold, by which side delivered it first.
pub const FIRST_SEEN_TOTAL: &str = "overlay_first_seen_total";
/// Messages dropped because the seen cache already held the id.
pub const DUPLICATES_DROPPED_TOTAL: &str = "overlay_duplicates_dropped_total";
/// Seen-cache entries evicted before they expired.
pub const SEEN_CACHE_EVICTED_TOTAL: &str = "overlay_seen_cache_evicted_total";
/// Messages dropped for being too old to be worth handling.
pub const STALE_DROPPED_TOTAL: &str = "overlay_stale_dropped_total";
/// Publishes refused by the class or byte rate limit.
pub const RATE_LIMITED_TOTAL: &str = "overlay_rate_limited_total";
/// Publishes gossipsub refused. `reason="no_subscribers"` is the SUBS race, not an error.
pub const PUBLISH_ERRORS_TOTAL: &str = "overlay_publish_errors_total";
/// Entries the publish queue threw away.
pub const PUBLISH_QUEUE_DROPS_TOTAL: &str = "overlay_publish_queue_drops_total";
/// Publishes suppressed before they reached gossipsub, the kill switch included.
pub const PUBLISH_SUPPRESSED_TOTAL: &str = "overlay_publish_suppressed_total";
/// Payloads that failed the snappy or message-id check on the receive path.
pub const INVALID_PAYLOAD_TOTAL: &str = "overlay_invalid_payload_total";
/// Frames carrying a topic id the peer has not announced.
pub const UNKNOWN_TOPIC_ID_TOTAL: &str = "overlay_unknown_topic_id_total";
/// Frames of a type this release does not define, skipped.
pub const UNKNOWN_FRAME_TYPE_TOTAL: &str = "overlay_unknown_frame_type_total";
/// Messages on a topic outside this host's advertised set.
pub const UNWANTED_TOPIC_TOTAL: &str = "overlay_unwanted_topic_total";
/// Messages on a topic name the sidecar does not know, classified by payload size.
pub const UNKNOWN_TOPIC_KIND_TOTAL: &str = "overlay_unknown_topic_kind_total";
/// Handshakes that did not produce a peer.
pub const HANDSHAKE_FAILURES_TOTAL: &str = "overlay_handshake_failures_total";
/// Peers whose declared region disagreed with the roster.
pub const ROSTER_REGION_MISMATCH_TOTAL: &str = "overlay_roster_region_mismatch_total";
/// Peers admitted on a key derived from the outgoing fleet seed.
pub const PEER_AUTH_VIA_PREVIOUS_SEED_TOTAL: &str = "overlay_peer_auth_via_previous_seed_total";
/// Second-hop work refused because the peer was over its fan-out budget.
pub const FANOUT_SUPPRESSED_TOTAL: &str = "overlay_fanout_suppressed_total";
/// Batches this host re-fanned as a relay.
pub const RELAYED_BATCHES_TOTAL: &str = "overlay_relayed_batches_total";
/// Relay batches from a peer in this host's own region, which no sender should send.
pub const RELAY_SAME_REGION_TOTAL: &str = "overlay_relay_same_region_total";
/// Messages from the beacon node dropped because the fanout lane was full.
pub const FANOUT_LANE_DROPPED_TOTAL: &str = "overlay_fanout_lane_dropped_total";
/// Chunks written to peers.
pub const CHUNKS_SENT_TOTAL: &str = "overlay_chunks_sent_total";
/// Chunks read from peers.
pub const CHUNKS_RECEIVED_TOTAL: &str = "overlay_chunks_received_total";
/// Messages that needed a parity chunk to reconstruct.
pub const PARITY_USED_TOTAL: &str = "overlay_parity_used_total";
/// Repair requests this host sent.
pub const REPAIR_REQUESTS_TOTAL: &str = "overlay_repair_requests_total";
/// Seconds from the first chunk of a message to its reconstruction.
pub const RECONSTRUCT_SECONDS: &str = "overlay_reconstruct_seconds";
/// What a peer's send lane holds now, in frames and in bytes.
pub const PEER_QUEUE_DEPTH: &str = "overlay_peer_queue_depth";
/// Frames a peer's send lane threw away.
pub const PEER_QUEUE_DROPS_TOTAL: &str = "overlay_peer_queue_drops_total";
/// Configuration reloads, by how they ended.
pub const CONFIG_RELOAD_TOTAL: &str = "overlay_config_reload_total";
/// Automatic roster reloads the shrink guard refused.
pub const ROSTER_RELOAD_REJECTED_TOTAL: &str = "overlay_roster_reload_rejected_total";
/// Always 1; the labels carry the build.
pub const BUILD_INFO: &str = "overlay_build_info";

/// Small or large, the traffic class.
pub const LABEL_CLASS: &str = "class";
/// Which way a message crossed the overlay, or `bn_out` into the beacon node.
pub const LABEL_DIRECTION: &str = "direction";
/// A peer's hostname.
pub const LABEL_PEER: &str = "peer";
/// A peer's declared region.
pub const LABEL_REGION: &str = "region";
/// A peer's site, empty when it has none.
pub const LABEL_SITE: &str = "site";
/// Which side delivered a message first.
pub const LABEL_SOURCE: &str = "source";
/// Why something was dropped, refused or failed.
pub const LABEL_REASON: &str = "reason";
/// The compatibility state.
pub const LABEL_STATE: &str = "state";
/// The beacon node's version string.
pub const LABEL_VERSION: &str = "version";
/// Which end of a handshake this host was.
pub const LABEL_ROLE: &str = "role";
/// Which second hop bytes were charged for.
pub const LABEL_KIND: &str = "kind";
/// `frames` or `bytes`, the unit a queue depth is measured in.
pub const LABEL_UNIT: &str = "unit";
/// How a reload ended.
pub const LABEL_OUTCOME: &str = "outcome";
/// The commit the binary was built from.
pub const LABEL_GIT_SHA: &str = "git_sha";

/// The beacon node delivered it first.
pub const SOURCE_BN: &str = "bn";
/// The overlay delivered it first.
pub const SOURCE_OVERLAY: &str = "overlay";
/// Published into the local beacon node, which has no peer, region or site.
pub const DIRECTION_BN_OUT: &str = "bn_out";
/// The lane counts whole frames.
pub const UNIT_FRAMES: &str = "frames";
/// The lane counts payload bytes.
pub const UNIT_BYTES: &str = "bytes";
/// The reload ran to the end.
pub const OUTCOME_OK: &str = "ok";
/// The reload kept some or all of the previous values.
pub const OUTCOME_ERROR: &str = "error";
/// A seen-cache entry went to stay within the bound, not because it expired.
pub const REASON_CAPACITY: &str = "capacity";
/// The `inject: false` kill switch.
pub const REASON_INJECT_OFF: &str = "inject_off";
/// Control events share the lane counter under a class of their own.
pub const CLASS_CONTROL: &str = "control";

/// Registers each metric and remembers the descriptor the registry took it under, so the §12
/// contract tests read the registered metrics rather than a second hand-written list.
struct Builder<'a> {
    registry: &'a Registry,
    registered: BTreeMap<String, Vec<String>>,
}

impl Builder<'_> {
    fn add<C: Collector + Clone + 'static>(&mut self, metric: C) -> Result<C> {
        for desc in metric.desc() {
            self.registered
                .insert(desc.fq_name.clone(), desc.variable_labels.clone());
        }
        self.registry.register(Box::new(metric.clone()))?;
        Ok(metric)
    }

    fn counter(&mut self, name: &str, help: &str) -> Result<IntCounter> {
        self.add(IntCounter::new(name, help)?)
    }

    fn counter_vec(&mut self, name: &str, help: &str, labels: &[&str]) -> Result<IntCounterVec> {
        self.add(IntCounterVec::new(Opts::new(name, help), labels)?)
    }

    fn gauge(&mut self, name: &str, help: &str) -> Result<IntGauge> {
        self.add(IntGauge::new(name, help)?)
    }

    fn gauge_vec(&mut self, name: &str, help: &str, labels: &[&str]) -> Result<IntGaugeVec> {
        self.add(IntGaugeVec::new(Opts::new(name, help), labels)?)
    }
}

/// Every §12 metric, registered on one `prometheus::Registry`, and the implementation of every
/// stats trait the component crates defined so none of them links `prometheus` itself.
pub struct Metrics {
    peers_connected: IntGaugeVec,
    peers_roster: IntGaugeVec,
    bn_connected: IntGauge,
    bn_subscriptions: IntGauge,
    bn_info: IntGaugeVec,
    bn_compat: IntGaugeVec,
    bn_trusted: IntGaugeVec,
    bn_events_dropped: IntCounterVec,
    messages: IntCounterVec,
    bytes: IntCounterVec,
    first_seen: IntCounterVec,
    duplicates_dropped: IntCounterVec,
    seen_cache_evicted: IntCounterVec,
    rate_limited: IntCounterVec,
    publish_errors: IntCounterVec,
    publish_queue_drops: IntCounterVec,
    publish_suppressed: IntCounterVec,
    invalid_payload: IntCounterVec,
    unknown_topic_id: IntCounterVec,
    unknown_frame_type: IntCounterVec,
    unwanted_topic: IntCounterVec,
    unknown_topic_kind: IntCounterVec,
    handshake_failures: IntCounterVec,
    roster_region_mismatch: IntCounterVec,
    peer_auth_via_previous_seed: IntCounterVec,
    fanout_suppressed: IntCounterVec,
    relayed_batches: IntCounter,
    relay_same_region: IntCounterVec,
    fanout_lane_dropped: IntCounterVec,
    peer_queue_depth: IntGaugeVec,
    peer_queue_drops: IntCounterVec,
    stale_dropped: IntCounterVec,
    config_reload: IntCounterVec,
    roster_reload_rejected: IntCounter,
    reconstruct_seconds: HistogramVec,
    registered: BTreeMap<String, Vec<String>>,
}

impl Metrics {
    /// Registers every §12 metric on `registry`, and on Linux the process collector the memory
    /// alert reads. Fails only if a name is registered twice, which is a programming error.
    pub fn new(registry: &Registry) -> Result<Self> {
        let mut b = Builder {
            registry,
            registered: BTreeMap::new(),
        };

        let region_site = &[LABEL_REGION, LABEL_SITE];
        let peer_traffic = &[
            LABEL_DIRECTION,
            LABEL_CLASS,
            LABEL_PEER,
            LABEL_REGION,
            LABEL_SITE,
        ];
        let class_reason = &[LABEL_CLASS, LABEL_REASON];
        let class_source = &[LABEL_CLASS, LABEL_SOURCE];
        let per_class = &[LABEL_CLASS];
        let per_peer = &[LABEL_PEER];

        let peers_connected = b.gauge_vec(
            PEERS_CONNECTED,
            "Overlay peers with a live connection.",
            region_site,
        )?;
        let peers_roster = b.gauge_vec(
            PEERS_ROSTER,
            "Roster hosts other than this one.",
            region_site,
        )?;
        let bn_connected = b.gauge(BN_CONNECTED, "1 while the beacon node link is up.")?;
        let bn_subscriptions =
            b.gauge(BN_SUBSCRIPTIONS, "Topics the beacon node is subscribed to.")?;
        let bn_info = b.gauge_vec(BN_INFO, "The beacon node's version.", &[LABEL_VERSION])?;
        let bn_compat = b.gauge_vec(
            BN_COMPAT,
            "The beacon node's compatibility state.",
            &[LABEL_STATE],
        )?;
        let bn_trusted = b.gauge_vec(
            BN_TRUSTED,
            "1 when the beacon node lists the sidecar as trusted.",
            &[],
        )?;
        let bn_events_dropped = b.counter_vec(
            BN_EVENTS_DROPPED_TOTAL,
            "Beacon node events dropped because their lane was full.",
            per_class,
        )?;
        let messages = b.counter_vec(MESSAGES_TOTAL, "Messages accounted for.", peer_traffic)?;
        let bytes = b.counter_vec(BYTES_TOTAL, "Payload bytes accounted for.", peer_traffic)?;
        let first_seen = b.counter_vec(
            FIRST_SEEN_TOTAL,
            "Messages this host had not seen before.",
            class_source,
        )?;
        let duplicates_dropped = b.counter_vec(
            DUPLICATES_DROPPED_TOTAL,
            "Messages the seen cache already held.",
            class_source,
        )?;
        let seen_cache_evicted = b.counter_vec(
            SEEN_CACHE_EVICTED_TOTAL,
            "Seen-cache entries evicted before they expired.",
            &[LABEL_REASON],
        )?;
        let rate_limited = b.counter_vec(
            RATE_LIMITED_TOTAL,
            "Publishes the rate limit refused.",
            per_class,
        )?;
        let publish_errors = b.counter_vec(
            PUBLISH_ERRORS_TOTAL,
            "Publishes gossipsub refused.",
            class_reason,
        )?;
        let publish_queue_drops = b.counter_vec(
            PUBLISH_QUEUE_DROPS_TOTAL,
            "Entries the publish queue threw away.",
            class_reason,
        )?;
        let publish_suppressed = b.counter_vec(
            PUBLISH_SUPPRESSED_TOTAL,
            "Publishes suppressed before gossipsub saw them.",
            class_reason,
        )?;
        let invalid_payload = b.counter_vec(
            INVALID_PAYLOAD_TOTAL,
            "Payloads that failed the snappy or message-id check.",
            per_peer,
        )?;
        let unknown_topic_id = b.counter_vec(
            UNKNOWN_TOPIC_ID_TOTAL,
            "Frames carrying a topic id the peer had not announced.",
            per_peer,
        )?;
        let unknown_frame_type = b.counter_vec(
            UNKNOWN_FRAME_TYPE_TOTAL,
            "Frames of a type this release does not define.",
            per_peer,
        )?;
        let unwanted_topic = b.counter_vec(
            UNWANTED_TOPIC_TOTAL,
            "Messages on a topic outside the advertised set.",
            per_peer,
        )?;
        let unknown_topic_kind = b.counter_vec(
            UNKNOWN_TOPIC_KIND_TOTAL,
            "Messages on a topic name the sidecar does not know.",
            per_class,
        )?;
        let handshake_failures = b.counter_vec(
            HANDSHAKE_FAILURES_TOTAL,
            "Handshakes that did not produce a peer.",
            &[LABEL_ROLE, LABEL_REASON],
        )?;
        let roster_region_mismatch = b.counter_vec(
            ROSTER_REGION_MISMATCH_TOTAL,
            "Peers whose declared region disagreed with the roster.",
            per_peer,
        )?;
        let peer_auth_via_previous_seed = b.counter_vec(
            PEER_AUTH_VIA_PREVIOUS_SEED_TOTAL,
            "Peers admitted on a key from the outgoing fleet seed.",
            per_peer,
        )?;
        let fanout_suppressed = b.counter_vec(
            FANOUT_SUPPRESSED_TOTAL,
            "Second-hop work refused by the fan-out budget.",
            &[LABEL_PEER, LABEL_KIND],
        )?;
        let relayed_batches = b.counter(RELAYED_BATCHES_TOTAL, "Batches re-fanned as a relay.")?;
        let relay_same_region = b.counter_vec(
            RELAY_SAME_REGION_TOTAL,
            "Relay batches from a peer in this host's own region.",
            &[LABEL_PEER],
        )?;
        let fanout_lane_dropped = b.counter_vec(
            FANOUT_LANE_DROPPED_TOTAL,
            "Messages dropped because the fanout lane was full.",
            per_class,
        )?;
        let peer_queue_depth = b.gauge_vec(
            PEER_QUEUE_DEPTH,
            "What a peer's send lane holds now.",
            &[LABEL_PEER, LABEL_CLASS, LABEL_UNIT],
        )?;
        let peer_queue_drops = b.counter_vec(
            PEER_QUEUE_DROPS_TOTAL,
            "Frames a peer's send lane threw away.",
            &[LABEL_PEER, LABEL_CLASS, LABEL_REASON],
        )?;
        // A millisecond to two seconds, doubling: reassembly either finishes inside a slot or
        // has already lost the race, so the resolution belongs at the fast end.
        let reconstruct_seconds = b.add(HistogramVec::new(
            HistogramOpts::new(
                RECONSTRUCT_SECONDS,
                "Seconds from a message's first chunk to its reconstruction.",
            )
            .buckets(prometheus::exponential_buckets(0.001, 2.0, 12)?),
            per_class,
        )?)?;

        let stale_dropped = b.counter_vec(
            STALE_DROPPED_TOTAL,
            "Messages dropped for being too old to be worth handling.",
            class_reason,
        )?;

        // Registered and then let go of: their producers land in v3 and T-073, and each of those
        // tickets adds the handle it needs. The registry keeps the collector alive, so the name
        // is on the scrape from this release on.
        b.counter(CHUNKS_SENT_TOTAL, "Chunks written to peers.")?;
        b.counter(CHUNKS_RECEIVED_TOTAL, "Chunks read from peers.")?;
        b.counter(
            PARITY_USED_TOTAL,
            "Messages that needed a parity chunk to reconstruct.",
        )?;
        b.counter(REPAIR_REQUESTS_TOTAL, "Repair requests sent.")?;
        let config_reload = b.counter_vec(
            CONFIG_RELOAD_TOTAL,
            "Configuration reloads.",
            &[LABEL_OUTCOME],
        )?;
        let roster_reload_rejected = b.counter(
            ROSTER_RELOAD_REJECTED_TOTAL,
            "Automatic roster reloads the shrink guard refused.",
        )?;

        b.gauge_vec(
            BUILD_INFO,
            "Always 1; the labels carry the build.",
            &[LABEL_VERSION, LABEL_GIT_SHA],
        )?
        .with_label_values(&[
            env!("CARGO_PKG_VERSION"),
            option_env!("ETH_GOSSIP_OVERLAY_GIT_SHA").unwrap_or("unknown"),
        ])
        .set(1);

        // Not through the builder: `process_*` is not an overlay metric and has no place in the
        // §12 name set the contract test reads.
        #[cfg(target_os = "linux")]
        registry.register(Box::new(
            prometheus::process_collector::ProcessCollector::for_self(),
        ))?;

        Ok(Self {
            peers_connected,
            peers_roster,
            bn_connected,
            bn_subscriptions,
            bn_info,
            bn_compat,
            bn_trusted,
            bn_events_dropped,
            messages,
            bytes,
            first_seen,
            duplicates_dropped,
            seen_cache_evicted,
            rate_limited,
            publish_errors,
            publish_queue_drops,
            publish_suppressed,
            invalid_payload,
            unknown_topic_id,
            unknown_frame_type,
            unwanted_topic,
            unknown_topic_kind,
            handshake_failures,
            roster_region_mismatch,
            peer_auth_via_previous_seed,
            fanout_suppressed,
            relayed_batches,
            relay_same_region,
            fanout_lane_dropped,
            peer_queue_depth,
            peer_queue_drops,
            stale_dropped,
            reconstruct_seconds,
            config_reload,
            roster_reload_rejected,
            registered: b.registered,
        })
    }

    /// The fully qualified name of every metric registered here, taken from the descriptors of
    /// the collectors themselves. The registry prunes families with no series, so gathering an
    /// idle registry would not show a metric that is registered and never touched, which is
    /// exactly what the §12 contract has to see.
    pub fn registered_names(&self) -> impl Iterator<Item = &str> {
        self.registered.keys().map(String::as_str)
    }

    /// The label names `metric` was registered with, or `None` if it was not registered here.
    pub fn label_names(&self, metric: &str) -> Option<&[String]> {
        self.registered.get(metric).map(Vec::as_slice)
    }

    /// How long a large message took from its first chunk to being whole again. T-074 is the
    /// caller; the series exists from this release so the dashboard does not wait for it.
    pub fn reconstructed(&self, class: Class, seconds: f64) {
        self.reconstruct_seconds
            .with_label_values(&[class_label(class)])
            .observe(seconds);
    }

    /// Mirrors `BnLink.connected`, the flag the link keeps and T-045 hands on.
    pub fn set_bn_connected(&self, connected: bool) {
        self.bn_connected.set(i64::from(connected));
    }
}

impl ReloadStats for Metrics {
    /// One reload, one count. A roster the shrink guard refused is an error like any other
    /// reload error and is also counted on its own, because the alert on it is about the
    /// discovery tool rather than about the sidecar.
    fn reloaded(&self, report: &ReloadReport) {
        let outcome = match report.error {
            None => OUTCOME_OK,
            Some(_) => OUTCOME_ERROR,
        };
        self.config_reload.with_label_values(&[outcome]).inc();
        if matches!(report.error, Some(ReloadError::RosterShrinkRejected { .. })) {
            self.roster_reload_rejected.inc();
        }
    }
}

impl SeenStats for Metrics {
    fn evicted_for_capacity(&self, count: usize) {
        self.seen_cache_evicted
            .with_label_values(&[REASON_CAPACITY])
            .inc_by(count.try_into().unwrap_or(u64::MAX));
    }
}

impl LaneStats for Metrics {
    fn dropped(&self, class: Class) {
        self.bn_events_dropped
            .with_label_values(&[class_label(class)])
            .inc();
    }

    fn control_dropped(&self) {
        self.bn_events_dropped
            .with_label_values(&[CLASS_CONTROL])
            .inc();
    }
}

impl QueueStats for Metrics {
    fn dropped(&self, class: Class, reason: QueueDropReason) {
        self.publish_queue_drops
            .with_label_values(&[class_label(class), queue_reason(reason)])
            .inc();
    }
}

impl PublishStats for Metrics {
    /// `messages_total` only: the publisher counts messages, not bytes, so a `bytes_total`
    /// series for this direction would sit at zero and read as "no traffic" on a dashboard.
    fn published(&self, class: Class) {
        self.messages
            .with_label_values(&[DIRECTION_BN_OUT, class_label(class), ABSENT, ABSENT, ABSENT])
            .inc();
    }

    fn suppressed_inject_off(&self, class: Class) {
        self.publish_suppressed
            .with_label_values(&[class_label(class), REASON_INJECT_OFF])
            .inc();
    }

    fn rate_limited(&self, class: Class) {
        self.rate_limited
            .with_label_values(&[class_label(class)])
            .inc();
    }

    fn error(&self, class: Class, reason: &'static str) {
        self.publish_errors
            .with_label_values(&[class_label(class), reason])
            .inc();
    }

    fn queue_drop(&self, class: Class, reason: QueueDropReason) {
        QueueStats::dropped(self, class, reason);
    }
}

impl CompatStats for Metrics {
    /// Zero every state, then raise the one that holds. The states are a closed set, so all of
    /// them stay on the scrape and an alert reads `== 1` on the state it cares about instead of
    /// working around a series that is simply not there. A state this release does not know
    /// still gets its own series at 1.
    fn set_compat(&self, state: &'static str) {
        for known in COMPAT_STATES {
            self.bn_compat.with_label_values(&[known]).set(0);
        }
        self.bn_compat.with_label_values(&[state]).set(1);
    }

    /// Reset first, unlike the compat states: version strings are unbounded, so the old one has
    /// to go or the scrape grows a series per beacon node release.
    fn set_info(&self, version: &str) {
        self.bn_info.reset();
        self.bn_info.with_label_values(&[version]).set(1);
    }

    fn set_trusted(&self, trusted: Option<bool>) {
        // An `IntGaugeVec` with no labels rather than an `IntGauge`, because a plain gauge is
        // exported from the moment it is registered and §12 wants no series at all while the
        // beacon node has not said.
        self.bn_trusted.reset();
        if let Some(trusted) = trusted {
            self.bn_trusted
                .with_label_values(NO_LABELS)
                .set(i64::from(trusted));
        }
    }
}

impl ManagerStats for Metrics {
    fn handshake_failure(&self, failure: HandshakeFailure) {
        self.handshake_failures
            .with_label_values(&[failure.role.as_str(), failure.reason.as_str()])
            .inc();
    }

    fn auth_via_previous_seed(&self, peer: &Hostname) {
        self.peer_auth_via_previous_seed
            .with_label_values(&[&peer.0])
            .inc();
    }

    fn roster_region_mismatch(&self, peer: &Hostname) {
        self.roster_region_mismatch
            .with_label_values(&[&peer.0])
            .inc();
    }

    fn unknown_frame_type(&self, peer: &Hostname) {
        self.unknown_frame_type.with_label_values(&[&peer.0]).inc();
    }

    fn dial_started(&self, _: &Hostname) {
        // No series in §12: a dial is only visible from the dialling side, so the count says
        // nothing an operator can read across a pair.
    }

    fn peers_connected(&self, counts: &PeerCounts) {
        set_peer_counts(&self.peers_connected, counts);
    }

    fn peers_roster(&self, counts: &PeerCounts) {
        set_peer_counts(&self.peers_roster, counts);
    }
}

impl SubsStats for Metrics {
    fn bn_subscriptions(&self, topics: usize) {
        self.bn_subscriptions
            .set(topics.try_into().unwrap_or(i64::MAX));
    }
}

impl TrafficStats for Metrics {
    fn message(&self, direction: Direction, class: Class, peer: PeerLabels<'_>, bytes: usize) {
        let labels = &[
            direction.as_str(),
            class_label(class),
            &peer.hostname.0,
            &peer.region.0,
            peer.site.unwrap_or(ABSENT),
        ];
        self.messages.with_label_values(labels).inc();
        self.bytes
            .with_label_values(labels)
            .inc_by(bytes.try_into().unwrap_or(u64::MAX));
    }
}

impl ReceiveStats for Metrics {
    fn unknown_topic_id(&self, peer: &Hostname) {
        self.unknown_topic_id.with_label_values(&[&peer.0]).inc();
    }

    fn unwanted_topic(&self, peer: &Hostname) {
        self.unwanted_topic.with_label_values(&[&peer.0]).inc();
    }

    fn invalid_payload(&self, peer: &Hostname) {
        self.invalid_payload.with_label_values(&[&peer.0]).inc();
    }

    fn first_seen(&self, class: Class) {
        self.first_seen
            .with_label_values(&[class_label(class), SOURCE_OVERLAY])
            .inc();
    }

    fn duplicate(&self, class: Class) {
        self.duplicates_dropped
            .with_label_values(&[class_label(class), SOURCE_OVERLAY])
            .inc();
    }

    fn fanout_suppressed(&self, peer: &Hostname, kind: FanoutKind) {
        self.fanout_suppressed
            .with_label_values(&[&peer.0, kind.as_str()])
            .inc();
    }

    fn relayed_batch(&self) {
        self.relayed_batches.inc();
    }

    fn relay_same_region(&self, peer: &Hostname) {
        self.relay_same_region.with_label_values(&[&peer.0]).inc();
    }
}

impl SenderStats for Metrics {
    fn queue_depth(&self, peer: &Hostname, class: Class, frames: usize, bytes: usize) {
        let class = class_label(class);
        self.peer_queue_depth
            .with_label_values(&[&peer.0, class, UNIT_FRAMES])
            .set(frames.try_into().unwrap_or(i64::MAX));
        self.peer_queue_depth
            .with_label_values(&[&peer.0, class, UNIT_BYTES])
            .set(bytes.try_into().unwrap_or(i64::MAX));
    }

    fn queue_drop(&self, peer: &Hostname, class: Class, reason: SendDropReason) {
        self.peer_queue_drops
            .with_label_values(&[&peer.0, class_label(class), reason.as_str()])
            .inc();
    }

    /// Entries and not calls: `stale_dropped_total` counts messages the beacon nodes never got,
    /// and one batch that aged out whole is as many of those as it held.
    fn stale_dropped(&self, reason: StaleReason, entries: usize) {
        self.stale_dropped
            .with_label_values(&[class_label(Class::Small), reason.as_str()])
            .inc_by(entries as u64);
    }
}

/// The beacon node side of the inbound path. [`InboundStats`] and [`ReceiveStats`] count the
/// same two series and differ only in the `source` label, which is why this side is a type of
/// its own: the trait deliberately takes no `source` argument, so the adapter binds it (T-016).
pub struct BnInbound(
    /// The registry the counts land on.
    pub Arc<Metrics>,
);

impl InboundStats for BnInbound {
    fn first_seen(&self, class: Class) {
        self.0
            .first_seen
            .with_label_values(&[class_label(class), SOURCE_BN])
            .inc();
    }

    fn duplicate(&self, class: Class) {
        self.0
            .duplicates_dropped
            .with_label_values(&[class_label(class), SOURCE_BN])
            .inc();
    }

    fn dropped_full(&self, class: Class) {
        self.0
            .fanout_lane_dropped
            .with_label_values(&[class_label(class)])
            .inc();
    }

    fn unknown_kind(&self, class: Class) {
        self.0
            .unknown_topic_kind
            .with_label_values(&[class_label(class)])
            .inc();
    }
}

/// Replaces the gauge's series outright. A region or site that leaves the roster has to take
/// its series with it, or the overlay-health alert keeps reading a count for hosts that are
/// gone.
fn set_peer_counts(gauge: &IntGaugeVec, counts: &PeerCounts) {
    gauge.reset();
    for ((region, site), count) in counts {
        gauge
            .with_label_values(&[&region.0, site.as_deref().unwrap_or(ABSENT)])
            .set((*count).try_into().unwrap_or(i64::MAX));
    }
}

/// Every `overlay_bn_compat` state, so the ones that do not hold can be zeroed rather than
/// dropped.
const COMPAT_STATES: [&str; 4] = [
    compat::STATE_SUPPORTED,
    compat::STATE_UNTESTED,
    compat::STATE_UNSUPPORTED,
    compat::STATE_SIZE_MISMATCH,
];

/// The one series of a metric that has no labels at all.
const NO_LABELS: &[&str] = &[];

/// What `site`, `peer` and `region` carry when the producer has none. An empty label and an
/// absent one are the same series to Prometheus, so this cannot collide with a real site.
const ABSENT: &str = "";

/// The `reason` label of a publish-queue drop.
fn queue_reason(reason: QueueDropReason) -> &'static str {
    match reason {
        QueueDropReason::Full => "full",
        QueueDropReason::Stale => "stale",
    }
}

/// The `class` label. `overlay-core` does not spell its enum out for metrics, and putting a
/// label method there would move a presentation choice into the crate that must not have one.
fn class_label(class: Class) -> &'static str {
    match class {
        Class::Small => "small",
        Class::Large => "large",
    }
}

/// The scrape endpoint, bound before it returns so a port already in use is a startup failure
/// and not a task that dies quietly. `GET /metrics` answers with the exposition of `main`.
///
/// D30 puts the endpoint on `127.0.0.1:7789` and the scraper on the host. Binding anywhere
/// else exposes every hostname in the roster to whoever can reach the port, so it is warned
/// about rather than refused: an operator with a scrape from another machine may mean it.
pub async fn serve(
    addr: SocketAddr,
    main: Registry,
    gossipsub: Arc<Mutex<prometheus_client::registry::Registry>>,
) -> io::Result<(SocketAddr, JoinHandle<()>)> {
    if !addr.ip().is_loopback() {
        warn!(
            %addr,
            "metrics_listen is not a loopback address; the scrape endpoint is reachable from the network"
        );
    }

    let listener = TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    let task = tokio::spawn(async move {
        loop {
            // A failed accept is per-connection (the peer went away between the SYN and here);
            // the listener is still good, so the next scrape is unaffected.
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let main = main.clone();
            let gossipsub = Arc::clone(&gossipsub);
            tokio::spawn(async move {
                let service = service_fn(move |req: Request<Incoming>| {
                    let response = respond(&req, &main, &gossipsub);
                    async move { Ok::<_, Infallible>(response) }
                });
                if let Err(err) = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await
                {
                    debug!(%err, "scrape connection ended early");
                }
            });
        }
    });

    Ok((bound, task))
}

/// The only path the endpoint answers. Everything else is a 404, so a browser pointed at the
/// port learns nothing about the host.
const METRICS_PATH: &str = "/metrics";

/// What Prometheus reads: the text format both encoders write, served under the 0.0.4 content
/// type that Prometheus accepts for either.
const TEXT_FORMAT: &str = "text/plain; version=0.0.4";

fn respond(
    req: &Request<Incoming>,
    main: &Registry,
    gossipsub: &Mutex<prometheus_client::registry::Registry>,
) -> Response<Full<Bytes>> {
    if req.method() != Method::GET || req.uri().path() != METRICS_PATH {
        return not_found();
    }

    match exposition(main, gossipsub) {
        Ok(body) => Response::builder()
            .header(CONTENT_TYPE, TEXT_FORMAT)
            .body(Full::new(Bytes::from(body))),
        Err(err) => {
            warn!(%err, "could not encode the metrics registry");
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::default())
        }
    }
    .unwrap_or_else(|_| {
        // `Response::builder` only fails on a header this function does not build from input.
        Response::new(Full::default())
    })
}

fn not_found() -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::default());
    *response.status_mut() = StatusCode::NOT_FOUND;
    response
}

/// Both registries in one body. Gossipsub's metrics come from `prometheus_client`, whose
/// OpenMetrics encoder ends with `# EOF`, so its half goes last: anything after that marker is
/// not read. Prometheus accepts the concatenation under the 0.0.4 content type.
fn exposition(
    main: &Registry,
    gossipsub: &Mutex<prometheus_client::registry::Registry>,
) -> std::result::Result<String, Box<dyn std::error::Error>> {
    let mut body = TextEncoder::new().encode_to_string(&main.gather())?;
    // A panicking scrape would poison the lock and silence gossipsub's metrics for good; the
    // registry behind it is only ever read.
    let gossipsub = gossipsub
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    prometheus_client::encoding::text::encode(&mut body, &gossipsub)?;
    Ok(body)
}
