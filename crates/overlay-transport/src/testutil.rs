//! A real overlay on loopback, for this crate's tests and for the crates that need one running:
//! T-032's fanout and T-051's fleet harness. Behind a feature because it is test-only code that
//! other crates' tests link.
//!
//! [`TestCluster`] binds an endpoint per host, builds the roster from the ports it got, and then
//! starts a [`ConnectionManager`] on each. Binding first is what lets the roster hold real
//! addresses with no port written down anywhere, so several clusters run in parallel in one test
//! binary. The ports come from a range of the harness's own, below every platform's ephemeral
//! range, rather than from `:0`: a restarted node has to bind the port it had, and with `:0` the
//! operating system is free to hand that port to another test in the moment in between. Not
//! every host has to run a manager: a [`NodeKind::Sink`] is an endpoint that accepts and holds,
//! which is how a test drives one manager from the outside.
//!
//! ```ignore
//! let mut cluster = TestCluster::start(3).await;
//! assert!(matches!(cluster.next_event(0).await, PeerEvent::Up(_)));
//! assert_eq!(cluster.live(0).len(), 2);
//! ```
//!
//! Admission is pluggable through [`Builder::start_with`], so a test can decide what a
//! connection turns into without waiting for T-025's HELLO.
//!
//! [`view`] is the other half: a [`LiveView`] whose peers a test decides the subscriptions of,
//! for the routing questions (T-031) that read the view and never the network.
//!
//! [`TestCluster::start_sidecar`] adds the rest of the sidecar's overlay pipeline to a node: the
//! fanout task (T-032), a receiver per live peer, the subscription exchange (T-027) and a
//! stand-in for T-017's publisher. What a beacon node would hand the node goes in through
//! [`TestCluster::from_bn`] and what would reach it comes back out of
//! [`TestCluster::published`].
//!
//! Two simplifications a reader should know about. Every node shares one pin table, where real
//! hosts each build their own from the roster they loaded, so a host is always pinnable even
//! when [`TestCluster::set_roster_for`] has taken it out of somebody's roster. And hostnames
//! carry a per-cluster prefix, so a test that reads the captured log can tell its own peers'
//! lines from another test's.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use bytes::Bytes;
use ed25519_dalek::SigningKey;
use overlay_core::budget::{FanoutBudget, FanoutKind};
use overlay_core::config::{self, Overlay};
use overlay_core::fanout::Outbound;
use overlay_core::identity::{FleetSeed, Seeds, derive_tls_keypair};
use overlay_core::lanes::{ClassLanes, LanePusher};
use overlay_core::msgid;
use overlay_core::protocol::MAX_FRAME_BYTES;
use overlay_core::pubqueue::{PublishItem, PublishSink};
use overlay_core::roster::{HostEntry, Hostname, Region, Roster, SelfIdentity};
use overlay_core::seen::{SeenCache, SharedSeenCache};
use overlay_core::subs::{Bitmap, PeerState};
use overlay_core::time::SystemClock;
use overlay_core::topic::Topic;
use overlay_core::topic::table::{PeerTopicTable, TopicId};
use overlay_core::topic::{Class, SubscriptionSets};
use overlay_core::wire::Frame;
use overlay_core::wire::MAX_PAYLOAD_BYTES;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::batching::Batching;
use crate::endpoint::{self, EndpointError};
use crate::fanout::{Direction, Fanout, PeerLabels, TrafficStats};
use crate::hello::{HelloAdmission, Negotiated, OwnTopics, SelfHello};
use crate::manager::{
    Admission, CloseCode, ConnectionManager, Handle, LivePeer, LiveSource, LiveView, Local,
    ManagerStats, PeerCounts, PeerEvent, PeerInfo,
};
use crate::receive::{Deps, NoStripes, PeerReceiver, ReceiveStats};
use crate::sender::{
    self, DropReason, LARGE_QUEUED_BYTES_MAX, LargeLedger, SenderHandle, SenderStats, StaleReason,
    Transport,
};
use crate::subs::SubsStats;
use crate::tls::{self, FailureReason, HandshakeFailure, PinTable, Role};

/// Long enough for a handshake, an admission and a reconnect on a loaded machine, and short
/// enough that a test which will never pass fails instead of hanging.
pub const WAIT: Duration = Duration::from_secs(5);

/// How long to wait before believing that no further event is coming.
pub const SETTLE: Duration = Duration::from_millis(250);

/// The one region every cluster host is in, so a test about declared regions has something to
/// differ from.
pub const REGION: &str = "eu";

/// What a node's publish stand-in holds before it drops its oldest entry. Far below T-017's own
/// bound, which a test would have to push four thousand messages through a live overlay to
/// reach; [`TestCluster::start_sidecar_with`] takes a smaller one still.
pub const PUBLISHED_MAX: usize = 1024;

/// The seen cache every sidecar in a cluster runs, at §5.5's TTL and a capacity sized for a
/// test rather than for a fleet.
const SEEN_TTL: Duration = Duration::from_secs(60);
const SEEN_CAPACITY: usize = 4096;

/// Distinguishes one cluster's hostnames from another's, because the captured log is shared by
/// every test in the binary.
static CLUSTERS: AtomicU64 = AtomicU64::new(0);

/// Ports the harness hands out, taken from below every platform's ephemeral range rather than
/// from `:0`. A restarted node has to bind the port it had, and with `:0` the operating system
/// is free to hand that port to another test in the moment between the close and the rebind,
/// which it does often enough to matter.
static NEXT_PORT: AtomicU32 = AtomicU32::new(0);
const PORT_RANGE: std::ops::Range<u32> = 20_000..30_000;

/// What a host in the cluster runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeKind {
    /// An endpoint with a connection manager on it.
    Manager,
    /// An endpoint that accepts connections and holds them, with no manager. A test dials
    /// through it to drive a manager from the outside.
    Sink,
    /// A sink on a runtime of its own, which [`TestCluster::vanish`] shuts down. Its socket
    /// stays bound and stops answering, which is what a host that died looks like to its peers;
    /// an endpoint dropped on a live runtime says goodbye on the way out instead.
    Vanishing,
    /// A sink presenting a key the pin table does not hold for its hostname, so a dialler
    /// refuses it the way it would refuse an impostor on a roster address.
    WrongKey,
    /// A sink whose key derives from the outgoing seed rather than the one in force, as a host
    /// that a rotation has not restarted yet still presents (DX-N2).
    PreviousSeedKey,
    /// An endpoint with nothing reading from it, so a test drives both ends of a connection
    /// itself: [`TestCluster::connected_pair`] is what accepts on it.
    Bare,
    /// A sink that answers HELLO with one topic binding and then binds the same id to another
    /// topic. That is the protocol error a control stream reader closes a connection for
    /// (T-027), and it happens again on every redial, which is what a peer whose fault survives
    /// a reconnect looks like.
    ConflictingTopicAdd,
    /// A sink that answers HELLO and then closes the connection with a code of the test's
    /// choosing, which is how a peer that has paired and then decided against the connection
    /// looks from the dial side.
    ClosesWith(CloseCode),
    /// A sink with a pin table of its own that is always empty, so it takes the packets of
    /// every dial and refuses the key behind them. A dialler's `connect()` resolves before the
    /// refusal reaches it, which is the one case where a resolved dial is not a peer.
    RefusesEveryone,
}

/// Everything the manager counts, so a test can read a series by name.
#[derive(Debug, Default)]
pub struct CountingStats {
    handshake_failures: Mutex<BTreeMap<(&'static str, &'static str), u64>>,
    previous_seed: Mutex<BTreeMap<Hostname, u64>>,
    region_mismatches: Mutex<BTreeMap<Hostname, u64>>,
    unknown_frame_types: Mutex<BTreeMap<Hostname, u64>>,
    dials: Mutex<BTreeMap<Hostname, u64>>,
    connected: Mutex<PeerCounts>,
    in_roster: Mutex<PeerCounts>,
    bn_subscriptions: Mutex<Option<usize>>,
    traffic: Mutex<Traffic>,
    unknown_topic_ids: Mutex<BTreeMap<Hostname, u64>>,
    unwanted_topics: Mutex<BTreeMap<Hostname, u64>>,
    invalid_payloads: Mutex<BTreeMap<Hostname, u64>>,
    first_seen: Mutex<HashMap<Class, u64>>,
    duplicates: Mutex<HashMap<Class, u64>>,
    fanout_suppressed: Mutex<BTreeMap<(Hostname, FanoutKind), u64>>,
    queue_depths: Mutex<HashMap<(Hostname, Class), (usize, usize)>>,
    queue_drops: Mutex<HashMap<(Hostname, Class, DropReason), u64>>,
    stale_dropped: Mutex<HashMap<StaleReason, u64>>,
}

impl CountingStats {
    /// `handshake_failures_total{role, reason}`.
    pub fn handshake_failures(&self, role: Role, reason: FailureReason) -> u64 {
        count(&self.handshake_failures, &(role.as_str(), reason.as_str()))
    }

    /// `peer_auth_via_previous_seed_total{peer}`.
    pub fn previous_seed(&self, peer: &Hostname) -> u64 {
        count(&self.previous_seed, peer)
    }

    /// `roster_region_mismatch_total{peer}`.
    pub fn region_mismatches(&self, peer: &Hostname) -> u64 {
        count(&self.region_mismatches, peer)
    }

    /// `unknown_frame_type_total{peer}`.
    pub fn unknown_frame_types(&self, peer: &Hostname) -> u64 {
        count(&self.unknown_frame_types, peer)
    }

    /// How many dials to `peer` this host started.
    pub fn dials(&self, peer: &Hostname) -> u64 {
        count(&self.dials, peer)
    }

    /// `peers_connected{region,site}` as it was last set.
    pub fn connected_gauge(&self) -> PeerCounts {
        self.connected.lock().unwrap().clone()
    }

    /// `peers_roster{region,site}` as it was last set.
    pub fn roster_gauge(&self) -> PeerCounts {
        self.in_roster.lock().unwrap().clone()
    }

    /// `bn_subscriptions` as it was last set, or `None` if it never was.
    pub fn bn_subscriptions(&self) -> Option<usize> {
        *self.bn_subscriptions.lock().unwrap()
    }

    /// `messages_total{direction, peer}` over every class.
    pub fn messages(&self, direction: Direction, peer: &Hostname) -> u64 {
        self.traffic(direction, peer).0
    }

    /// `bytes_total{direction, peer}` over every class.
    pub fn bytes(&self, direction: Direction, peer: &Hostname) -> u64 {
        self.traffic(direction, peer).1
    }

    /// `messages_total{direction, class, peer}`, which is what says how a payload was
    /// classified.
    pub fn messages_of(&self, direction: Direction, class: Class, peer: &Hostname) -> u64 {
        self.traffic
            .lock()
            .unwrap()
            .get(&(direction, class, peer.clone()))
            .map_or(0, |(messages, _)| *messages)
    }

    fn traffic(&self, direction: Direction, peer: &Hostname) -> (u64, u64) {
        self.traffic
            .lock()
            .unwrap()
            .iter()
            .filter(|((counted, _, hostname), _)| *counted == direction && hostname == peer)
            .fold((0, 0), |(messages, bytes), (_, (m, b))| {
                (messages + m, bytes + b)
            })
    }

    /// `unknown_topic_id_total{peer}`.
    pub fn unknown_topic_ids(&self, peer: &Hostname) -> u64 {
        count(&self.unknown_topic_ids, peer)
    }

    /// `unwanted_topic_total{peer}`.
    pub fn unwanted_topics(&self, peer: &Hostname) -> u64 {
        count(&self.unwanted_topics, peer)
    }

    /// `invalid_payload_total{peer}`.
    pub fn invalid_payloads(&self, peer: &Hostname) -> u64 {
        count(&self.invalid_payloads, peer)
    }

    /// `first_seen_total{class, source="overlay"}`.
    pub fn first_seen(&self, class: Class) -> u64 {
        self.first_seen
            .lock()
            .unwrap()
            .get(&class)
            .copied()
            .unwrap_or_default()
    }

    /// `fanout_suppressed_total{peer, kind}`.
    pub fn fanout_suppressed(&self, peer: &Hostname, kind: FanoutKind) -> u64 {
        count(&self.fanout_suppressed, &(peer.clone(), kind))
    }

    /// `peer_queue_depth{peer, class}` in frames and bytes, as it was last set.
    pub fn queue_depth(&self, peer: &Hostname, class: Class) -> (usize, usize) {
        self.queue_depths
            .lock()
            .unwrap()
            .get(&(peer.clone(), class))
            .copied()
            .unwrap_or_default()
    }

    /// `peer_queue_drops_total{peer, class, reason}`.
    pub fn queue_drops(&self, peer: &Hostname, class: Class, reason: DropReason) -> u64 {
        self.queue_drops
            .lock()
            .unwrap()
            .get(&(peer.clone(), class, reason))
            .copied()
            .unwrap_or_default()
    }

    /// `stale_dropped_total{class="small", reason}`, in entries rather than in calls.
    pub fn stale_dropped(&self, reason: StaleReason) -> u64 {
        self.stale_dropped
            .lock()
            .unwrap()
            .get(&reason)
            .copied()
            .unwrap_or_default()
    }

    /// `duplicates_dropped_total{class, source="overlay"}`.
    pub fn duplicates(&self, class: Class) -> u64 {
        self.duplicates
            .lock()
            .unwrap()
            .get(&class)
            .copied()
            .unwrap_or_default()
    }
}

/// `messages_total` and `bytes_total` for one direction, class and peer.
type Traffic = HashMap<(Direction, Class, Hostname), (u64, u64)>;

fn count<K: Ord + Clone>(counts: &Mutex<BTreeMap<K, u64>>, key: &K) -> u64 {
    counts.lock().unwrap().get(key).copied().unwrap_or_default()
}

fn add<K: Ord + Clone>(counts: &Mutex<BTreeMap<K, u64>>, key: K) {
    *counts.lock().unwrap().entry(key).or_default() += 1;
}

impl ManagerStats for CountingStats {
    fn handshake_failure(&self, failure: HandshakeFailure) {
        add(
            &self.handshake_failures,
            (failure.role.as_str(), failure.reason.as_str()),
        );
    }

    fn auth_via_previous_seed(&self, peer: &Hostname) {
        add(&self.previous_seed, peer.clone());
    }

    fn roster_region_mismatch(&self, peer: &Hostname) {
        add(&self.region_mismatches, peer.clone());
    }

    fn unknown_frame_type(&self, peer: &Hostname) {
        add(&self.unknown_frame_types, peer.clone());
    }

    fn dial_started(&self, peer: &Hostname) {
        add(&self.dials, peer.clone());
    }

    fn peers_connected(&self, counts: &PeerCounts) {
        *self.connected.lock().unwrap() = counts.clone();
    }

    fn peers_roster(&self, counts: &PeerCounts) {
        *self.in_roster.lock().unwrap() = counts.clone();
    }
}

impl TrafficStats for CountingStats {
    fn message(&self, direction: Direction, class: Class, peer: PeerLabels<'_>, bytes: usize) {
        let mut traffic = self.traffic.lock().unwrap();
        let counted = traffic
            .entry((direction, class, peer.hostname.clone()))
            .or_default();
        counted.0 += 1;
        counted.1 += bytes as u64;
    }
}

impl ReceiveStats for CountingStats {
    fn unknown_topic_id(&self, peer: &Hostname) {
        add(&self.unknown_topic_ids, peer.clone());
    }

    fn unwanted_topic(&self, peer: &Hostname) {
        add(&self.unwanted_topics, peer.clone());
    }

    fn invalid_payload(&self, peer: &Hostname) {
        add(&self.invalid_payloads, peer.clone());
    }

    fn first_seen(&self, class: Class) {
        *self.first_seen.lock().unwrap().entry(class).or_default() += 1;
    }

    fn duplicate(&self, class: Class) {
        *self.duplicates.lock().unwrap().entry(class).or_default() += 1;
    }

    fn fanout_suppressed(&self, peer: &Hostname, kind: FanoutKind) {
        add(&self.fanout_suppressed, (peer.clone(), kind));
    }
}

impl SenderStats for CountingStats {
    fn queue_depth(&self, peer: &Hostname, class: Class, frames: usize, bytes: usize) {
        self.queue_depths
            .lock()
            .unwrap()
            .insert((peer.clone(), class), (frames, bytes));
    }

    fn queue_drop(&self, peer: &Hostname, class: Class, reason: DropReason) {
        *self
            .queue_drops
            .lock()
            .unwrap()
            .entry((peer.clone(), class, reason))
            .or_default() += 1;
    }

    fn stale_dropped(&self, reason: StaleReason, entries: usize) {
        *self
            .stale_dropped
            .lock()
            .unwrap()
            .entry(reason)
            .or_default() += entries as u64;
    }
}

impl SubsStats for CountingStats {
    fn bn_subscriptions(&self, topics: usize) {
        *self.bn_subscriptions.lock().unwrap() = Some(topics);
    }
}

/// How a cluster is put together before it starts.
pub struct Builder {
    kinds: Vec<NodeKind>,
    cfg: Overlay,
    roster: Option<Vec<usize>>,
    small: config::SmallClass,
    fanout: config::Fanout,
    regions: Vec<Region>,
    advertised: BTreeMap<usize, u64>,
}

impl Builder {
    /// One node per entry, named in index order so that the index is also the tie-break order.
    pub fn new(kinds: &[NodeKind]) -> Self {
        Self {
            kinds: kinds.to_vec(),
            // Loopback keepalives that answer in microseconds, so a peer that stops answering
            // is out of the live set in about a second instead of the shipped five.
            cfg: Overlay {
                listen: "127.0.0.1:0".parse().unwrap(),
                keepalive: Duration::from_millis(100),
                idle_timeout: Duration::from_millis(1000),
                ..Overlay::default()
            },
            roster: None,
            small: config::SmallClass::default(),
            fanout: config::Fanout::default(),
            regions: vec![Region(REGION.to_owned()); kinds.len()],
            advertised: BTreeMap::new(),
        }
    }

    /// The region each node declares and is listed under in the roster, one entry per node. A
    /// cluster is one region unless a test says otherwise, which is what a relay plan needs
    /// (D15, D20).
    pub fn regions(mut self, regions: &[&str]) -> Self {
        self.regions = regions
            .iter()
            .map(|region| Region((*region).to_owned()))
            .collect();
        self
    }

    /// The fanout every sidecar in the cluster routes under, on the channel a reload publishes
    /// on (T-043).
    pub fn fanout(mut self, fanout: config::Fanout) -> Self {
        self.fanout = fanout;
        self
    }

    /// The transport settings every node runs under. Only `listen` is overridden, per node, with
    /// the loopback address it binds.
    pub fn overlay(mut self, cfg: Overlay) -> Self {
        self.cfg = cfg;
        self
    }

    /// Which nodes are in the roster the managers start with. Every node is, by default; a
    /// smaller set is how a test reloads one in later.
    pub fn roster(mut self, hosts: &[usize]) -> Self {
        self.roster = Some(hosts.to_vec());
        self
    }

    /// What node `index` advertises in its HELLO, for a cluster standing in for a fleet whose
    /// hosts are not all on one release. Applied before the node has a manager, so its first
    /// HELLO carries it.
    pub fn advertising(mut self, index: usize, features: u64) -> Self {
        self.advertised.insert(index, features);
        self
    }

    /// The batching window and stale bound every sidecar in the cluster runs under. The shipped
    /// defaults otherwise; a test that has to put several payloads in one window widens it
    /// rather than racing the scheduler for 10 ms.
    pub fn small(mut self, small: config::SmallClass) -> Self {
        self.small = small;
        self
    }

    /// Starts the cluster with the admission the sidecar ships, so every connection between two
    /// managers goes through the real handshake.
    pub async fn start(self) -> TestCluster<HelloAdmission> {
        self.start_each(|node| {
            Arc::new(HelloAdmission::new(
                node.self_hello.clone(),
                node.topics.clone(),
                node.stats.clone(),
            ))
        })
        .await
    }

    /// Starts the cluster with an admission of the test's own, shared by every node.
    pub async fn start_with<A: Admission>(self, admission: A) -> TestCluster<A> {
        let admission = Arc::new(admission);
        self.start_each(move |_| admission.clone()).await
    }

    /// One admission per node, rebuilt whenever a node restarts, because a node stands in for a
    /// process and a restarted process is a new one.
    async fn start_each<A: Admission>(
        self,
        admission: impl Fn(&Node) -> Arc<A> + Send + Sync + 'static,
    ) -> TestCluster<A> {
        let prefix = format!("c{}", CLUSTERS.fetch_add(1, Ordering::Relaxed));
        // Every cluster runs mid-rotation so that a node can hold a key from either seed, which
        // is the only way to reach the previous-seed path from outside.
        let seeds = Seeds {
            current: FleetSeed::from([0x11; 32]),
            previous: Some(FleetSeed::from([0x22; 32])),
        };
        let pins = Arc::new(ArcSwap::from_pointee(PinTable::default()));

        let mut hosts = Vec::new();
        let mut nodes = Vec::new();
        for (index, kind) in self.kinds.iter().copied().enumerate() {
            let hostname = Hostname(format!("{prefix}-bn-{index:02}"));
            let region = self.regions[index].clone();
            features::mask(&hostname, self.advertised.get(&index).copied());
            let self_hello = SelfHello {
                hostname: hostname.clone(),
                region: region.clone(),
                site: None,
                // Not the process id: every node in a cluster runs in this one process, and a
                // test about a restart needs them told apart the way two processes would be.
                instance_id: rand::random(),
            };
            let key = match (kind, &seeds.previous) {
                // Any key the fleet seed does not derive will do; a fixed one keeps the test
                // deterministic.
                (NodeKind::WrongKey, _) => SigningKey::from_bytes(&[0x42; 32]),
                (NodeKind::PreviousSeedKey, Some(previous)) => {
                    derive_tls_keypair(previous, &hostname)
                }
                _ => derive_tls_keypair(&seeds.current, &hostname),
            };
            let runtime = (kind == NodeKind::Vanishing).then(|| {
                tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .unwrap()
            });
            let node_pins = match kind {
                NodeKind::RefusesEveryone => Arc::new(ArcSwap::from_pointee(PinTable::default())),
                _ => pins.clone(),
            };
            let _guard = runtime.as_ref().map(tokio::runtime::Runtime::enter);
            let (endpoint, addr) = bind_reserved(&self.cfg, &node_pins, &key);
            let holding = !matches!(kind, NodeKind::Manager | NodeKind::Bare);
            let sink = holding.then(|| {
                let held = hold_connections(
                    endpoint.clone(),
                    node_pins.clone(),
                    self_hello.clone(),
                    kind,
                );
                match &runtime {
                    Some(runtime) => runtime.spawn(held),
                    None => tokio::spawn(held),
                }
            });
            drop(_guard);

            hosts.push(HostEntry {
                hostname: hostname.clone(),
                region,
                site: None,
                addr,
            });
            nodes.push(Node {
                self_hello,
                roster: watch::channel(Roster { hosts: Vec::new() }).0,
                topics: Arc::new(Mutex::new(OwnTopics::default())),
                hostname,
                key,
                kind,
                endpoint: Some(endpoint),
                manager: None,
                events: {
                    let (sender, receiver) = mpsc::channel(64);
                    (sender, Some(receiver))
                },
                stats: Arc::new(CountingStats::default()),
                runtime,
                sink,
                sidecar: None,
            });
        }

        let mut cluster = TestCluster {
            cfg: self.cfg,
            seeds,
            pins,
            hosts,
            nodes,
            admission: Box::new(admission),
            small: watch::channel(self.small).0,
            fanout: watch::channel(self.fanout).0,
        };
        let initial = self
            .roster
            .unwrap_or_else(|| (0..cluster.nodes.len()).collect());
        cluster.set_roster(&initial);
        for index in 0..cluster.nodes.len() {
            if cluster.nodes[index].kind == NodeKind::Manager {
                cluster.start_manager(index);
            }
        }
        cluster
    }
}

/// Binds an endpoint on a port of the harness's own, so the cluster keeps it for as long as the
/// test binary runs.
fn bind_reserved(
    cfg: &Overlay,
    pins: &Arc<ArcSwap<PinTable>>,
    key: &SigningKey,
) -> (quinn::Endpoint, SocketAddr) {
    for _ in 0..PORT_RANGE.len() {
        let port =
            PORT_RANGE.start + NEXT_PORT.fetch_add(1, Ordering::Relaxed) % PORT_RANGE.len() as u32;
        let cfg = Overlay {
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, port as u16)),
            ..cfg.clone()
        };
        if let Ok(endpoint) = endpoint::bind(&cfg, tls::server_config(pins.clone(), key).unwrap()) {
            let addr = endpoint.local_addr().unwrap();
            return (endpoint, addr);
        }
    }
    panic!("no free port in {PORT_RANGE:?}")
}

/// Accepts everything, answers HELLO, and lets nothing go, so the peer's connection stays up
/// until the endpoint or the runtime under it goes away. A sink that stayed silent would look to
/// the manager under test like a host that connects and never speaks, which is a different test.
async fn hold_connections(
    endpoint: quinn::Endpoint,
    pins: Arc<ArcSwap<PinTable>>,
    self_hello: SelfHello,
    kind: NodeKind,
) {
    let conflicting = kind == NodeKind::ConflictingTopicAdd;
    let announced = if conflicting {
        vec![(TopicId::new(1), topic("beacon_block").to_string())]
    } else {
        Vec::new()
    };
    // The connection keeps the peer's side of it alive; the answer keeps the control stream
    // open, which is what a peer that had a manager of its own would do with it.
    let mut held = Vec::new();
    let mut answered = Vec::new();
    while let Some(incoming) = endpoint.accept().await {
        if let Ok(connection) = incoming.await {
            if let Some(pinned) = tls::peer_identity(&pins.load(), &connection)
                && let Ok(mut peer) = crate::hello::perform(
                    connection.clone(),
                    Role::Accept,
                    &self_hello,
                    &pinned.hostname,
                    announced.clone(),
                    WAIT,
                    &(),
                )
                .await
            {
                if conflicting {
                    let contradiction = Frame::TopicAdd {
                        id: 1,
                        topic: topic("beacon_attestation_3").to_string(),
                    };
                    let _ = peer.control.write_frame(&contradiction).await;
                }
                if let NodeKind::ClosesWith(code) = kind {
                    // A close abandons whatever the streams still hold, so the HELLO this side
                    // just wrote would never reach the dialler and the connection would end in
                    // a refused admission instead of the close the test is about.
                    tokio::time::sleep(Duration::from_millis(30)).await;
                    code.close(&connection);
                }
                answered.push(peer);
            }
            held.push(connection);
        }
    }
}

struct Node {
    self_hello: SelfHello,
    /// This node's own roster, as a host loads its own file. One channel per node so a test can
    /// take one host out of another's roster and leave the pair with no connection.
    roster: watch::Sender<Roster>,
    topics: Arc<Mutex<OwnTopics>>,
    hostname: Hostname,
    key: SigningKey,
    kind: NodeKind,
    endpoint: Option<quinn::Endpoint>,
    manager: Option<Handle>,
    events: (mpsc::Sender<PeerEvent>, Option<mpsc::Receiver<PeerEvent>>),
    stats: Arc<CountingStats>,
    runtime: Option<tokio::runtime::Runtime>,
    sink: Option<JoinHandle<()>>,
    sidecar: Option<Sidecar>,
}

/// A running overlay of `n` hosts on loopback.
pub struct TestCluster<A: Admission = HelloAdmission> {
    cfg: Overlay,
    seeds: Seeds,
    pins: Arc<ArcSwap<PinTable>>,
    hosts: Vec<HostEntry>,
    nodes: Vec<Node>,
    admission: NodeAdmission<A>,
    /// What every sidecar's batcher runs under, on the channel a reload would publish on
    /// (T-043). Every node in a cluster shares it, the way every host in a fleet runs one
    /// `config.yaml`.
    small: watch::Sender<config::SmallClass>,
    /// What every sidecar's router routes under, on the same kind of channel and for the same
    /// reason (D36's threshold reloads).
    fanout: watch::Sender<config::Fanout>,
}

/// How a cluster builds a node's admission, which it does again whenever a node restarts.
type NodeAdmission<A> = Box<dyn Fn(&Node) -> Arc<A> + Send + Sync>;

impl TestCluster<HelloAdmission> {
    /// `hosts` managers, all in the roster from the start.
    pub async fn start(hosts: usize) -> Self {
        Builder::new(&vec![NodeKind::Manager; hosts]).start().await
    }
}

impl<A: Admission> TestCluster<A> {
    /// The name node `index` runs under.
    pub fn hostname(&self, index: usize) -> Hostname {
        self.nodes[index].hostname.clone()
    }

    /// The loopback address node `index` bound, which is what the roster carries for it.
    pub fn addr(&self, index: usize) -> SocketAddr {
        self.hosts[index].addr
    }

    /// Node `index`'s endpoint, for a test that wants to dial with something other than a
    /// manager.
    pub fn endpoint(&self, index: usize) -> &quinn::Endpoint {
        self.nodes[index].endpoint.as_ref().unwrap()
    }

    /// What node `index`'s manager has counted.
    pub fn stats(&self, index: usize) -> &CountingStats {
        &self.nodes[index].stats
    }

    /// When node `index`'s manager next dials `peer`, if it is waiting out a backoff.
    pub fn retry_at(&self, index: usize, peer: &Hostname) -> Option<Instant> {
        self.nodes[index]
            .manager
            .as_ref()
            .and_then(|manager| manager.retry_at(peer))
    }

    /// Who node `index` is connected to.
    pub fn live(&self, index: usize) -> LiveView {
        self.nodes[index]
            .manager
            .as_ref()
            .map(Handle::live)
            .unwrap_or_default()
    }

    /// The `DATAGRAM` frames node `index` has read from `peer`, counted by quinn on the
    /// connection itself. Datagrams that arrived rather than batches that were built, which is
    /// what a test about the small class's carrier is asking.
    pub fn datagrams_received(&self, index: usize, peer: &Hostname) -> u64 {
        self.live(index)
            .get(peer)
            .map_or(0, |live| live.connection.stats().frame_rx.datagram)
    }

    /// What node `index` puts in its own HELLO.
    pub fn self_hello(&self, index: usize) -> SelfHello {
        self.nodes[index].self_hello.clone()
    }

    /// The pin table every node in this cluster reads, as one host's would be after a reload.
    pub fn pins(&self) -> &Arc<ArcSwap<PinTable>> {
        &self.pins
    }

    /// The seed every host's key derives from.
    pub fn seeds(&self) -> &Seeds {
        &self.seeds
    }

    /// The transport settings the cluster runs under.
    pub fn cfg(&self) -> &Overlay {
        &self.cfg
    }

    /// What node `index` puts in its own HELLO and hands out topic ids from, so a test can
    /// intern a topic the way the mirror's `Changed` hook would (T-026).
    pub fn topics(&self, index: usize) -> &Arc<Mutex<OwnTopics>> {
        &self.nodes[index].topics
    }

    /// Node `index`'s peer events, for a test that runs a consumer of its own (T-027's
    /// exchange) instead of reading them here. The cluster's own [`next_event`](Self::next_event)
    /// has nothing to read for that node afterwards.
    pub fn take_events(&mut self, index: usize) -> mpsc::Receiver<PeerEvent> {
        self.nodes[index]
            .events
            .1
            .take()
            .unwrap_or_else(|| panic!("node {index}'s events have already been taken"))
    }

    fn events_mut(&mut self, index: usize) -> &mut mpsc::Receiver<PeerEvent> {
        self.nodes[index]
            .events
            .1
            .as_mut()
            .unwrap_or_else(|| panic!("node {index}'s events were taken by a consumer of its own"))
    }

    /// The next event from node `index`'s manager, failing the test rather than hanging when
    /// none arrives.
    pub async fn next_event(&mut self, index: usize) -> PeerEvent {
        tokio::time::timeout(WAIT, self.events_mut(index).recv())
            .await
            .unwrap_or_else(|_| panic!("no peer event from node {index} within {WAIT:?}"))
            .expect("the manager holds the sender for as long as the cluster does")
    }

    /// An event if one turns up quickly, for asserting that nothing more happens.
    pub async fn try_next_event(&mut self, index: usize) -> Option<PeerEvent> {
        tokio::time::timeout(SETTLE, self.events_mut(index).recv())
            .await
            .ok()
            .flatten()
    }

    /// Replaces the roster every node reads, and the pin table with it, the way a SIGHUP reload
    /// would (T-043).
    pub fn set_roster(&mut self, hosts: &[usize]) {
        let roster = self.roster_of(hosts);
        self.pins
            .store(Arc::new(PinTable::build(&roster, &self.seeds)));
        for node in &self.nodes {
            node.roster.send_replace(roster.clone());
        }
    }

    /// Replaces one node's roster and leaves everyone else's alone, as a fleet mid-rollout has
    /// it. A host missing from node `index`'s roster is one it never dials and refuses on the
    /// way in, so the pair has no connection while both are up. The pin table is shared and
    /// stays whole, which is what keeps the other pairs pairing.
    pub fn set_roster_for(&mut self, index: usize, hosts: &[usize]) {
        let roster = self.roster_of(hosts);
        self.nodes[index].roster.send_replace(roster);
    }

    fn roster_of(&self, hosts: &[usize]) -> Roster {
        Roster {
            hosts: hosts
                .iter()
                .map(|index| self.hosts[*index].clone())
                .collect(),
        }
    }

    /// Stops answering on node `index`'s socket without closing anything, which is what its
    /// peers see when the host dies.
    pub fn vanish(&mut self, index: usize) {
        if let Some(runtime) = self.nodes[index].runtime.take() {
            runtime.shutdown_background();
        }
    }

    /// Stops node `index`'s manager and starts a new one on the same port, as a sidecar restart
    /// would.
    pub async fn restart(&mut self, index: usize) {
        // The sidecar holds a live source, and through it the endpoint whose port has to come
        // free. A restarted process starts a new one anyway.
        self.nodes[index].sidecar = None;
        if let Some(manager) = self.nodes[index].manager.take() {
            manager.shutdown().await;
        }
        // Every `Up` still queued carries a connection, and a connection holds the endpoint's
        // socket open. A router would have taken them; a test that only watches the other side
        // has to drop them here or the port never comes free.
        if let Some(events) = &mut self.nodes[index].events.1 {
            while events.try_recv().is_ok() {}
        }
        self.nodes[index].endpoint = None;
        let cfg = Overlay {
            listen: self.hosts[index].addr,
            ..self.cfg.clone()
        };
        // The manager has closed the endpoint and waited for it to go idle, but quinn's driver
        // task holds the socket until the runtime gets round to dropping it, so the port comes
        // free a scheduler tick or two after `shutdown` returns rather than inside it.
        let deadline = tokio::time::Instant::now() + WAIT;
        let endpoint = loop {
            let server = tls::server_config(self.pins.clone(), &self.nodes[index].key).unwrap();
            match endpoint::bind(&cfg, server) {
                Ok(endpoint) => break endpoint,
                Err(error) if tokio::time::Instant::now() < deadline => {
                    tracing::debug!(%error, "port not free yet");
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => panic!("node {index} could not rebind {}: {error}", cfg.listen),
            }
        };
        self.nodes[index].endpoint = Some(endpoint);
        self.nodes[index].self_hello.instance_id = rand::random();
        self.start_manager(index);
    }

    /// A connection to node `to`, presenting `as_host`'s overlay key and leaving node `from`'s
    /// endpoint. A name the roster does not have still derives a key from the fleet seed, which
    /// is exactly what a host removed from the roster would present.
    pub async fn dial_as(
        &self,
        as_host: &Hostname,
        from: usize,
        to: usize,
    ) -> Result<quinn::Connection, EndpointError> {
        let key = derive_tls_keypair(&self.seeds.current, as_host);
        let client = tls::client_config(self.pins.clone(), &key, &self.hostname(to)).unwrap();
        endpoint::connect(&self.cfg, self.endpoint(from), self.addr(to), client).await
    }

    /// A second connection from node `from` to node `to`, under `from`'s own identity.
    pub async fn dial(&self, from: usize, to: usize) -> Result<quinn::Connection, EndpointError> {
        self.dial_as(&self.hostname(from), from, to).await
    }

    /// Both ends of one connection, for a test that plays the handshake itself. Node `to` has to
    /// be a [`NodeKind::Bare`]: the accept happens here, and a sink would take the connection
    /// first.
    pub async fn connected_pair(
        &self,
        from: usize,
        to: usize,
    ) -> (quinn::Connection, quinn::Connection) {
        let accepting = async {
            self.endpoint(to)
                .accept()
                .await
                .expect("the endpoint is still open")
                .await
                .unwrap()
        };
        let (dialled, accepted) = tokio::join!(self.dial(from, to), accepting);
        (dialled.unwrap(), accepted)
    }

    /// A connection to node `to` that has been through the dialler's half of the handshake,
    /// which is what a peer with a manager of its own would have done. `self_hello` is what the
    /// far end learns about the caller, so a test decides for itself which process it is.
    pub async fn dial_with_hello(
        &self,
        from: usize,
        to: usize,
        self_hello: &SelfHello,
    ) -> PeerInfo {
        self.dial_announcing(from, to, self_hello, Vec::new()).await
    }

    /// The same, with a topic table in the HELLO. Node `to` decodes every frame from this
    /// connection against `announced` and nothing else (D13), so a test that writes frames by
    /// hand says here what its ids mean.
    pub async fn dial_announcing(
        &self,
        from: usize,
        to: usize,
        self_hello: &SelfHello,
        announced: Vec<(TopicId, String)>,
    ) -> PeerInfo {
        let connection = self.dial(from, to).await.unwrap();
        crate::hello::perform(
            connection,
            Role::Dial,
            self_hello,
            &self.hostname(to),
            announced,
            WAIT,
            &(),
        )
        .await
        .unwrap()
    }

    /// The live set as node `index`'s fanout task reads it.
    pub fn live_source(&self, index: usize) -> LiveSource {
        self.nodes[index]
            .manager
            .as_ref()
            .expect("node has a manager")
            .live_source()
    }

    /// Starts node `index`'s overlay pipeline with the beacon node it would have standing in
    /// for: `sets` is what its mirror reports (T-014), what reaches it arrives through
    /// [`from_bn`](Self::from_bn), and what it would publish is [`published`](Self::published).
    pub fn start_sidecar(&mut self, index: usize, sets: SubscriptionSets) {
        self.start_sidecar_with(index, sets, PUBLISHED_MAX);
    }

    /// The same with a publish stand-in of `published_max` entries, for a test about what a
    /// beacon node that has stopped draining costs (DX-N4).
    pub fn start_sidecar_with(
        &mut self,
        index: usize,
        sets: SubscriptionSets,
        published_max: usize,
    ) {
        let events = self.take_events(index);
        let live = self.live_source(index);
        let node = &self.nodes[index];
        let stats = node.stats.clone();
        let published = Arc::new(PublishSpy::new(published_max));
        let seen = SharedSeenCache::new(SeenCache::new(
            SEEN_TTL,
            SEEN_CAPACITY,
            Arc::new(SystemClock),
        ));
        let (subscriptions, watching) = watch::channel(sets);
        let identity = SelfIdentity {
            hostname: node.hostname.clone(),
            region: node.self_hello.region.clone(),
            site: None,
        };
        let deps = Deps {
            seen: seen.clone(),
            publish: published.clone(),
            sets: watching.clone(),
            stripes: Arc::new(NoStripes::new(stats.clone())),
            stats: stats.clone(),
            node: Arc::new(identity.clone()),
            clock: Arc::new(SystemClock),
            // The slot length comes from the beacon node's spec snapshot in production
            // (CL-N3); a cluster has no beacon node, so it runs at mainnet's.
            budget: FanoutBudget::default_for(
                self.hosts.len(),
                config::LargeClass::default().chunk_bytes,
                12,
                Instant::now(),
            ),
        };
        let receivers: Receivers = Arc::new(Mutex::new(BTreeMap::new()));
        let (to_exchange, exchanged) = mpsc::channel(64);
        let lanes = ClassLanes::new(Arc::new(()));
        let to_fanout = lanes.pusher();
        let (small, batching) = Batching::spawn(self.small.subscribe(), stats.clone());
        let tasks = vec![
            crate::subs::spawn(exchanged, watching, node.topics.clone(), stats.clone()),
            tokio::spawn(receive_peers(events, to_exchange, deps, receivers.clone())),
            Fanout::spawn(
                lanes,
                live,
                identity,
                self.fanout.subscribe(),
                node.topics.clone(),
                small,
                stats,
                Arc::default(),
            ),
            batching,
        ];
        self.nodes[index].sidecar = Some(Sidecar {
            seen,
            to_fanout,
            published,
            subscriptions,
            receivers,
            tasks,
        });
    }

    /// What node `index`'s beacon node is subscribed to now, as a change the mirror reports.
    pub fn subscribe(&self, index: usize, sets: SubscriptionSets) {
        self.sidecar(index).subscriptions.send_replace(sets);
    }

    /// Hands node `index` a message as its beacon node would (T-016): the id is computed, the
    /// seen cache is asked first, and a new message goes to the fanout task. `false` means the
    /// sidecar had already seen it, which is what a beacon node echoing back what the overlay
    /// just published looks like.
    pub fn from_bn(&self, index: usize, topic: &Topic, payload: &[u8]) -> bool {
        let sidecar = self.sidecar(index);
        let payload = Bytes::copy_from_slice(payload);
        let class = Class::of(topic.kind(), payload.len());
        let id = msgid::compute(&topic.to_string(), &payload, MAX_PAYLOAD_BYTES).id;
        if !sidecar.seen.insert(id) {
            return false;
        }
        sidecar
            .to_fanout
            .push(
                class,
                Outbound {
                    topic: topic.clone(),
                    class,
                    id,
                    payload,
                    received_at: Instant::now(),
                },
            )
            .expect("the fanout lane has room");
        true
    }

    /// Node `index`'s seen cache, which is what says whether a message was recorded as well as
    /// published (D08).
    pub fn seen(&self, index: usize) -> &SharedSeenCache {
        &self.sidecar(index).seen
    }

    /// What node `index` has queued for its beacon node, oldest first.
    pub fn published(&self, index: usize) -> Vec<PublishItem> {
        self.sidecar(index).published.published()
    }

    /// `publish_queue_drops_total` for node `index`: what its publish queue threw away because
    /// nothing was draining it.
    pub fn publish_drops(&self, index: usize) -> u64 {
        self.sidecar(index).published.dropped()
    }

    /// Node `index`'s receiver for `peer`, while the pair is live.
    pub fn receiver(&self, index: usize, peer: &Hostname) -> Option<Arc<PeerReceiver>> {
        self.sidecar(index)
            .receivers
            .lock()
            .unwrap()
            .get(peer)
            .cloned()
    }

    fn sidecar(&self, index: usize) -> &Sidecar {
        self.nodes[index]
            .sidecar
            .as_ref()
            .unwrap_or_else(|| panic!("node {index} has no sidecar started"))
    }

    fn start_manager(&mut self, index: usize) {
        let node = &self.nodes[index];
        let manager = ConnectionManager::spawn(
            Local {
                cfg: self.cfg.clone(),
                self_id: SelfIdentity {
                    hostname: node.hostname.clone(),
                    region: Region(REGION.to_owned()),
                    site: None,
                },
                pins: self.pins.clone(),
                own_key: node.key.clone(),
            },
            node.endpoint.clone().unwrap(),
            node.roster.subscribe(),
            (self.admission)(node),
            node.events.0.clone(),
            node.stats.clone(),
            sender::Deps {
                // One ledger per node, because a node stands in for a process and the cap is
                // what one sidecar holds across its peers.
                ledger: Arc::new(LargeLedger::new(LARGE_QUEUED_BYTES_MAX)),
                stats: node.stats.clone(),
            },
            Arc::default(),
        );
        self.nodes[index].manager = Some(manager);
    }
}

impl<A: Admission> Drop for TestCluster<A> {
    /// Closing every endpoint is what stops the tasks: an accept loop ends when its endpoint
    /// does, and a dial task's next attempt fails at once instead of holding a socket open for
    /// the rest of the test binary.
    fn drop(&mut self) {
        for node in &mut self.nodes {
            if let Some(sink) = node.sink.take() {
                sink.abort();
            }
            if let Some(endpoint) = &node.endpoint {
                endpoint.close(CloseCode::Shutdown.code(), CloseCode::Shutdown.reason());
            }
            if let Some(runtime) = node.runtime.take() {
                runtime.shutdown_background();
            }
        }
    }
}

/// One node's overlay pipeline, on top of the manager the cluster already runs for it.
struct Sidecar {
    /// The cache all three insert sites share, so what the overlay delivered is remembered
    /// when the beacon node echoes it back (§5.5).
    seen: SharedSeenCache,
    to_fanout: LanePusher<Outbound>,
    published: Arc<PublishSpy>,
    subscriptions: watch::Sender<SubscriptionSets>,
    receivers: Receivers,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Sidecar {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

/// One receiver per live peer, kept where a test can reach one.
type Receivers = Arc<Mutex<BTreeMap<Hostname, Arc<PeerReceiver>>>>;

/// The tee in front of T-027's exchange: a receiver per live peer, then the event on to the
/// exchange, which owns the peer's control stream. T-045 wires the two the same way, because
/// only one consumer can hold the manager's events and both halves need them.
async fn receive_peers(
    mut events: mpsc::Receiver<PeerEvent>,
    exchange: mpsc::Sender<PeerEvent>,
    deps: Deps,
    receivers: Receivers,
) {
    while let Some(event) = events.recv().await {
        match &event {
            PeerEvent::Up(peer) => {
                let receiver = Arc::new(PeerReceiver::spawn(peer, deps.clone()));
                receivers
                    .lock()
                    .unwrap()
                    .insert(peer.hostname.clone(), receiver);
            }
            PeerEvent::Down(peer, _) => {
                receivers.lock().unwrap().remove(peer);
            }
        }
        if exchange.send(event).await.is_err() {
            return;
        }
    }
}

/// Stands in for T-017's publisher: what reaches it is what would reach the beacon node. It is
/// bounded and drops its oldest entry like the real queue (DX-N4), so a test can wedge it
/// without pushing four thousand messages through a live overlay.
pub struct PublishSpy {
    capacity: usize,
    items: Mutex<VecDeque<PublishItem>>,
    dropped: AtomicU64,
}

impl PublishSpy {
    /// A spy that holds `capacity` entries before it starts dropping the oldest.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            items: Mutex::new(VecDeque::new()),
            dropped: AtomicU64::new(0),
        }
    }

    /// What is queued, oldest first.
    pub fn published(&self) -> Vec<PublishItem> {
        self.items.lock().unwrap().iter().cloned().collect()
    }

    /// How many entries were dropped to make room.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

impl PublishSink for PublishSpy {
    fn enqueue(&self, item: PublishItem) {
        let mut items = self.items.lock().unwrap();
        while items.len() >= self.capacity {
            items.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        items.push_back(item);
    }
}

/// A peer's transport as a test holds it: every frame it is given is recorded, and a spy that
/// starts [`stalled`](SendSpy::stalled) writes nothing until the test lets it go, which is what
/// a peer whose congestion window has closed does to its sender.
#[derive(Clone)]
pub struct SendSpy(Arc<SpyState>);

struct SpyState {
    permits: tokio::sync::Semaphore,
    sent: Mutex<Vec<Bytes>>,
    datagrams: Mutex<Vec<Bytes>>,
}

impl SendSpy {
    /// A transport that takes everything at once.
    pub fn open() -> Self {
        Self::with_permits(tokio::sync::Semaphore::MAX_PERMITS)
    }

    /// A transport that takes nothing until [`release`](Self::release).
    pub fn stalled() -> Self {
        Self::with_permits(0)
    }

    /// A transport that takes `frames` and then stalls, for a test that has to see a sender
    /// part way through its queue.
    pub fn taking(frames: usize) -> Self {
        Self::with_permits(frames)
    }

    fn with_permits(permits: usize) -> Self {
        Self(Arc::new(SpyState {
            permits: tokio::sync::Semaphore::new(permits),
            sent: Mutex::new(Vec::new()),
            datagrams: Mutex::new(Vec::new()),
        }))
    }

    /// Lets the sender write everything it has been holding, and everything after it.
    pub fn release(&self) {
        self.0
            .permits
            .add_permits(tokio::sync::Semaphore::MAX_PERMITS);
    }

    /// The frames written on streams so far, in the order they went.
    pub fn sent(&self) -> Vec<Bytes> {
        self.0.sent.lock().unwrap().clone()
    }

    /// The frames handed to the path as datagrams. A datagram waits for no permit, because a
    /// real one waits for no window either.
    pub fn datagrams(&self) -> Vec<Bytes> {
        self.0.datagrams.lock().unwrap().clone()
    }
}

impl Transport for SendSpy {
    async fn send(&self, frame: Bytes) -> std::io::Result<()> {
        self.0
            .permits
            .acquire()
            .await
            .map_err(std::io::Error::other)?
            .forget();
        self.0.sent.lock().unwrap().push(frame);
        Ok(())
    }

    fn send_datagram(&self, frame: Bytes) -> Result<(), quinn::SendDatagramError> {
        self.0.datagrams.lock().unwrap().push(frame);
        Ok(())
    }
}

/// A topic on the one fork digest the harness uses.
pub fn topic(name: &str) -> Topic {
    Topic::parse(&format!("/eth2/6a95a1a9/{name}/ssz_snappy")).unwrap()
}

/// What the mirror reports for a beacon node subscribed to `advertised`, with `extra` standing
/// for T-015's own-proposal column topics: interned and announced so their ids reach peers, and
/// left out of the bitmap because the beacon node never asked for them (D06).
pub fn subscriptions(advertised: &[&Topic], extra: &[&Topic]) -> SubscriptionSets {
    let cloned =
        |set: &[&Topic]| -> Vec<Topic> { set.iter().map(|topic| (*topic).clone()).collect() };
    SubscriptionSets {
        advertised: cloned(advertised).into_iter().collect(),
        local: cloned(advertised)
            .into_iter()
            .chain(cloned(extra))
            .collect(),
    }
}

/// Polls until `ready` holds, failing the test rather than hanging when it never does.
pub async fn eventually(what: &str, ready: impl FnMut() -> bool) {
    poll(WAIT, Duration::from_millis(10), what, ready).await;
}

/// The same under a bound the test is asserting rather than guarding: it polls tightly enough
/// that the polling is not what a wall-clock claim measures.
pub async fn within(bound: Duration, what: &str, ready: impl FnMut() -> bool) {
    poll(bound, Duration::from_millis(1), what, ready).await;
}

async fn poll(bound: Duration, every: Duration, what: &str, mut ready: impl FnMut() -> bool) {
    let polling = async {
        while !ready() {
            tokio::time::sleep(every).await;
        }
    };
    tokio::time::timeout(bound, polling)
        .await
        .unwrap_or_else(|_| panic!("{what} did not happen within {bound:?}"));
}

/// A peer's state as its `SUBS` and `TOPIC_ADD`s would have left it: `bindings` are the topic
/// ids the peer announced, `bits` the ids its beacon node is subscribed to. The two are
/// separate because a peer that has announced a topic without setting its bit is the ordinary
/// way a beacon node stops wanting one.
pub fn peer_state(bindings: &[(u16, &Topic)], bits: &[u16]) -> PeerState {
    let mut table = PeerTopicTable::new();
    for (id, topic) in bindings {
        table
            .apply_add(TopicId::new(*id), &topic.to_string())
            .unwrap();
    }
    let mut bitmap = Bitmap::new();
    for bit in bits {
        bitmap.set(TopicId::new(*bit));
    }
    PeerState { table, bitmap }
}

/// A live view of peers a test built entry by entry, for the readers that report the fields a
/// routing view leaves at their defaults (T-042's `status`).
pub fn view_of(peers: Vec<(Hostname, LivePeer)>) -> LiveView {
    LiveView(peers.into_iter().collect())
}

/// A live view of peers a test has decided the subscriptions of. They share one connection,
/// because nothing about a subscription or a routing question reads it.
pub fn view(connection: &quinn::Connection, peers: Vec<(Hostname, PeerState)>) -> LiveView {
    LiveView(
        peers
            .into_iter()
            .map(|(hostname, state)| {
                (
                    hostname.clone(),
                    LivePeer {
                        region: Region(REGION.to_owned()),
                        site: None,
                        rtt: Duration::ZERO,
                        connected_since: Instant::now(),
                        instance_id: 0,
                        software_version: "test".to_owned(),
                        negotiated: Negotiated {
                            minor: 0,
                            features: 0,
                            // What a v1 peer advertises, so a send path reading this view is
                            // not stopped by a limit no real peer would name.
                            peer_max_frame_bytes: MAX_FRAME_BYTES,
                            peer_max_batch_entries: 0,
                        },
                        connection: connection.clone(),
                        sender: SenderHandle::stopped(hostname.clone()),
                        state: Arc::new(Mutex::new(state)),
                    },
                )
            })
            .collect(),
    )
}

/// The feature bits one host advertises in its HELLO, for the fallback D29 exists for.
///
/// Every node in a test binary runs one build, so the intersection two of them negotiate is
/// always the whole set and no fallback can ever run. Masking what one host advertises is what
/// the other side of a fleet halfway through an upgrade looks like (T-062, T-051 scenario 18).
/// It takes effect on the next HELLO that host sends, so a running node is restarted to change
/// it, the way a real one would be.
///
/// ```ignore
/// features::mask(fleet.node(2).hostname(), Some(0));
/// fleet.restart_node(2).await;
/// ```
pub mod features {
    use std::collections::HashMap;
    use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};

    use overlay_core::protocol::SUPPORTED_FEATURES;
    use overlay_core::roster::Hostname;

    static MASKED: LazyLock<Mutex<HashMap<Hostname, u64>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

    fn masked() -> MutexGuard<'static, HashMap<Hostname, u64>> {
        MASKED.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Makes `host` advertise `features` instead of what its build supports, or what its build
    /// supports again with `None`.
    pub fn mask(host: &Hostname, features: Option<u64>) {
        match features {
            Some(features) => {
                masked().insert(host.clone(), features);
            }
            None => {
                masked().remove(host);
            }
        }
    }

    /// What `host` puts in its HELLO: what it was masked to, or this build's own set, which is
    /// every host outside a test about the fallback.
    pub(crate) fn advertised(host: &Hostname) -> u64 {
        masked().get(host).copied().unwrap_or(SUPPORTED_FEATURES)
    }
}

/// The datagram limit one host's batcher fills a batch to, for T-062's fallback test.
///
/// A `TooLarge` from `send_datagram` is path MTU dropping between the batcher's check and the
/// send, and nothing a test can do to a loopback connection makes quinn's answer to
/// `max_datagram_size` disagree with what the same connection will then take. So the fanout
/// reads the limit through here, and a host set to a limit larger than its path really holds
/// builds exactly the batch that case produces.
///
/// ```ignore
/// datagram_limit::set(&cluster.hostname(0), Some(8192));
/// ```
pub mod datagram_limit {
    use std::collections::HashMap;
    use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};

    use overlay_core::roster::Hostname;

    static FORCED: LazyLock<Mutex<HashMap<Hostname, usize>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

    fn forced_limits() -> MutexGuard<'static, HashMap<Hostname, usize>> {
        FORCED.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Makes `host` batch to `max_bytes` whatever its connections hold, or gives it quinn's own
    /// answer back with `None`.
    pub fn set(host: &Hostname, max_bytes: Option<usize>) {
        match max_bytes {
            Some(max_bytes) => {
                forced_limits().insert(host.clone(), max_bytes);
            }
            None => {
                forced_limits().remove(host);
            }
        }
    }

    /// What `host` has been told to batch to, if anything. Nothing for every host outside the
    /// fallback test.
    pub(crate) fn forced(host: &Hostname) -> Option<usize> {
        forced_limits().get(host).copied()
    }
}

/// A byte rate one host reads its peers' data streams at, for T-051's scenario 14.
///
/// The overlay has no bandwidth knob and netem is not available inside a test binary, so a slow
/// host is made by pausing its own reads. [`crate::receive`] waits here before each frame and
/// charges what it delivered, and because the pacer is shared by every stream task of a host,
/// paying for one message keeps the next stream unread. Data then piles up behind the
/// connection's flow-control window until the senders' large lanes overflow, which is the
/// behaviour D17's bounds exist for.
///
/// ```ignore
/// throttle::set(&cluster.hostname(2), Some(125_000)); // 1 Mbps
/// // ... publish, then:
/// throttle::set(&cluster.hostname(2), None);
/// ```
pub mod throttle {
    use std::collections::HashMap;
    use std::sync::{LazyLock, Mutex, MutexGuard, PoisonError};
    use std::time::{Duration, Instant};

    use overlay_core::roster::Hostname;

    /// The longest single pause. A paced reader comes back often enough that dropping its
    /// receiver still ends the task promptly, and no wait in the fleet harness is longer than
    /// this.
    const SLICE: Duration = Duration::from_millis(50);

    /// One host's rate and the moment it has paid off what it has read.
    struct Pacer {
        bytes_per_s: u64,
        ready_at: Instant,
    }

    static PACED: LazyLock<Mutex<HashMap<Hostname, Pacer>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

    fn paced() -> MutexGuard<'static, HashMap<Hostname, Pacer>> {
        PACED.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Paces `host`'s reads at `bytes_per_s`, or lets them run at full speed again with `None`.
    pub fn set(host: &Hostname, bytes_per_s: Option<u64>) {
        match bytes_per_s {
            Some(bytes_per_s) if bytes_per_s > 0 => {
                paced().insert(
                    host.clone(),
                    Pacer {
                        bytes_per_s,
                        ready_at: Instant::now(),
                    },
                );
            }
            _ => {
                paced().remove(host);
            }
        }
    }

    /// Charges `bytes` against `host`'s rate, which is what the next [`wait`] pays for.
    pub(crate) fn charge(host: &Hostname, bytes: usize) {
        let mut paced = paced();
        if let Some(pacer) = paced.get_mut(host) {
            let owed = Duration::from_secs_f64(bytes as f64 / pacer.bytes_per_s as f64);
            pacer.ready_at = pacer.ready_at.max(Instant::now()) + owed;
        }
    }

    /// Returns once `host` has paid for everything it has read. Immediately for a host nothing
    /// has throttled, which is every host outside scenario 14.
    pub(crate) async fn wait(host: &Hostname) {
        loop {
            let Some(ready_at) = paced().get(host).map(|pacer| pacer.ready_at) else {
                return;
            };
            let Some(left) = ready_at.checked_duration_since(Instant::now()) else {
                return;
            };
            tokio::time::sleep(left.min(SLICE)).await;
        }
    }
}
