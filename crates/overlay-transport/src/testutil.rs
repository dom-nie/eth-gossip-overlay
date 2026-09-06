//! A real overlay on loopback, for this crate's tests and for the crates that need one running:
//! T-032's fanout and T-051's fleet harness.
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
//! Two simplifications a reader should know about. Every node shares one pin table and one
//! roster channel, where real hosts each load their own, so [`TestCluster::set_roster`] reloads
//! the whole cluster at once. And hostnames carry a per-cluster prefix, so a test that reads the
//! captured log can tell its own peers' lines from another test's.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use ed25519_dalek::SigningKey;
use overlay_core::config::Overlay;
use overlay_core::identity::{FleetSeed, Seeds, derive_tls_keypair};
use overlay_core::roster::{HostEntry, Hostname, Region, Roster, SelfIdentity};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::endpoint::{self, EndpointError};
use overlay_core::topic::table::TopicId;
use overlay_core::wire::Frame;

use crate::hello::{HelloAdmission, OwnTopics, SelfHello};
use crate::manager::{
    Admission, CloseCode, ConnectionManager, Handle, LiveView, Local, ManagerStats, PeerCounts,
    PeerEvent, PeerInfo,
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
}

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
        }
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
        let (roster, _) = watch::channel(Roster { hosts: Vec::new() });
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
            let self_hello = SelfHello {
                hostname: hostname.clone(),
                region: Region(REGION.to_owned()),
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
                region: Region(REGION.to_owned()),
                site: None,
                addr,
            });
            nodes.push(Node {
                self_hello,
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
            });
        }

        let mut cluster = TestCluster {
            cfg: self.cfg,
            seeds,
            pins,
            hosts,
            roster,
            nodes,
            admission: Box::new(admission),
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
        vec![(TopicId::new(1), topic("beacon_block"))]
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
                && let Ok(peer) = crate::hello::perform(
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
                let mut peer = peer;
                if conflicting {
                    let contradiction = Frame::TopicAdd {
                        id: 1,
                        topic: topic("beacon_attestation_3"),
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
}

/// A running overlay of `n` hosts on loopback.
pub struct TestCluster<A: Admission = HelloAdmission> {
    cfg: Overlay,
    seeds: Seeds,
    pins: Arc<ArcSwap<PinTable>>,
    hosts: Vec<HostEntry>,
    roster: watch::Sender<Roster>,
    nodes: Vec<Node>,
    admission: NodeAdmission<A>,
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
        let roster = Roster {
            hosts: hosts
                .iter()
                .map(|index| self.hosts[*index].clone())
                .collect(),
        };
        self.pins
            .store(Arc::new(PinTable::build(&roster, &self.seeds)));
        self.roster.send_replace(roster);
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
        let connection = self.dial(from, to).await.unwrap();
        crate::hello::perform(
            connection,
            Role::Dial,
            self_hello,
            &self.hostname(to),
            Vec::new(),
            WAIT,
            &(),
        )
        .await
        .unwrap()
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
            self.roster.subscribe(),
            (self.admission)(node),
            node.events.0.clone(),
            node.stats.clone(),
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

/// A topic on the one fork digest the harness uses.
fn topic(name: &str) -> String {
    format!("/eth2/6a95a1a9/{name}/ssz_snappy")
}

/// Polls until `ready` holds, failing the test rather than hanging when it never does.
pub async fn eventually(what: &str, mut ready: impl FnMut() -> bool) {
    let poll = async {
        while !ready() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::time::timeout(WAIT, poll)
        .await
        .unwrap_or_else(|_| panic!("{what} did not happen within {WAIT:?}"));
}
