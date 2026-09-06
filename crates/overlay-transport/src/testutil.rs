//! A real overlay on loopback, for this crate's tests and for the crates that need one running:
//! T-032's fanout and T-051's fleet harness.
//!
//! [`TestCluster`] binds an endpoint per host on an ephemeral port, builds the roster from the
//! ports it got, and then starts a [`ConnectionManager`] on each. Binding first is what lets the
//! roster hold real addresses without a fixed port anywhere, so several clusters run in parallel
//! in one test binary. Not every host has to run a manager: a [`NodeKind::Sink`] is an endpoint
//! that accepts and holds, which is how a test drives one manager from the outside.
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
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use ed25519_dalek::SigningKey;
use overlay_core::config::Overlay;
use overlay_core::identity::{FleetSeed, Seeds, derive_tls_keypair};
use overlay_core::roster::{HostEntry, Hostname, Region, Roster, SelfIdentity};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::endpoint::{self, EndpointError};
use crate::manager::{
    Admission, CloseCode, ConnectionManager, Handle, IdentityAdmission, LiveView, Local,
    ManagerStats, PeerCounts, PeerEvent,
};
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
}

/// Everything the manager counts, so a test can read a series by name.
#[derive(Debug, Default)]
pub struct CountingStats {
    handshake_failures: Mutex<BTreeMap<(&'static str, &'static str), u64>>,
    previous_seed: Mutex<BTreeMap<Hostname, u64>>,
    region_mismatches: Mutex<BTreeMap<Hostname, u64>>,
    dials: Mutex<BTreeMap<Hostname, u64>>,
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

    /// How many dials to `peer` this host started.
    pub fn dials(&self, peer: &Hostname) -> u64 {
        count(&self.dials, peer)
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

    fn dial_started(&self, peer: &Hostname) {
        add(&self.dials, peer.clone());
    }

    // No test reads the gauges, and a gauge that is only ever set has nothing to assert on.
    fn peers_connected(&self, _: &PeerCounts) {}
    fn peers_roster(&self, _: &PeerCounts) {}
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

    /// Starts the cluster with the admission this ticket ships.
    pub async fn start(self) -> TestCluster<IdentityAdmission> {
        let (roster, _) = watch::channel(Roster { hosts: Vec::new() });
        let admission = IdentityAdmission::new(roster.subscribe());
        self.start_with_channel(roster, admission).await
    }

    /// Starts the cluster with an admission of the test's own.
    pub async fn start_with<A: Admission>(self, admission: A) -> TestCluster<A> {
        let (roster, _) = watch::channel(Roster { hosts: Vec::new() });
        self.start_with_channel(roster, admission).await
    }

    async fn start_with_channel<A: Admission>(
        self,
        roster: watch::Sender<Roster>,
        admission: A,
    ) -> TestCluster<A> {
        let prefix = format!("c{}", CLUSTERS.fetch_add(1, Ordering::Relaxed));
        let seeds = Seeds {
            current: FleetSeed::from([0x11; 32]),
            previous: None,
        };
        let pins = Arc::new(ArcSwap::from_pointee(PinTable::default()));

        let mut hosts = Vec::new();
        let mut nodes = Vec::new();
        for (index, kind) in self.kinds.iter().copied().enumerate() {
            let hostname = Hostname(format!("{prefix}-bn-{index:02}"));
            let key = match kind {
                // Any key the fleet seed does not derive will do; a fixed one keeps the test
                // deterministic.
                NodeKind::WrongKey => SigningKey::from_bytes(&[0x42; 32]),
                _ => derive_tls_keypair(&seeds.current, &hostname),
            };
            let runtime = (kind == NodeKind::Vanishing).then(|| {
                tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .unwrap()
            });
            let _guard = runtime.as_ref().map(tokio::runtime::Runtime::enter);
            let endpoint =
                endpoint::bind(&self.cfg, tls::server_config(pins.clone(), &key).unwrap()).unwrap();
            let addr = endpoint.local_addr().unwrap();
            let sink = (kind != NodeKind::Manager).then(|| match &runtime {
                Some(runtime) => runtime.spawn(hold_connections(endpoint.clone())),
                None => tokio::spawn(hold_connections(endpoint.clone())),
            });
            drop(_guard);

            hosts.push(HostEntry {
                hostname: hostname.clone(),
                region: Region(REGION.to_owned()),
                site: None,
                addr,
            });
            nodes.push(Node {
                hostname,
                key,
                kind,
                endpoint: Some(endpoint),
                manager: None,
                events: mpsc::channel(64),
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
            admission: Arc::new(admission),
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

/// Accepts everything and lets nothing go, so the peer's connection stays up until the endpoint
/// or the runtime under it goes away.
async fn hold_connections(endpoint: quinn::Endpoint) {
    let mut held = Vec::new();
    while let Some(incoming) = endpoint.accept().await {
        if let Ok(connection) = incoming.await {
            held.push(connection);
        }
    }
}

struct Node {
    hostname: Hostname,
    key: SigningKey,
    kind: NodeKind,
    endpoint: Option<quinn::Endpoint>,
    manager: Option<Handle>,
    events: (mpsc::Sender<PeerEvent>, mpsc::Receiver<PeerEvent>),
    stats: Arc<CountingStats>,
    runtime: Option<tokio::runtime::Runtime>,
    sink: Option<JoinHandle<()>>,
}

/// A running overlay of `n` hosts on loopback.
pub struct TestCluster<A: Admission = IdentityAdmission> {
    cfg: Overlay,
    seeds: Seeds,
    pins: Arc<ArcSwap<PinTable>>,
    hosts: Vec<HostEntry>,
    roster: watch::Sender<Roster>,
    nodes: Vec<Node>,
    admission: Arc<A>,
}

impl TestCluster<IdentityAdmission> {
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

    /// Who node `index` is connected to.
    pub fn live(&self, index: usize) -> LiveView {
        self.nodes[index]
            .manager
            .as_ref()
            .map(Handle::live)
            .unwrap_or_default()
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

    /// The next event from node `index`'s manager, failing the test rather than hanging when
    /// none arrives.
    pub async fn next_event(&mut self, index: usize) -> PeerEvent {
        tokio::time::timeout(WAIT, self.nodes[index].events.1.recv())
            .await
            .unwrap_or_else(|_| panic!("no peer event from node {index} within {WAIT:?}"))
            .expect("the manager holds the sender for as long as the cluster does")
    }

    /// An event if one turns up quickly, for asserting that nothing more happens.
    pub async fn try_next_event(&mut self, index: usize) -> Option<PeerEvent> {
        tokio::time::timeout(SETTLE, self.nodes[index].events.1.recv())
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
        self.nodes[index].endpoint = None;
        let cfg = Overlay {
            listen: self.hosts[index].addr,
            ..self.cfg.clone()
        };
        let server = tls::server_config(self.pins.clone(), &self.nodes[index].key).unwrap();
        self.nodes[index].endpoint = Some(endpoint::bind(&cfg, server).unwrap());
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
            self.admission.clone(),
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
