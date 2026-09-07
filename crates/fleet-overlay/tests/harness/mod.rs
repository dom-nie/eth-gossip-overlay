//! N complete sidecars in one process, each with a fake beacon node of its own (T-051).
//!
//! Every node is the wiring `fleet-overlay run` builds: [`App::build`] reads a `config.yaml`, a
//! `roster.yaml`, a fleet seed and a node key from a directory of its own, writes its
//! `lighthouse.env`, binds a metrics endpoint and an admin socket, and dials the rest of the
//! roster over QUIC on loopback. The only thing that is not production code is the beacon node:
//! `FakeBn` runs Lighthouse's own transport, gossipsub parameters and RPC behaviour, so what the
//! sidecar talks to is the beacon node's wire behaviour and not a stub of it.
//!
//! ```no_run
//! # async fn example() {
//! # use harness::{Fleet, WAIT, topic};
//! let block = topic("beacon_block");
//! let mut fleet = Fleet::builder().regions(&[("eu", 3), ("us", 2)]).start().await;
//! for node in fleet.nodes() {
//!     node.subscribe(&block).await;
//! }
//! fleet.wait_full_mesh(WAIT).await;
//!
//! fleet.node(0).bn().publish(&block, b"a block").await;
//! fleet
//!     .wait_for("the block to reach node 1", WAIT, |fleet| {
//!         fleet.node(1).bn().count(&block, b"a block") == 1
//!     })
//!     .await;
//!
//! let scrape = fleet.node(1).metrics().await;
//! assert!(scrape.sum("overlay_first_seen_total", &[("source", "overlay")]) > 0.0);
//! assert!(fleet.node(1).ctl(r#"{"cmd":"status"}"#).await.contains(r#""ok":true"#));
//! # }
//! ```
//!
//! # Waiting
//!
//! Nothing here sleeps for longer than [`SETTLE`]. Every wait is [`Fleet::wait_for`] or
//! [`Fleet::wait_for_metrics`] polling a condition until it holds or the deadline passes, and a
//! wait that runs out says what it was waiting for. [`Fleet::wait_full_mesh`] is the one every
//! scenario starts with: it proves the connection count, the subscription exchange and both
//! gossipsub links by driving a probe message from every node to every peer it should have.
//!
//! # Scenarios
//!
//! The nine v1 scenarios and DX-N5's review scenarios live in `tests/fleet_v1.rs`. The seven
//! that need a feature this release does not ship are written by the ticket that ships it, in
//! this harness, with the hooks only they need:
//!
//! | # | Scenario | Written by |
//! |---|---|---|
//! | 10 | two origins with divergent live views publish once, at most 2(k+m) chunks received | T-074 |
//! | 11 | a chunk arriving before its `TOPIC_ADD` is counted, not crashed, and zero in steady state | T-073 |
//! | 12 | single-host and two-host regions use whole delivery and the direct small path | T-072, T-063 |
//! | 13 | an unsubscribed relay re-fans but does not publish | T-063 |
//! | 15 | a wedged beacon node on one host does not delay the second hop to its region | T-063, T-073 |
//! | 16 | one third of a region lost mid-slot completes via parity or repair before the deadline | T-074, T-082 |
//! | 18 | a rolling upgrade adding a feature bit keeps pairing and serves older peers by fallback | T-062 |

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use fleet_overlay::app::App;
use fleet_overlay::logging::{self, LogHandle};
use overlay_bn::testutil::{FakeBn, FakeBnEvent};
use overlay_core::config::{Config, Log, LogFormat, LogLevel};
use overlay_core::roster::Hostname;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Long enough for a fleet to pair and deliver on a loaded machine, short enough that a
/// scenario which will never pass fails instead of hanging.
pub const WAIT: Duration = Duration::from_secs(30);

/// How long to wait before believing nothing further is coming. The longest sleep anywhere in
/// the harness, which is what keeps the whole suite inside its minute.
pub const SETTLE: Duration = Duration::from_millis(50);

/// How often a wait re-reads the condition.
const POLL: Duration = Duration::from_millis(10);

/// The fork digest every topic in the harness carries. The sidecar never computes one, so any
/// eight hex characters will do as long as every node uses the same.
const FORK_DIGEST: &str = "6a95a1a9";

/// The topic every beacon node is subscribed to, on which [`Fleet::wait_full_mesh`] proves that
/// a message really crosses each pair. Small class, and no scenario asserts on it.
const PROBE_TOPIC: &str = "beacon_attestation_63";

/// The QUIC and metrics ports the harness hands out, below every platform's ephemeral range
/// rather than from `:0`: a restarted node has to bind the port it had, and `:0` lets the
/// operating system give that port to another test in the moment in between.
const PORT_RANGE: std::ops::Range<u32> = 20_000..30_000;

/// Where this test binary starts walking the range, so two binaries running side by side do not
/// collide on their first node.
static NEXT_PORT: LazyLock<AtomicU32> = LazyLock::new(|| {
    let spread = std::process::id() as u64 * 7919;
    AtomicU32::new((spread % PORT_RANGE.len() as u64) as u32)
});

/// Held across every node's [`App::build`]. The two values below are read from the process
/// environment, which one process cannot give two nodes at once, so only one node in the whole
/// binary may be inside `build` at a time.
static STARTING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// One subscriber for the whole binary. `logging::init` keeps the first one installed, so every
/// node's [`App`] shares this handle rather than fighting over the global dispatcher.
static LOG: LazyLock<Arc<LogHandle>> = LazyLock::new(|| {
    Arc::new(logging::init(&Log {
        level: LogLevel::Warn,
        format: LogFormat::Json,
    }))
});

/// A `/eth2/<digest>/<name>/ssz_snappy` topic string, which is the only shape the mirror parses.
pub fn topic(name: &str) -> String {
    format!("/eth2/{FORK_DIGEST}/{name}/ssz_snappy")
}

/// What every node in a fleet starts with, for the knobs a scenario varies.
#[derive(Clone, Debug)]
pub struct Settings {
    /// `inject`: whether the sidecars publish what they receive into their beacon nodes.
    pub inject: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self { inject: true }
    }
}

/// How a fleet is laid out before it starts.
#[derive(Default)]
pub struct Builder {
    regions: Vec<(String, usize)>,
    settings: Settings,
}

impl Builder {
    /// The region layout: one entry per region, with how many hosts it holds. Nodes are
    /// numbered in the order given, so `&[("eu", 3), ("us", 2)]` puts nodes 0 to 2 in `eu`.
    pub fn regions(mut self, regions: &[(&str, usize)]) -> Self {
        self.regions = regions
            .iter()
            .map(|(name, hosts)| ((*name).to_owned(), *hosts))
            .collect();
        self
    }

    /// Changes the configuration every node starts with.
    pub fn config(mut self, with: impl FnOnce(&mut Settings)) -> Self {
        with(&mut self.settings);
        self
    }

    /// Starts every node and returns once each one's admin socket answers.
    pub async fn start(self) -> Fleet {
        let dir = tempfile::tempdir().unwrap();
        let prefix = format!("f{}", FLEETS.fetch_add(1, Ordering::Relaxed));
        write_secret(&dir.path().join("seed"), &SEED);

        let mut nodes = Vec::new();
        for (region, hosts) in &self.regions {
            for _ in 0..*hosts {
                let index = nodes.len();
                nodes.push(Node::create(dir.path(), &prefix, index, region).await);
            }
        }
        let mut fleet = Fleet {
            dir,
            nodes,
            settings: self.settings,
            cut: Vec::new(),
        };
        for index in 0..fleet.nodes.len() {
            fleet.write_files(index);
        }
        for index in 0..fleet.nodes.len() {
            fleet.start_node(index).await;
        }
        fleet
    }
}

/// Distinguishes one fleet's hostnames from another's: the read-pacing hook and the captured
/// log are both process-wide.
static FLEETS: AtomicUsize = AtomicUsize::new(0);

/// A running fleet: every node's files, its fake beacon node and its sidecar.
pub struct Fleet {
    dir: tempfile::TempDir,
    nodes: Vec<Node>,
    settings: Settings,
    /// Pairs whose rosters no longer name each other, from [`Fleet::partition`].
    cut: Vec<(usize, usize)>,
}

impl Fleet {
    /// A fleet to be laid out and started.
    pub fn builder() -> Builder {
        Builder::default()
    }

    /// Every node, in the order the region layout named them.
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// One node.
    pub fn node(&self, index: usize) -> &Node {
        &self.nodes[index]
    }

    /// Polls `ready` until it holds, or panics after `timeout` saying what it waited for.
    pub async fn wait_for(
        &self,
        what: &str,
        timeout: Duration,
        mut ready: impl FnMut(&Self) -> bool,
    ) {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if ready(self) {
                return;
            }
            tokio::time::sleep(POLL).await;
        }
        panic!("waited {timeout:?} for {what}");
    }

    /// The same, over a fresh scrape of every node, indexed as [`Fleet::nodes`] is.
    pub async fn wait_for_metrics(
        &self,
        what: &str,
        timeout: Duration,
        mut ready: impl FnMut(&[Scrape]) -> bool,
    ) {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if ready(&self.metrics().await) {
                return;
            }
            tokio::time::sleep(POLL).await;
        }
        panic!("waited {timeout:?} for {what}");
    }

    /// A scrape of every node.
    pub async fn metrics(&self) -> Vec<Scrape> {
        let mut scrapes = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            scrapes.push(node.metrics().await);
        }
        scrapes
    }

    /// Long enough for a message that was going to arrive to have arrived, so a test can assert
    /// that nothing more did.
    pub async fn settle(&self) {
        tokio::time::sleep(SETTLE).await;
    }

    /// Returns once every node holds a connection to each peer its roster still names, and a
    /// probe message has crossed each of those pairs since this call began.
    ///
    /// The connection count alone is not enough to publish on: a peer becomes live at the end
    /// of HELLO and its subscription bitmap arrives on the control stream just after, so a
    /// message sent in between goes nowhere. Driving a probe across every pair is what proves
    /// the whole path, and it is counted at the receiver before the beacon node is involved, so
    /// it works with the kill switch off as well.
    pub async fn wait_full_mesh(&mut self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        let probe = topic(PROBE_TOPIC);
        for node in &self.nodes {
            node.subscribe(&probe).await;
        }
        self.wait_for(
            "every beacon node to mirror the probe topic",
            timeout,
            |f| f.nodes.iter().all(|node| node.bn().subscribed(&probe)),
        )
        .await;
        self.wait_for_peers("every node to see the peers its roster names", timeout)
            .await;

        let before = self.crossings().await;
        loop {
            for index in 0..self.nodes.len() {
                let payload = format!("probe {index} {:?}", Instant::now()).into_bytes();
                self.nodes[index].bn().try_publish(&probe, &payload).await;
            }
            let done = Instant::now() + SETTLE * 4;
            while Instant::now() < done {
                if self.crossed_every_pair(&before).await {
                    return;
                }
                tokio::time::sleep(POLL).await;
            }
            assert!(
                Instant::now() < deadline,
                "waited {timeout:?} for a full mesh"
            );
        }
    }

    /// How many messages each node has taken from each peer, as `messages_total{direction=in}`
    /// reports it.
    async fn crossings(&self) -> Vec<Vec<f64>> {
        let scrapes = self.metrics().await;
        (0..self.nodes.len())
            .map(|to| {
                (0..self.nodes.len())
                    .map(|from| {
                        scrapes[to].sum(
                            "overlay_messages_total",
                            &[("direction", "in"), ("peer", &self.nodes[from].hostname.0)],
                        )
                    })
                    .collect()
            })
            .collect()
    }

    async fn crossed_every_pair(&self, before: &[Vec<f64>]) -> bool {
        let now = self.crossings().await;
        (0..self.nodes.len()).all(|to| {
            self.expected_peers(to)
                .iter()
                .all(|&from| now[to][from] > before[to][from])
        })
    }

    /// The peers node `index` should hold: every other node its roster still names.
    fn expected_peers(&self, index: usize) -> Vec<usize> {
        (0..self.nodes.len())
            .filter(|&other| other != index && !self.is_cut(index, other))
            .collect()
    }

    fn is_cut(&self, a: usize, b: usize) -> bool {
        self.cut.contains(&(a, b)) || self.cut.contains(&(b, a))
    }

    /// Polls the admin sockets until every running node reports the peers its roster names.
    async fn wait_for_peers(&self, what: &str, timeout: Duration) {
        let expected: Vec<usize> = (0..self.nodes.len())
            .map(|index| self.expected_peers(index).len())
            .collect();
        let deadline = Instant::now() + timeout;
        loop {
            let counts = self.peer_counts().await;
            if counts == expected {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "waited {timeout:?} for {what}: {counts:?}, wanted {expected:?}"
            );
            tokio::time::sleep(POLL).await;
        }
    }

    /// How many live peers each node reports on its admin socket.
    async fn peer_counts(&self) -> Vec<usize> {
        let mut counts = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            counts.push(node.live_peers().await);
        }
        counts
    }

    /// Writes `roster.yaml` and `config.yaml` for one node.
    fn write_files(&self, index: usize) {
        let node = &self.nodes[index];
        let hosts: String = (0..self.nodes.len())
            .filter(|&other| other == index || !self.is_cut(index, other))
            .map(|other| {
                let peer = &self.nodes[other];
                format!(
                    "  - hostname: {}\n    region: {}\n    addr: \"{}\"\n",
                    peer.hostname, peer.region, peer.overlay
                )
            })
            .collect();
        std::fs::write(node.dir.join("roster.yaml"), format!("hosts:\n{hosts}")).unwrap();

        let path = |name: &str| node.dir.join(name).display().to_string();
        let yaml = format!(
            "overlay:\n  listen: \"{}\"\n  roster_file: {}\n  fleet_seed_file: {}\n\
             \x20 keepalive_ms: 500\n  idle_timeout_ms: 5000\n\
             bn:\n  node_key_file: {}\n  identity_url: \"{}\"\n  libp2p_addr: \"{}\"\n\
             \x20 listen_addr: \"/ip4/127.0.0.1/tcp/0\"\n\
             inject: {}\nadmin_socket: {}\nmetrics_listen: \"{}\"\n\
             log:\n  level: warn\n  format: json\n",
            node.overlay,
            path("roster.yaml"),
            self.dir.path().join("seed").display(),
            path("node.key"),
            node.bn_http,
            node.bn_addr,
            self.settings.inject,
            path("admin.sock"),
            node.metrics,
        );
        std::fs::write(node.dir.join("config.yaml"), yaml).unwrap();
    }

    /// Cuts every pair between the two sets by taking each side out of the other's roster and
    /// reloading, which closes the connection that pair holds and keeps it from being redialled.
    /// Nothing else changes: both halves keep their beacon nodes and their other peers.
    pub async fn partition(&mut self, a: &[usize], b: &[usize]) {
        for &left in a {
            for &right in b {
                self.cut.push((left, right));
            }
        }
        for index in 0..self.nodes.len() {
            self.write_files(index);
        }
        self.reload_all().await;
        self.wait_for_peers("the cut connections to close", WAIT)
            .await;
    }

    /// `fleet-overlayctl reload` on every running node, the way `systemctl reload` reaches a
    /// whole fleet.
    async fn reload_all(&self) {
        for node in &self.nodes {
            if node.app.is_some() {
                let answer = node.ctl(r#"{"cmd":"reload"}"#).await;
                assert!(answer.contains(r#""ok":true"#), "reload: {answer}");
            }
        }
    }

    /// Builds one node's sidecar and leaves it running.
    async fn start_node(&mut self, index: usize) {
        let _starting = STARTING.lock().await;
        let node = &self.nodes[index];
        // `App` reads this host's name and its runtime directory from the process environment,
        // which N sidecars in one process cannot each have. Both are read before `build` reaches
        // its first await, and [`STARTING`] keeps every other node in the binary out until this
        // one is built, so the values in force are always this node's.
        unsafe {
            std::env::set_var("FLEET_OVERLAY_HOSTNAME", &node.hostname.0);
            std::env::set_var("RUNTIME_DIRECTORY", &node.dir);
        }
        let config_path = node.dir.join("config.yaml");
        let cfg = Config::load(&config_path).unwrap();
        let app = App::build(config_path, cfg, LOG.clone())
            .await
            .unwrap_or_else(|err| panic!("node {index} did not start: {err}"));
        let (stop, mut stopped) = watch::channel(false);
        let task = tokio::spawn(app.run(async move {
            let _ = stopped.wait_for(|stop| *stop).await;
        }));
        self.nodes[index].app = Some(Running { stop, task });
    }
}

/// The sidecar task and the switch that ends it.
struct Running {
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

/// One host: its files, its fake beacon node and its sidecar.
pub struct Node {
    hostname: Hostname,
    region: String,
    dir: PathBuf,
    overlay: SocketAddr,
    metrics: SocketAddr,
    bn_http: String,
    bn_addr: String,
    bn: Option<Bn>,
    app: Option<Running>,
}

impl Node {
    async fn create(root: &Path, prefix: &str, index: usize, region: &str) -> Self {
        let dir = root.join(format!("n{index}"));
        std::fs::create_dir(&dir).unwrap();
        let fake = FakeBn::start().await;
        let (bn_http, bn_addr) = (fake.http_addr().to_string(), fake.addr().to_string());
        Self {
            hostname: Hostname(format!("{prefix}-bn-{index:02}")),
            region: region.to_owned(),
            dir,
            overlay: reserved(Transport::Udp),
            metrics: reserved(Transport::Tcp),
            bn_http,
            bn_addr,
            bn: Some(Bn::new(fake)),
            app: None,
        }
    }

    /// This host's name, its identity everywhere in the fleet.
    pub fn hostname(&self) -> &Hostname {
        &self.hostname
    }

    /// This node's beacon node.
    pub fn bn(&self) -> &Bn {
        self.bn
            .as_ref()
            .expect("this node's beacon node is running")
    }

    /// Subscribes the beacon node to `topic`, which the sidecar mirrors and advertises.
    pub async fn subscribe(&self, topic: &str) {
        self.bn().fake.subscribe(topic).await;
    }

    /// A `GET /metrics` against this node's scrape endpoint, parsed.
    pub async fn metrics(&self) -> Scrape {
        let mut stream = TcpStream::connect(self.metrics).await.unwrap();
        stream
            .write_all(b"GET /metrics HTTP/1.0\r\n\r\n")
            .await
            .unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).await.unwrap();
        Scrape::parse(&answer)
    }

    /// One request on the admin socket, as `fleet-overlayctl` sends it, and the line back.
    pub async fn ctl(&self, request: &str) -> String {
        let socket = self.dir.join("admin.sock");
        let stream = UnixStream::connect(&socket).await.unwrap();
        let mut stream = BufReader::new(stream);
        stream
            .get_mut()
            .write_all(format!("{request}\n").as_bytes())
            .await
            .unwrap();
        let mut answer = String::new();
        stream.read_line(&mut answer).await.unwrap();
        answer
    }

    /// How many live peers the admin socket reports, or none when the sidecar is stopped.
    pub async fn live_peers(&self) -> usize {
        if self.app.is_none() {
            return 0;
        }
        let answer = self.ctl(r#"{"cmd":"status"}"#).await;
        let status: serde_json::Value = serde_json::from_str(&answer).unwrap();
        status["status"]["peers"]
            .as_array()
            .unwrap_or_else(|| panic!("no peers in {answer}"))
            .len()
    }
}

/// What a beacon node received: the topic and the payload as its snappy transform left it.
type Message = (String, Vec<u8>);

/// A beacon node with everything it has seen kept for a test to read.
pub struct Bn {
    fake: FakeBn,
    received: Arc<Mutex<Vec<Message>>>,
    subscribed: Arc<Mutex<Vec<String>>>,
    drains: Vec<JoinHandle<()>>,
}

impl Bn {
    fn new(mut fake: FakeBn) -> Self {
        let (received, subscribed) = (Arc::default(), Arc::<Mutex<Vec<String>>>::default());
        let mut messages = fake.received();
        let sink: Arc<Mutex<Vec<Message>>> = Arc::clone(&received);
        let reading = tokio::spawn(async move {
            while let Some((topic, payload, _)) = messages.recv().await {
                sink.lock().unwrap().push((topic, payload));
            }
        });
        let mut events = fake.events();
        let topics = Arc::clone(&subscribed);
        let watching = tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                if let FakeBnEvent::Subscribed { topic, .. } = event {
                    topics.lock().unwrap().push(topic);
                }
            }
        });
        Self {
            fake,
            received,
            subscribed,
            drains: vec![reading, watching],
        }
    }

    /// Publishes `payload` on `topic` the way a validated message reaches an explicit peer.
    /// The payload is the uncompressed bytes; snappy happens on the wire, as it does for a real
    /// beacon node.
    pub async fn publish(&self, topic: &str, payload: &[u8]) {
        self.fake
            .publish(topic, payload)
            .await
            .unwrap_or_else(|err| panic!("{topic}: {err}"));
    }

    /// The same, for a probe that is allowed to find no subscriber yet.
    async fn try_publish(&self, topic: &str, payload: &[u8]) {
        let _ = self.fake.publish(topic, payload).await;
    }

    /// Everything this beacon node has received, in order.
    pub fn received(&self) -> Vec<Message> {
        self.received.lock().unwrap().clone()
    }

    /// How many times it received exactly this payload on this topic.
    pub fn count(&self, topic: &str, payload: &[u8]) -> usize {
        self.received()
            .iter()
            .filter(|(seen, bytes)| seen == topic && bytes == payload)
            .count()
    }

    /// Whether the sidecar has subscribed to `topic` on this beacon node, which is what the
    /// mirror does once the beacon node announces it.
    pub fn subscribed(&self, topic: &str) -> bool {
        self.subscribed.lock().unwrap().iter().any(|t| t == topic)
    }
}

/// One `GET /metrics` answer, parsed into the series it carries.
pub struct Scrape(Vec<(String, BTreeMap<String, String>, f64)>);

impl Scrape {
    fn parse(answer: &str) -> Self {
        let body = answer
            .split_once("\r\n\r\n")
            .map_or(answer, |(_, rest)| rest);
        Self(
            body.lines()
                .filter(|line| !line.starts_with('#') && !line.is_empty())
                .filter_map(series)
                .collect(),
        )
    }

    /// The sum of every series whose name matches and which carries all of `labels`. A metric
    /// nothing has touched is zero, which is how Prometheus reads an absent series too.
    pub fn sum(&self, name: &str, labels: &[(&str, &str)]) -> f64 {
        self.0
            .iter()
            .filter(|(series, at, _)| {
                series == name
                    && labels
                        .iter()
                        .all(|(key, value)| at.get(*key).map(String::as_str) == Some(*value))
            })
            .map(|(_, _, value)| value)
            .sum()
    }

    /// Whether any series of this name carries all of `labels`.
    pub fn has(&self, name: &str, labels: &[(&str, &str)]) -> bool {
        self.0.iter().any(|(series, at, _)| {
            series == name
                && labels
                    .iter()
                    .all(|(key, value)| at.get(*key).map(String::as_str) == Some(*value))
        })
    }
}

/// One exposition line: `name{label="value",..} number`.
fn series(line: &str) -> Option<(String, BTreeMap<String, String>, f64)> {
    let (head, value) = line.rsplit_once(' ')?;
    let value = value.parse().ok()?;
    let Some((name, rest)) = head.split_once('{') else {
        return Some((head.to_owned(), BTreeMap::new(), value));
    };
    let labels = rest
        .trim_end_matches('}')
        .split("\",")
        .filter_map(|pair| pair.split_once("=\""))
        .map(|(key, value)| (key.trim().to_owned(), value.trim_matches('"').to_owned()))
        .collect();
    Some((name.to_owned(), labels, value))
}

/// Which kind of socket a reserved port has to be free for.
enum Transport {
    Udp,
    Tcp,
}

/// A loopback address in [`PORT_RANGE`] that nothing holds right now.
fn reserved(transport: Transport) -> SocketAddr {
    for _ in 0..PORT_RANGE.len() {
        let offset = NEXT_PORT.fetch_add(1, Ordering::Relaxed) % PORT_RANGE.len() as u32;
        let port = (PORT_RANGE.start + offset) as u16;
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let free = match transport {
            Transport::Udp => UdpSocket::bind(addr).is_ok(),
            Transport::Tcp => TcpListener::bind(addr).is_ok(),
        };
        if free {
            return addr;
        }
    }
    panic!("no free port in {PORT_RANGE:?}")
}

/// The fleet seed every node starts on. Any 32 bytes will do, and a fixed one keeps a failing
/// run reproducible.
const SEED: [u8; 32] = [0x11; 32];

/// Writes a secret the way `gen-seed` leaves one: 64 hex characters at mode 0600, so no node
/// warns about the permissions of its own fixture.
fn write_secret(path: &Path, bytes: &[u8; 32]) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::write(path, hex(bytes)).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// A 32-byte secret as the seed and node-key files hold it.
fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        text.push_str(&format!("{byte:02x}"));
        text
    }) + "\n"
}
