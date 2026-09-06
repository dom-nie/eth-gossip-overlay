//! Test fixtures for the BN link.
//!
//! [`FakeBn`] is a beacon node as far as the sidecar can tell: Lighthouse's own transport and
//! snappy transform under its gossipsub parameters, listening on loopback, next to a mock of
//! the four HTTP endpoints the link reads. A test points a real link at it:
//!
//! ```ignore
//! let mut bn = FakeBn::start().await;
//! let cfg = LinkConfig { libp2p_addr: bn.addr(), ..with a 10 ms backoff };
//! let client = BnClient::new(bn.http_addr(), Duration::from_secs(2));
//! let mut link = BnLink::spawn(
//!     cfg, &node_key, client, &mut registry, lanes.pusher(), spec_tx, sets_rx, commands_rx,
//! );
//! // BnEvent::Connected { peer_id: bn.peer_id() } arrives on `link.events`.
//! bn.subscribe(TOPIC).await;
//! // BnEvent::Subscribed { .. } arrives; a publish from the link now reaches the fake:
//! let (topic, decompressed, id) = bn.received().recv().await.unwrap();
//! // The other way round: subscribe the link, bn.wait_for(Subscribed), then bn.publish(..).
//! ```
//!
//! Beside its gossipsub the fake runs Lighthouse's real `RPC` behaviour, so a test drives the
//! sidecar's req/resp side with the beacon node's own codec, framing and handler:
//!
//! ```ignore
//! let mut responses = bn.responses();
//! bn.send_status(status).await;               // also send_ping, request_metadata,
//! bn.request_blocks_by_range(0, 4).await;     // request_blocks_by_range, send_goodbye
//! match responses.recv().await.unwrap() {
//!     RpcAnswer::Status(status) => ..,        // Pong(seq), MetaData(..)
//!     RpcAnswer::Error(text) => ..,           // an error chunk, its result code named in it
//!     _ => ..,
//! }
//! // Nothing the sidecar sends of its own accord; sidecar_never_initiates_a_request
//! // asserts this stays empty.
//! assert!(bn.inbound_requests().try_recv().is_err());
//! ```
//!
//! Both sides' RPC handlers hold a connection open, so the fake runs Lighthouse's own 10 s
//! idle timeout ([`IDLE_TIMEOUT`]) and a link with no traffic on it stays up.
//!
//! The two-swarm helpers at the bottom ([`connected_pair`], [`subscribe_both`],
//! [`next_message`]) join two of the sidecar's own behaviours over the memory transport, for
//! tests that need the protocol code and no beacon node at all.

use std::collections::HashSet;
use std::io::Write;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use libp2p::core::transport::MemoryTransport;
use libp2p::core::upgrade::Version;
use libp2p::futures::StreamExt;
use libp2p::gossipsub::{
    self, AllowAllSubscriptionFilter, IdentTopic, Message, MessageAcceptance, MessageAuthenticity,
    MessageId, MetricsConfig, PublishError, TopicHash, ValidationMode,
};
use libp2p::swarm::{NetworkBehaviour, Swarm, SwarmEvent};
use libp2p::{Multiaddr, PeerId, SwarmBuilder, Transport, noise, yamux};
use lighthouse_network::rpc::methods::{
    MetaData, MetadataRequest, OldBlocksByRangeRequest, Ping as RpcPing, RpcSuccessResponse,
};
use lighthouse_network::rpc::{
    GoodbyeReason, Protocol, RPC, RPCMessage, RPCReceived, RequestType, StatusMessage,
};
use lighthouse_network::types::SnappyTransform;
use prometheus_client::registry::Registry;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use types::{ChainSpec, ForkContext, Hash256, MainnetEthSpec, Slot};
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::gossip::{BnLinkConfig, GossipBehaviour};
use crate::link::LinkConfig;
use crate::node_key::NodeKey;

/// Long enough for a noise handshake plus a few gossipsub round trips on a loaded CI box.
const WAIT: Duration = Duration::from_secs(5);

/// Everything `tracing` writes in this test binary. One process-wide subscriber rather
/// than one per test: with a single dispatcher registered, tracing-core caches a call
/// site's interest by asking the dispatcher of whichever thread hits it first, and a
/// parallel test with no subscriber on its thread would cache "never" for the call site
/// a test with a thread-local subscriber is waiting on. A test looks for a string only
/// it logs.
pub static LOG: LazyLock<Log> = LazyLock::new(|| {
    let log = Log::default();
    let sink = log.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || sink.clone())
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("the only global subscriber in this test binary");
    log
});

/// The captured log, shared by every test in the binary.
#[derive(Clone, Default)]
pub struct Log(Arc<Mutex<Vec<u8>>>);

impl Log {
    /// Everything logged so far.
    pub fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl Write for Log {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A beacon node's network side: Lighthouse's real transport
/// (`lighthouse_network::build_transport`) and `SnappyTransform` under the gossipsub
/// parameters copied from its private `gossipsub_config`, in a task of its own, plus a mock of
/// the HTTP endpoints the link reads. Every peer that connects is made an explicit peer, the
/// way `--trusted-peers` does it on the real node, and every message received is reported
/// `Accept` so gossipsub behaves as the beacon node's does.
pub struct FakeBn {
    task: JoinHandle<()>,
    peer_id: PeerId,
    port: u16,
    http: MockServer,
    commands: mpsc::Sender<Cmd>,
    received: Option<mpsc::Receiver<Received>>,
    events: mpsc::Receiver<FakeBnEvent>,
    answers: Option<mpsc::Receiver<RpcAnswer>>,
    inbound: Option<mpsc::Receiver<Protocol>>,
    responses: Responses,
    /// The fork's gossipsub metrics under `gossipsub_`, as Lighthouse registers them; only
    /// a fake from [`start_with_metrics`](Self::start_with_metrics) has one.
    metrics: Option<Registry>,
}

/// What the mock answers on the three endpoints the connect probe reads. The identity
/// endpoint always serves the fake's own peer id.
struct Responses {
    version: ResponseTemplate,
    spec: ResponseTemplate,
    peers: ResponseTemplate,
}

impl Default for Responses {
    fn default() -> Self {
        Self {
            version: ok_json(
                json!({"data": {"version": "Lighthouse/v8.2.2-e423a66/x86_64-linux"}}),
            ),
            spec: ok_json(json!({"data": {
                "DATA_COLUMN_SIDECAR_SUBNET_COUNT": "128",
                "NUMBER_OF_COLUMNS": "128",
                "NUMBER_OF_CUSTODY_GROUPS": "128",
                "MAX_PAYLOAD_SIZE": "10485760",
                "SECONDS_PER_SLOT": "12",
                "SLOTS_PER_EPOCH": "32"
            }})),
            peers: ok_json(json!([])),
        }
    }
}

/// A 200 with `body` as JSON, the shape every beacon API answer has.
pub fn ok_json(body: serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(body)
}

/// A link config pointed at `bn`, with a backoff fast enough for a test to see a reconnect and
/// an ephemeral listen port, so tests run in parallel without agreeing on one.
pub fn link_config(bn: &FakeBn) -> LinkConfig {
    LinkConfig {
        libp2p_addr: bn.addr(),
        listen_addr: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        backoff_min: Duration::from_millis(10),
        backoff_max: Duration::from_millis(100),
        gossip: BnLinkConfig {
            idontwant_on_publish: true,
        },
    }
}

/// A fresh node key in `dir`. The file is read at spawn and not needed after.
pub fn node_key(dir: &tempfile::TempDir) -> NodeKey {
    NodeKey::load_or_create(&dir.path().join("node.key")).unwrap()
}

/// A message the fake received: the topic, the payload as its snappy transform decompressed
/// it, and the id its copy of Lighthouse's id function gave it.
pub type Received = (String, Vec<u8>, MessageId);

/// What the fake's swarm saw, for tests that watch the beacon node's side.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FakeBnEvent {
    /// A peer connected and was made explicit.
    Connected(PeerId),
    /// The last connection to a peer closed.
    Disconnected(PeerId),
    /// A peer subscribed to `topic`; a publish on it from the fake reaches that peer now.
    Subscribed {
        /// The peer.
        peer: PeerId,
        /// The full topic string.
        topic: String,
    },
}

type LighthouseGossip = gossipsub::Behaviour<SnappyTransform, AllowAllSubscriptionFilter>;

/// The beacon node's two behaviours: gossipsub as `service/mod.rs` builds it, and the real
/// `RPC`, whose handler is what keeps a quiet connection alive past [`IDLE_TIMEOUT`].
#[derive(NetworkBehaviour)]
struct FakeBnBehaviour {
    gossip: LighthouseGossip,
    rpc: RPC<u64, MainnetEthSpec>,
}

/// What the fake got back for a request it sent.
#[derive(Clone, Debug, PartialEq)]
pub enum RpcAnswer {
    /// The peer's Status, at the version Lighthouse negotiated.
    Status(StatusMessage),
    /// The metadata sequence number a Ping was answered with.
    Pong(u64),
    /// The peer's metadata.
    MetaData(Arc<MetaData<MainnetEthSpec>>),
    /// An error chunk or a handler failure, as text. Lighthouse keeps its handler error type
    /// crate-private, so text is the only shape available; the result code is in it by name
    /// (`ErrorResponse(ResourceUnavailable, ..)`), along with the protocol it was sent on.
    Error(String),
}

enum Cmd {
    Subscribe(String),
    Publish {
        topic: String,
        data: Vec<u8>,
        reply: oneshot::Sender<Result<MessageId, PublishError>>,
    },
    /// The next connection from this peer is an ordinary one, not an explicit peer.
    Public(PeerId),
    MeshPeers {
        topic: String,
        reply: oneshot::Sender<Vec<PeerId>>,
    },
    /// Send this request to the connected peer; the answer lands on `answers`.
    Request(Box<RequestType<MainnetEthSpec>>),
    /// Say goodbye and close the connection, the way Lighthouse's peer manager does.
    Goodbye(GoodbyeReason),
    /// Dial this address, the way the beacon node dials a peer it was handed as an ENR or in
    /// `--libp2p-addresses`.
    Dial(Multiaddr),
}

/// Where a swarm task puts what it sees.
struct Sinks {
    received: mpsc::Sender<Received>,
    events: mpsc::Sender<FakeBnEvent>,
    answers: mpsc::Sender<RpcAnswer>,
    inbound: mpsc::Sender<Protocol>,
}

/// A peer of the fake that is not trusted: an ordinary gossipsub node the fake grafts into its
/// mesh, standing in for the public network. Built by [`FakeBn::attach_public_peer`].
pub struct PublicPeer {
    peer_id: PeerId,
    commands: mpsc::Sender<Cmd>,
    events: mpsc::Receiver<FakeBnEvent>,
    _task: JoinHandle<()>,
}

impl PublicPeer {
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Publishes `payload` on `topic`, uncompressed here and snappy on the wire, the way a
    /// public Lighthouse would.
    pub async fn publish(&self, topic: &str, payload: &[u8]) -> MessageId {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Cmd::Publish {
                topic: topic.to_owned(),
                data: payload.to_vec(),
                reply,
            })
            .await
            .unwrap();
        answer.await.unwrap().unwrap()
    }

    async fn wait_for(&mut self, wanted: impl FnMut(&FakeBnEvent) -> bool) -> FakeBnEvent {
        wait_for(&mut self.events, wanted).await
    }
}

impl FakeBn {
    /// A fake on a fresh loopback port with a fresh key, next to a fresh mock server.
    pub async fn start() -> Self {
        Self::start_on(0, MockServer::start().await).await
    }

    /// A fake whose gossipsub metrics can be read with [`metrics_text`](Self::metrics_text).
    pub async fn start_with_metrics() -> Self {
        Self::build(0, MockServer::start().await, Some(Registry::default())).await
    }

    /// A fake with a fresh key on `port` (0 for any), served by `http`, whose identity
    /// endpoint is repointed at the new key. This is how a test restarts the beacon node
    /// behind the HTTP endpoint a link was configured with.
    pub async fn start_on(port: u16, http: MockServer) -> Self {
        Self::build(port, http, None).await
    }

    async fn build(port: u16, http: MockServer, mut metrics: Option<Registry>) -> Self {
        let mut swarm = lighthouse_swarm(metrics.as_mut());
        swarm
            .listen_on(format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap())
            .unwrap();
        let port = tokio::time::timeout(WAIT, async {
            loop {
                if let SwarmEvent::NewListenAddr { address, .. } = swarm.select_next_some().await {
                    break tcp_port(&address);
                }
            }
        })
        .await
        .expect("the fake beacon node never reported its listen address");
        let peer_id = *swarm.local_peer_id();
        let (commands, command_rx) = mpsc::channel(64);
        let (received_tx, received) = mpsc::channel(8192);
        let (events_tx, events) = mpsc::channel(64);
        let (answers_tx, answers) = mpsc::channel(64);
        let (inbound_tx, inbound) = mpsc::channel(64);
        let task = tokio::spawn(drive(
            swarm,
            command_rx,
            Sinks {
                received: received_tx,
                events: events_tx,
                answers: answers_tx,
                inbound: inbound_tx,
            },
        ));
        let bn = Self {
            task,
            peer_id,
            port,
            http,
            commands,
            received: Some(received),
            events,
            answers: Some(answers),
            inbound: Some(inbound),
            responses: Responses::default(),
            metrics,
        };
        bn.remount().await;
        bn
    }

    /// The fake's gossipsub metrics in Prometheus text form.
    pub fn metrics_text(&self) -> String {
        let registry = self
            .metrics
            .as_ref()
            .expect("a fake from start_with_metrics");
        let mut text = String::new();
        prometheus_client::encoding::text::encode(&mut text, registry).unwrap();
        text
    }

    /// How many IDONTWANT control messages the fake has received.
    pub fn idontwant_msgs(&self) -> u64 {
        self.metrics_text()
            .lines()
            .find_map(|line| line.strip_prefix("gossipsub_idontwant_msgs_total "))
            .map(|count| count.trim().parse().unwrap())
            .unwrap_or(0)
    }

    /// The identity the mock serves and the swarm runs under.
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// The loopback port the swarm listens on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// What `bn.libp2p_addr` would say: the listen address without a peer id.
    pub fn addr(&self) -> Multiaddr {
        format!("/ip4/127.0.0.1/tcp/{}", self.port).parse().unwrap()
    }

    /// What `bn.identity_url` would say.
    pub fn http_addr(&self) -> Url {
        Url::parse(&format!("{}/eth/v1/node/identity", self.http.uri())).unwrap()
    }

    /// The mock server, for counting what the link asked it.
    pub fn http(&self) -> &MockServer {
        &self.http
    }

    /// Subscribes the fake to `topic`; the link sees `BnEvent::Subscribed` once it has.
    pub async fn subscribe(&self, topic: &str) {
        self.commands
            .send(Cmd::Subscribe(topic.to_owned()))
            .await
            .unwrap();
    }

    /// Publishes `payload` on `topic` the way the beacon node would: uncompressed here, snappy
    /// on the wire. Gossipsub refuses it until a subscriber for the topic is connected, so
    /// wait for [`FakeBnEvent::Subscribed`] first.
    pub async fn publish(&self, topic: &str, payload: &[u8]) -> Result<MessageId, PublishError> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Cmd::Publish {
                topic: topic.to_owned(),
                data: payload.to_vec(),
                reply,
            })
            .await
            .unwrap();
        answer.await.unwrap()
    }

    /// Everything the fake receives, in order. Taken once per fake.
    pub fn received(&mut self) -> mpsc::Receiver<Received> {
        self.received.take().expect("received() is taken once")
    }

    /// The answers to the requests the fake sends, in order. Taken once per fake.
    pub fn responses(&mut self) -> mpsc::Receiver<RpcAnswer> {
        self.answers.take().expect("responses() is taken once")
    }

    /// Every request the peer sends the fake, by protocol. The sidecar sends none. Taken once
    /// per fake.
    pub fn inbound_requests(&mut self) -> mpsc::Receiver<Protocol> {
        self.inbound
            .take()
            .expect("inbound_requests() is taken once")
    }

    /// Sends a Status the way the peer manager does on every new peer.
    pub async fn send_status(&self, status: StatusMessage) {
        self.request(RequestType::Status(status)).await;
    }

    /// Sends a Ping carrying the fake's own metadata sequence number.
    pub async fn send_ping(&self, seq_number: u64) {
        self.request(RequestType::Ping(RpcPing { data: seq_number }))
            .await;
    }

    /// Asks for the peer's metadata. Lighthouse's outbound upgrade offers v3, v2 and v1 in
    /// that order and multistream-select takes the first the peer supports, so a peer that
    /// registers all three always answers v3.
    pub async fn request_metadata(&self) {
        self.request(RequestType::MetaData(MetadataRequest::new_v3()))
            .await;
    }

    /// Asks for `count` blocks from `start_slot`, a protocol the sidecar registers and
    /// refuses.
    pub async fn request_blocks_by_range(&self, start_slot: u64, count: u64) {
        self.request(RequestType::BlocksByRange(OldBlocksByRangeRequest::new(
            start_slot, count, 1,
        )))
        .await;
    }

    /// Says goodbye and closes the connection, as `RPC::shutdown` does on the real node.
    pub async fn send_goodbye(&self, reason: GoodbyeReason) {
        self.commands.send(Cmd::Goodbye(reason)).await.unwrap();
    }

    /// Sends a goodbye as an ordinary request instead of through `RPC::shutdown`. Lighthouse's
    /// handler stays active and keeps the connection, so whatever closes it afterwards is the
    /// peer acting on the reason it read. `send_goodbye` is what a real peer manager does.
    pub async fn send_goodbye_request(&self, reason: GoodbyeReason) {
        self.request(RequestType::Goodbye(reason)).await;
    }

    async fn request(&self, request: RequestType<MainnetEthSpec>) {
        self.commands
            .send(Cmd::Request(Box::new(request)))
            .await
            .unwrap();
    }

    /// Dials `addr`, the way the beacon node dials a sidecar it was given as an ENR or in
    /// `--libp2p-addresses`. The connection it opens is inbound at the sidecar.
    pub async fn dial(&self, addr: Multiaddr) {
        self.commands.send(Cmd::Dial(addr)).await.unwrap();
    }

    /// Skips the fake's events until one satisfies `wanted`.
    pub async fn wait_for(&mut self, wanted: impl FnMut(&FakeBnEvent) -> bool) -> FakeBnEvent {
        wait_for(&mut self.events, wanted).await
    }

    /// The peers in the fake's mesh for `topic` right now.
    pub async fn mesh_peers(&self, topic: &str) -> Vec<PeerId> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(Cmd::MeshPeers {
                topic: topic.to_owned(),
                reply,
            })
            .await
            .unwrap();
        answer.await.unwrap()
    }

    /// Connects an ordinary peer to the fake, subscribed to `topic`, and returns once each
    /// side has seen the other's subscription, so the fake's next heartbeat grafts it and a
    /// publish from it reaches the fake. The fake must already be subscribed to `topic`.
    pub async fn attach_public_peer(&mut self, topic: &str) -> PublicPeer {
        let mut swarm = lighthouse_swarm(None);
        let peer_id = *swarm.local_peer_id();
        self.commands.send(Cmd::Public(peer_id)).await.unwrap();
        swarm
            .behaviour_mut()
            .gossip
            .subscribe(&IdentTopic::new(topic))
            .unwrap();
        swarm
            .dial(self.addr().with_p2p(self.peer_id).unwrap())
            .unwrap();
        let (commands, command_rx) = mpsc::channel(64);
        let (received_tx, _received) = mpsc::channel(64);
        let (events_tx, events) = mpsc::channel(64);
        let (answers_tx, _answers) = mpsc::channel(1);
        let (inbound_tx, _inbound) = mpsc::channel(1);
        let mut public = PublicPeer {
            peer_id,
            commands,
            events,
            _task: tokio::spawn(drive(
                swarm,
                command_rx,
                Sinks {
                    received: received_tx,
                    events: events_tx,
                    answers: answers_tx,
                    inbound: inbound_tx,
                },
            )),
        };
        self.wait_for(|e| {
            matches!(e, FakeBnEvent::Subscribed { peer, topic: t } if *peer == peer_id && t == topic)
        })
        .await;
        let bn = self.peer_id;
        public
            .wait_for(|e| {
                matches!(e, FakeBnEvent::Subscribed { peer, topic: t } if *peer == bn && t == topic)
            })
            .await;
        public
    }

    /// Drops the swarm, which closes its connections and frees the port, and hands back the
    /// mock server so a replacement can be started behind the same HTTP endpoint.
    pub async fn shutdown(self) -> MockServer {
        self.task.abort();
        let _ = self.task.await;
        self.http
    }

    /// Replaces what `/eth/v1/node/version` answers.
    pub async fn set_version_response(&mut self, response: ResponseTemplate) {
        self.responses.version = response;
        self.remount().await;
    }

    /// Replaces what `/eth/v1/config/spec` answers.
    pub async fn set_spec_response(&mut self, response: ResponseTemplate) {
        self.responses.spec = response;
        self.remount().await;
    }

    /// Replaces what `/lighthouse/peers` answers.
    pub async fn set_peers_response(&mut self, response: ResponseTemplate) {
        self.responses.peers = response;
        self.remount().await;
    }

    async fn remount(&self) {
        self.http.reset().await;
        let identity = ok_json(json!({"data": {"peer_id": self.peer_id.to_string()}}));
        for (at, response) in [
            ("/eth/v1/node/identity", identity),
            ("/eth/v1/node/version", self.responses.version.clone()),
            ("/eth/v1/config/spec", self.responses.spec.clone()),
            ("/lighthouse/peers", self.responses.peers.clone()),
        ] {
            Mock::given(method("GET"))
                .and(path(at))
                .respond_with(response)
                .mount(&self.http)
                .await;
        }
    }
}

/// Skips `events` until one satisfies `wanted`.
async fn wait_for(
    events: &mut mpsc::Receiver<FakeBnEvent>,
    mut wanted: impl FnMut(&FakeBnEvent) -> bool,
) -> FakeBnEvent {
    tokio::time::timeout(WAIT, async {
        loop {
            let event = events.recv().await.expect("the swarm task ended");
            if wanted(&event) {
                return event;
            }
        }
    })
    .await
    .expect("the awaited swarm event never happened")
}

fn tcp_port(addr: &Multiaddr) -> u16 {
    addr.iter()
        .find_map(|p| match p {
            libp2p::multiaddr::Protocol::Tcp(port) => Some(port),
            _ => None,
        })
        .expect("a TCP listen address")
}

/// Polls the fake's swarm until its task is aborted. What it receives is passed on with
/// `try_send`, so a test that never reads loses messages rather than stalling the fake.
/// Every peer that connects becomes an explicit peer, the way `--trusted-peers` does it on
/// the real node, except the ones a `Cmd::Public` named.
async fn drive(mut swarm: Swarm<FakeBnBehaviour>, mut commands: mpsc::Receiver<Cmd>, sinks: Sinks) {
    let mut public = HashSet::new();
    // Who requests go to: the sidecar, the only non-public peer a test connects to the fake.
    let mut peer = None;
    let mut next_request = 0;
    loop {
        tokio::select! {
            event = swarm.select_next_some() => match event {
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    if !public.contains(&peer_id) {
                        swarm.behaviour_mut().gossip.add_explicit_peer(&peer_id);
                        peer = Some(peer_id);
                    }
                    let _ = sinks.events.try_send(FakeBnEvent::Connected(peer_id));
                }
                SwarmEvent::ConnectionClosed { peer_id, num_established: 0, .. } => {
                    let _ = sinks.events.try_send(FakeBnEvent::Disconnected(peer_id));
                }
                SwarmEvent::Behaviour(FakeBnBehaviourEvent::Gossip(
                    gossipsub::Event::Subscribed { peer_id, topic, .. },
                )) => {
                    let _ = sinks.events.try_send(FakeBnEvent::Subscribed {
                        peer: peer_id,
                        topic: topic.into_string(),
                    });
                }
                SwarmEvent::Behaviour(FakeBnBehaviourEvent::Gossip(gossipsub::Event::Message {
                    propagation_source,
                    message_id,
                    message,
                })) => {
                    swarm.behaviour_mut().gossip.report_message_validation_result(
                        &message_id,
                        &propagation_source,
                        MessageAcceptance::Accept,
                    );
                    let _ = sinks.received.try_send((
                        message.topic.into_string(),
                        message.data,
                        message_id,
                    ));
                }
                SwarmEvent::Behaviour(FakeBnBehaviourEvent::Rpc(RPCMessage { message, .. })) => {
                    match message {
                        Ok(RPCReceived::Request(_, request)) => {
                            let protocol = request.versioned_protocol().protocol();
                            let _ = sinks.inbound.try_send(protocol);
                        }
                        Ok(RPCReceived::Response(_, response)) => {
                            let _ = sinks.answers.try_send(answer(response));
                        }
                        Ok(RPCReceived::EndOfStream(..)) => {}
                        Err(err) => {
                            let _ = sinks.answers.try_send(RpcAnswer::Error(format!("{err:?}")));
                        }
                    }
                }
                _ => {}
            },
            command = commands.recv() => match command {
                Some(Cmd::Subscribe(topic)) => {
                    let gossip = &mut swarm.behaviour_mut().gossip;
                    gossip.subscribe(&IdentTopic::new(topic)).unwrap();
                }
                Some(Cmd::Publish { topic, data, reply }) => {
                    let gossip = &mut swarm.behaviour_mut().gossip;
                    let _ = reply.send(gossip.publish(IdentTopic::new(topic), data));
                }
                Some(Cmd::Public(peer_id)) => {
                    public.insert(peer_id);
                }
                Some(Cmd::MeshPeers { topic, reply }) => {
                    let hash = TopicHash::from_raw(topic);
                    let mesh = swarm.behaviour().gossip.mesh_peers(&hash).copied().collect();
                    let _ = reply.send(mesh);
                }
                Some(Cmd::Request(request)) => {
                    next_request += 1;
                    if let Some(peer) = peer {
                        let rpc = &mut swarm.behaviour_mut().rpc;
                        rpc.send_request(peer, next_request, *request);
                    }
                }
                Some(Cmd::Dial(addr)) => {
                    swarm.dial(addr).unwrap();
                }
                Some(Cmd::Goodbye(reason)) => {
                    next_request += 1;
                    if let Some(peer) = peer {
                        swarm.behaviour_mut().rpc.shutdown(peer, next_request, reason);
                    }
                }
                None => return,
            },
        }
    }
}

/// The three responses the sidecar ever sends; anything else is kept as text.
fn answer(response: RpcSuccessResponse<MainnetEthSpec>) -> RpcAnswer {
    match response {
        RpcSuccessResponse::Status(status) => RpcAnswer::Status(status),
        RpcSuccessResponse::Pong(ping) => RpcAnswer::Pong(ping.data),
        RpcSuccessResponse::MetaData(metadata) => RpcAnswer::MetaData(metadata),
        other => RpcAnswer::Error(format!("{other:?}")),
    }
}

/// Lighthouse's own idle connection timeout (`service/mod.rs:498`). What holds a quiet link
/// open past it is the RPC handler's keep-alive (`rpc/handler.rs`, `connection_keep_alive` is
/// true unless the handler is deactivated); gossipsub's keeps alive only mesh peers, and an
/// explicit peer is never grafted.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// Lighthouse's swarm as `service/mod.rs` builds it for a node without QUIC or mplex: its
/// `build_transport` (TCP nodelay, noise, yamux, 10 s for the dial and upgrade), its
/// [`IDLE_TIMEOUT`], and both behaviours it runs on the wire the sidecar sees.
fn lighthouse_swarm(metrics: Option<&mut Registry>) -> Swarm<FakeBnBehaviour> {
    SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_other_transport(|keypair| {
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(lighthouse_network::build_transport(
                keypair.clone(),
                false,
                false,
            )?)
        })
        .unwrap()
        .with_behaviour(|_| FakeBnBehaviour {
            gossip: lighthouse_behaviour(metrics),
            rpc: RPC::new(fork_context(), false, None, None, 0),
        })
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(IDLE_TIMEOUT))
        .build()
}

/// Mainnet at slot 0. The sidecar never reads a fork digest of its own, so the current fork
/// only decides which protocols the fake offers on its own inbound side.
fn fork_context() -> Arc<ForkContext> {
    Arc::new(ForkContext::new::<MainnetEthSpec>(
        Slot::new(0),
        Hash256::ZERO,
        &ChainSpec::mainnet(),
    ))
}

/// The behaviour as `service/mod.rs:341-350` constructs it, minus the whitelist filter (every
/// topic a test uses is one the beacon node would allow) and the peer scoring (trusted peers
/// are exempt from it anyway). `metrics` attaches the fork's metrics under `gossipsub_`, the
/// prefix the beacon node uses.
fn lighthouse_behaviour(metrics: Option<&mut Registry>) -> LighthouseGossip {
    let spec = ChainSpec::mainnet();
    let behaviour = gossipsub::Behaviour::new_with_subscription_filter_and_transform(
        MessageAuthenticity::Anonymous,
        lighthouse_gossipsub_config(&spec),
        AllowAllSubscriptionFilter::default(),
        SnappyTransform::new(spec.max_payload_size as usize, spec.max_compressed_len()),
    )
    .unwrap();
    match metrics {
        Some(registry) => behaviour.with_metrics(
            registry.sub_registry_with_prefix("gossipsub"),
            MetricsConfig::default(),
        ),
        None => behaviour,
    }
}

/// `gossipsub_config` from `beacon_node/lighthouse_network/src/config.rs:450-523` at v8.2.2,
/// which is private, at the default load profile 3 (`NetworkLoad`, `config.rs:395-440`) on
/// mainnet: two epochs of duplicate cache, the 1 s heartbeat and the mesh, gossip and RPC
/// limits the beacon node runs with.
fn lighthouse_gossipsub_config(spec: &ChainSpec) -> gossipsub::Config {
    gossipsub::ConfigBuilder::default()
        .max_transmit_size(spec.max_message_size())
        .heartbeat_interval(Duration::from_secs(1))
        .mesh_n(5)
        .mesh_n_low(3)
        .mesh_outbound_min(2)
        .mesh_n_high(10)
        .gossip_lazy(3)
        .fanout_ttl(Duration::from_secs(60))
        .history_length(12)
        .flood_publish(false)
        .max_publish_messages(500)
        .max_control_messages_sent(500)
        .max_control_message_size(128 << 10)
        .history_gossip(3)
        .validate_messages()
        .validation_mode(ValidationMode::Anonymous)
        .duplicate_cache_time(Duration::from_secs(32 * 12 * 2))
        .message_id_fn(lighthouse_message_id)
        .allow_self_origin(true)
        .idontwant_message_size_threshold(1000)
        .build()
        .unwrap()
}

/// `MESSAGE_DOMAIN_VALID_SNAPPY` as mainnet's `ChainSpec` carries it, read once.
static MESSAGE_DOMAIN_VALID_SNAPPY: LazyLock<[u8; 4]> =
    LazyLock::new(|| ChainSpec::mainnet().message_domain_valid_snappy);

/// The `prefix` and `gossip_message_id` closures of `gossipsub_config`
/// (`config.rs:459-491`), verbatim on their altair branch: every live fork has altair enabled,
/// so the pre-altair branch and the fork-context lookup that selects it are left out.
/// `message.data` is what the snappy transform already decompressed.
fn lighthouse_message_id(message: &gossipsub::Message) -> MessageId {
    let prefix = *MESSAGE_DOMAIN_VALID_SNAPPY;
    let topic_bytes = message.topic.as_str().as_bytes();
    let topic_len_bytes = topic_bytes.len().to_le_bytes();
    let mut vec = Vec::with_capacity(
        prefix.len() + topic_len_bytes.len() + topic_bytes.len() + message.data.len(),
    );
    vec.extend_from_slice(&prefix);
    vec.extend_from_slice(&topic_len_bytes);
    vec.extend_from_slice(topic_bytes);
    vec.extend_from_slice(&message.data);
    MessageId::from(&Sha256::digest(vec.as_slice())[..20])
}

/// Which of the pair an event came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    A,
    B,
}

/// Wraps `behaviour` in a swarm listening on a fresh `/memory/<port>` address.
pub async fn listening(behaviour: GossipBehaviour) -> Swarm<GossipBehaviour> {
    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_other_transport(|keypair| {
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(
                MemoryTransport::default()
                    .upgrade(Version::V1)
                    .authenticate(noise::Config::new(keypair)?)
                    .multiplex(yamux::Config::default()),
            )
        })
        .unwrap()
        .with_behaviour(|_| behaviour)
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();
    swarm.listen_on("/memory/0".parse().unwrap()).unwrap();
    tokio::time::timeout(WAIT, async {
        loop {
            if let SwarmEvent::NewListenAddr { .. } = swarm.select_next_some().await {
                break;
            }
        }
    })
    .await
    .expect("swarm never reported its listen address");
    swarm
}

/// Two listening swarms, `a` dialling `b`, each with the other as its explicit peer, returned
/// once both sides see the connection.
pub async fn connected_pair(
    a: GossipBehaviour,
    b: GossipBehaviour,
) -> (Swarm<GossipBehaviour>, Swarm<GossipBehaviour>) {
    let mut a = listening(a).await;
    let mut b = listening(b).await;
    let (a_id, b_id) = (*a.local_peer_id(), *b.local_peer_id());
    a.behaviour_mut().add_explicit_peer(&b_id);
    b.behaviour_mut().add_explicit_peer(&a_id);
    let b_addr = b.listeners().next().cloned().unwrap();
    a.dial(b_addr).unwrap();
    let mut up = [false, false];
    drive_until(&mut a, &mut b, |side, event| {
        if let SwarmEvent::ConnectionEstablished { .. } = event {
            up[side as usize] = true;
        }
        up.iter().all(|&x| x).then_some(())
    })
    .await;
    (a, b)
}

/// Subscribes both sides to `topic` and waits until each has seen the other's subscription, so
/// a publish right after this reaches the other side.
pub async fn subscribe_both(
    a: &mut Swarm<GossipBehaviour>,
    b: &mut Swarm<GossipBehaviour>,
    topic: &str,
) -> IdentTopic {
    let topic = IdentTopic::new(topic);
    a.behaviour_mut().subscribe(&topic).unwrap();
    b.behaviour_mut().subscribe(&topic).unwrap();
    let mut seen = [false, false];
    drive_until(a, b, |side, event| {
        if let SwarmEvent::Behaviour(gossipsub::Event::Subscribed { .. }) = event {
            seen[side as usize] = true;
        }
        seen.iter().all(|&x| x).then_some(())
    })
    .await;
    topic
}

/// The next gossipsub message either side receives.
pub async fn next_message(
    a: &mut Swarm<GossipBehaviour>,
    b: &mut Swarm<GossipBehaviour>,
) -> Message {
    drive_until(a, b, |_, event| match event {
        SwarmEvent::Behaviour(gossipsub::Event::Message { message, .. }) => Some(message),
        _ => None,
    })
    .await
}

/// Polls both swarms until `done` returns a value for an event from either side. Panics after
/// [`WAIT`], which is how a test reports that the exchange it expected never happened.
pub async fn drive_until<T>(
    a: &mut Swarm<GossipBehaviour>,
    b: &mut Swarm<GossipBehaviour>,
    mut done: impl FnMut(Side, SwarmEvent<gossipsub::Event>) -> Option<T>,
) -> T {
    tokio::time::timeout(WAIT, async {
        loop {
            let (side, event) = tokio::select! {
                event = a.select_next_some() => (Side::A, event),
                event = b.select_next_some() => (Side::B, event),
            };
            if let Some(out) = done(side, event) {
                return out;
            }
        }
    })
    .await
    .expect("the two swarms never produced the awaited event")
}
