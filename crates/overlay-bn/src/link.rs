//! The task that keeps the sidecar connected to its beacon node: dial, explicit peer,
//! reconnect with backoff, and the hand-off of everything the swarm produces to the rest of
//! the sidecar without ever waiting on it.
//!
//! One `select!` over the swarm, the command receiver, the reconnect timer and the connect
//! probe. Nothing else is awaited in the loop and every hand-off out of it is a `try_send`,
//! so a slow consumer loses items and never stalls gossip with the beacon node (D07).
//!
//! The transport is what Lighthouse v8.2.2 accepts on its libp2p port, copied from
//! `build_transport` in `beacon_node/lighthouse_network/src/service/utils.rs`: TCP with
//! `nodelay`, noise, yamux, 10 s for the dial and upgrade together. No DNS layer, because the
//! sidecar dials a literal address, and no identify behaviour: Lighthouse ignores identify
//! errors, so the only cost is that the beacon node lists the sidecar's client as unknown.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use libp2p::core::upgrade::Version;
use libp2p::futures::StreamExt;
use libp2p::gossipsub::{self, IdentTopic, MessageAcceptance, MessageId, PublishError};
use libp2p::request_response::{self, ProtocolSupport, ResponseChannel};
use libp2p::swarm::{ConnectionError, NetworkBehaviour, Swarm, SwarmEvent};
use libp2p::{Multiaddr, PeerId, SwarmBuilder, Transport, multiaddr, noise, tcp, yamux};
use overlay_core::backoff::Backoff;
use overlay_core::config::Bn;
use overlay_core::lanes::LanePusher;
use overlay_core::topic::{Class, SubscriptionSets, UNKNOWN_LARGE_THRESHOLD_BYTES};
use prometheus_client::registry::Registry;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::bn_http::{BnClient, BnHttpError, PeerInfo};
use crate::gossip::{BnLinkConfig, GossipBehaviour, build_behaviour};
use crate::node_key::NodeKey;
use crate::rpc::{Eth2Codec, Request, Responder, Response, proto};
use crate::spec::SpecSnapshot;

/// The first delay before redialling a beacon node that went away; §5.3 uses the same
/// numbers for overlay reconnects.
pub const BACKOFF_MIN: Duration = Duration::from_millis(500);
/// The delay the backoff doubles up to.
pub const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// Lighthouse's own bound on the dial and upgrade together (`build_transport`'s
/// `.timeout(..)`, a `TransportTimeout` around the whole dial future): the TCP connect, the
/// noise handshake and the yamux negotiation share it.
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// How long an inbound req/resp stream has to be read and answered. The same ten seconds the
/// pinned fork defaults to, passed explicitly so a change to that default cannot quietly
/// change how long a half-written request holds a stream open. Lighthouse gives a request
/// 15 s to arrive (`REQUEST_TIMEOUT` in `rpc/protocol.rs`); one that has not arrived in ten
/// is not coming, and the sidecar's answers are a few bytes it already holds.
const RPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Slots in the control channel. On connect Lighthouse sends its whole subscription set in
/// one RPC, up to `max_topics_at_any_fork * 2` topics (`service/mod.rs:336-338`, hundreds
/// at a fork boundary), and each one is a `Subscribed` pushed in a single swarm burst; a
/// dropped one is a topic T-014 never mirrors until the next reconnect, so the channel
/// holds the burst with room to spare.
pub const CONTROL_CHANNEL_CAPACITY: usize = 1024;

/// Topic names that take the large lane on sight: D02's known large kinds, matched by prefix
/// as the §7 row "Lane classification in the swarm loop" has it. Any other name is large only
/// from [`UNKNOWN_LARGE_THRESHOLD_BYTES`] up. The lane is a queueing priority; T-016 computes
/// the authoritative class.
pub const LARGE_NAME_PREFIXES: [&str; 3] =
    ["beacon_block", "data_column_sidecar_", "blob_sidecar_"];

/// What the link needs from the operator's config.
#[derive(Clone, Debug)]
pub struct LinkConfig {
    /// `bn.libp2p_addr`, parsed; the beacon node's peer id is appended per dial.
    pub libp2p_addr: Multiaddr,
    /// The first reconnect delay.
    pub backoff_min: Duration,
    /// The reconnect delay ceiling.
    pub backoff_max: Duration,
    /// The gossipsub parameters the config contributes.
    pub gossip: BnLinkConfig,
}

impl LinkConfig {
    /// The production values: `bn`'s address and flags, the §5.3 backoff.
    pub fn from_config(bn: &Bn) -> Result<Self, multiaddr::Error> {
        Ok(Self {
            libp2p_addr: bn.libp2p_addr.parse()?,
            backoff_min: BACKOFF_MIN,
            backoff_max: BACKOFF_MAX,
            gossip: BnLinkConfig {
                idontwant_on_publish: bn.idontwant_on_publish,
            },
        })
    }
}

/// What the link tells the rest of the sidecar, on a bounded channel it never waits for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BnEvent {
    /// A connection to the beacon node is up and it is the explicit peer.
    Connected {
        /// The beacon node's peer id for this connection.
        peer_id: PeerId,
    },
    /// What the HTTP probe found after a `Connected`. A field is `None` when its request
    /// failed; the connection stays up regardless.
    BnInfo {
        /// The beacon node's raw version string. T-018 parses it.
        version: Option<String>,
        /// Whether `/lighthouse/peers` lists the sidecar as trusted; `None` when the endpoint
        /// failed or the sidecar is not listed.
        trusted: Option<bool>,
    },
    /// The connection went away. Follows a `Connected`; a dial that never succeeded emits
    /// nothing.
    Disconnected,
    /// The beacon node subscribed to `topic`.
    Subscribed {
        /// The beacon node.
        peer: PeerId,
        /// The full topic string.
        topic: String,
    },
    /// The beacon node unsubscribed from `topic`.
    Unsubscribed {
        /// The beacon node.
        peer: PeerId,
        /// The full topic string.
        topic: String,
    },
}

/// A message the beacon node forwarded, as gossipsub handed it over: the payload is still in
/// its compressed wire form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BnMessage {
    /// The id gossipsub computed, which is the beacon node's id for it.
    pub id: MessageId,
    /// The full topic string.
    pub topic: String,
    /// The snappy-compressed payload.
    pub data: Vec<u8>,
    /// The peer it came from, needed to report validation.
    pub source: PeerId,
}

/// What the rest of the sidecar asks the swarm to do.
#[derive(Debug)]
pub enum BnCommand {
    /// Subscribe to the full topic string.
    Subscribe(String),
    /// Unsubscribe from the full topic string.
    Unsubscribe(String),
    /// Publish `data`, already in its compressed wire form, and report gossipsub's answer.
    Publish {
        /// The full topic string.
        topic: String,
        /// The snappy-compressed payload.
        data: Vec<u8>,
        /// Where the message id, or gossipsub's refusal, goes.
        reply: oneshot::Sender<Result<MessageId, PublishError>>,
    },
    /// Tell gossipsub a received message is valid so it leaves the message cache.
    ReportAccept {
        /// The id gossipsub reported the message under.
        id: MessageId,
        /// The peer it came from.
        source: PeerId,
    },
}

/// A running link.
pub struct BnLink {
    /// The swarm task. It ends when the command sender is dropped.
    pub task: JoinHandle<()>,
    /// Whether a connection to the beacon node is up right now; what T-041 exports as
    /// `bn_connected`.
    pub connected: Arc<AtomicBool>,
    /// The control events, [`CONTROL_CHANNEL_CAPACITY`] deep.
    pub events: mpsc::Receiver<BnEvent>,
}

impl BnLink {
    /// Builds the swarm under the node key and starts the task. The first dial happens at
    /// once; every later one waits for the backoff. `registry` receives gossipsub's metrics,
    /// and `sets` is T-014's mirror: every change to the beacon node's own subscriptions is
    /// what the sidecar's `MetaData` answers report.
    #[expect(
        clippy::too_many_arguments,
        reason = "the link's wiring: its config, its identity, and one channel end per \
                  consumer. Every parameter has its own type, so a call site cannot mix two \
                  up, and a struct to hold them would only move the same list one line up"
    )]
    pub fn spawn(
        cfg: LinkConfig,
        node_key: &NodeKey,
        bn_client: BnClient,
        registry: &mut Registry,
        lanes: LanePusher<BnMessage>,
        spec: watch::Sender<SpecSnapshot>,
        sets: watch::Receiver<SubscriptionSets>,
        commands: mpsc::Receiver<BnCommand>,
    ) -> Self {
        let connected = Arc::new(AtomicBool::new(false));
        let (control, events) = mpsc::channel(CONTROL_CHANNEL_CAPACITY);
        let mut responder = Responder::new();
        responder.set_spec(&spec.borrow());
        let link = Link {
            swarm: build_swarm(&cfg.gossip, node_key, registry),
            backoff: Backoff::new(cfg.backoff_min, cfg.backoff_max),
            own_peer_id: node_key.peer_id(),
            cfg,
            bn_client,
            control,
            lanes,
            spec,
            sets,
            commands,
            responder,
            connected: connected.clone(),
            bn_peer: None,
            reconnect: None,
            probe: None,
        };
        Self {
            task: tokio::spawn(link.run()),
            connected,
            events,
        }
    }
}

/// A future the loop polls only while it is armed.
type Pending<T> = Option<Pin<Box<dyn Future<Output = T> + Send>>>;

/// The three answers of the connect probe, in the order they are requested.
type Probe = (
    Result<String, BnHttpError>,
    Result<SpecSnapshot, BnHttpError>,
    Result<Option<PeerInfo>, BnHttpError>,
);

struct Link {
    swarm: Swarm<LinkBehaviour>,
    cfg: LinkConfig,
    bn_client: BnClient,
    own_peer_id: PeerId,
    control: mpsc::Sender<BnEvent>,
    lanes: LanePusher<BnMessage>,
    spec: watch::Sender<SpecSnapshot>,
    sets: watch::Receiver<SubscriptionSets>,
    commands: mpsc::Receiver<BnCommand>,
    responder: Responder,
    connected: Arc<AtomicBool>,
    backoff: Backoff,
    /// The beacon node this link is connected to, while it is.
    bn_peer: Option<PeerId>,
    reconnect: Pending<Result<PeerId, BnHttpError>>,
    probe: Pending<Probe>,
}

impl Link {
    async fn run(mut self) {
        self.arm_reconnect(Duration::ZERO);
        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => self.on_swarm_event(event),
                command = self.commands.recv() => match command {
                    Some(command) => self.on_command(command),
                    None => break,
                },
                identity = armed(&mut self.reconnect) => {
                    self.reconnect = None;
                    self.on_identity(identity);
                }
                probe = armed(&mut self.probe) => {
                    self.probe = None;
                    self.on_probe(probe);
                }
                () = changed(&mut self.sets) => {
                    let sets = self.sets.borrow_and_update();
                    self.responder.set_subscriptions(&sets.advertised);
                }
            }
        }
    }

    /// Fetches the beacon node's peer id after `delay`; the dial happens when it arrives.
    fn arm_reconnect(&mut self, delay: Duration) {
        let client = self.bn_client.clone();
        self.reconnect = Some(Box::pin(async move {
            tokio::time::sleep(delay).await;
            client.peer_id().await
        }));
    }

    /// Arms the reconnect with the next backoff delay. The RNG is a fresh thread-local each
    /// time because it must not live across the loop's awaits.
    fn retry_later(&mut self) {
        let delay = self.backoff.next_delay(&mut rand::rng());
        self.arm_reconnect(delay);
    }

    fn on_identity(&mut self, identity: Result<PeerId, BnHttpError>) {
        let peer_id = match identity {
            Ok(peer_id) => peer_id,
            Err(err) => {
                tracing::warn!(%err, "beacon node identity unavailable");
                return self.retry_later();
            }
        };
        let addr = match self.cfg.libp2p_addr.clone().with_p2p(peer_id) {
            Ok(addr) => addr,
            Err(addr) => {
                tracing::error!(%addr, %peer_id, "bn.libp2p_addr names another peer id");
                return self.retry_later();
            }
        };
        if let Err(err) = self.swarm.dial(addr) {
            tracing::warn!(%err, "dial refused");
            self.retry_later();
        }
    }

    fn on_swarm_event(&mut self, event: SwarmEvent<LinkBehaviourEvent>) {
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, .. } => self.on_connected(peer_id),
            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established: 0,
                cause,
                ..
            } => self.on_closed(peer_id, cause),
            SwarmEvent::OutgoingConnectionError { error, .. } => {
                tracing::warn!(%error, "dial to the beacon node failed");
                self.retry_later();
            }
            SwarmEvent::Behaviour(LinkBehaviourEvent::Gossip(gossipsub::Event::Message {
                propagation_source,
                message_id,
                message,
            })) => {
                let topic = message.topic.into_string();
                let class = lane_for(&topic, message.data.len());
                // A dropped message is counted, and for the large lane logged, by the pusher.
                let _ = self.lanes.push(
                    class,
                    BnMessage {
                        id: message_id,
                        topic,
                        data: message.data,
                        source: propagation_source,
                    },
                );
            }
            SwarmEvent::Behaviour(LinkBehaviourEvent::Gossip(gossipsub::Event::Subscribed {
                peer_id,
                topic,
                ..
            })) => {
                self.emit(BnEvent::Subscribed {
                    peer: peer_id,
                    topic: topic.into_string(),
                });
            }
            SwarmEvent::Behaviour(LinkBehaviourEvent::Gossip(gossipsub::Event::Unsubscribed {
                peer_id,
                topic,
            })) => {
                self.emit(BnEvent::Unsubscribed {
                    peer: peer_id,
                    topic: topic.into_string(),
                });
            }
            SwarmEvent::Behaviour(LinkBehaviourEvent::Rpc(request_response::Event::Message {
                peer,
                message:
                    request_response::Message::Request {
                        request, channel, ..
                    },
                ..
            })) => self.on_rpc_request(peer, request, channel),
            _ => {}
        }
    }

    /// Answers one request from the responder's own state. A Goodbye is the beacon node's
    /// farewell: there is no chunk to write, so the channel is dropped and the connection
    /// closed, which T-013's reconnect picks up. A refused send is a stream the peer has
    /// already gone from.
    fn on_rpc_request(
        &mut self,
        peer: PeerId,
        request: Request,
        channel: ResponseChannel<Response>,
    ) {
        let response = self.responder.answer(&request);
        if let Response::Goodbye(reason) = response {
            tracing::info!(%peer, reason, "the beacon node said goodbye");
            let _ = self.swarm.disconnect_peer_id(peer);
        } else {
            let _ = self
                .swarm
                .behaviour_mut()
                .rpc
                .send_response(channel, response);
        }
    }

    /// Makes the beacon node the explicit peer, reports it, and starts the HTTP probe, which
    /// runs beside the swarm rather than in front of it.
    fn on_connected(&mut self, peer_id: PeerId) {
        self.swarm
            .behaviour_mut()
            .gossip
            .add_explicit_peer(&peer_id);
        self.bn_peer = Some(peer_id);
        self.connected.store(true, Ordering::Relaxed);
        self.backoff.reset();
        self.emit(BnEvent::Connected { peer_id });
        let client = self.bn_client.clone();
        let own = self.own_peer_id;
        self.probe = Some(Box::pin(async move {
            tokio::join!(client.version(), client.spec(), client.peer_info(&own))
        }));
    }

    /// The explicit peer is removed before the redial so gossipsub does not dial it too, with
    /// no address, on its own schedule. A probe still running is for a connection that is
    /// gone; the next connect starts another.
    fn on_closed(&mut self, peer_id: PeerId, cause: Option<ConnectionError>) {
        tracing::warn!(%peer_id, ?cause, "connection to the beacon node closed");
        self.swarm
            .behaviour_mut()
            .gossip
            .remove_explicit_peer(&peer_id);
        if self.bn_peer.take().is_some() {
            self.connected.store(false, Ordering::Relaxed);
            self.probe = None;
            self.emit(BnEvent::Disconnected);
        }
        self.retry_later();
    }

    /// A failed request is a `None` field and a warning, never a disconnect: a slow HTTP port
    /// is no reason to drop gossip.
    fn on_probe(&mut self, (version, spec, peer_info): Probe) {
        for err in [
            version.as_ref().err(),
            spec.as_ref().err(),
            peer_info.as_ref().err(),
        ]
        .into_iter()
        .flatten()
        {
            tracing::warn!(%err, "connect probe failed");
        }
        if let Ok(snapshot) = spec {
            self.responder.set_spec(&snapshot);
            self.spec.send_replace(snapshot);
        }
        self.emit(BnEvent::BnInfo {
            version: version.ok(),
            trusted: peer_info.ok().flatten().map(|peer| peer.is_trusted),
        });
    }

    fn on_command(&mut self, command: BnCommand) {
        let gossip = &mut self.swarm.behaviour_mut().gossip;
        match command {
            BnCommand::Subscribe(topic) => {
                if let Err(err) = gossip.subscribe(&IdentTopic::new(topic)) {
                    tracing::warn!(%err, "subscribe refused");
                }
            }
            BnCommand::Unsubscribe(topic) => {
                gossip.unsubscribe(&IdentTopic::new(topic));
            }
            BnCommand::Publish { topic, data, reply } => {
                // The requester may have stopped waiting; there is nothing to do about that.
                let _ = reply.send(gossip.publish(IdentTopic::new(topic), data));
            }
            BnCommand::ReportAccept { id, source } => {
                gossip.report_message_validation_result(&id, &source, MessageAcceptance::Accept);
            }
        }
    }

    /// Hands `event` to the control channel without waiting. A full channel drops it, counts
    /// it and says so at error level: the consumer is not keeping up with a handful of events.
    fn emit(&self, event: BnEvent) {
        match self.control.try_send(event) {
            Ok(()) | Err(TrySendError::Closed(_)) => {}
            Err(TrySendError::Full(event)) => {
                self.lanes.stats().control_dropped();
                tracing::error!(?event, "control channel full; event dropped");
            }
        }
    }
}

/// The `lighthouse.env` line that makes the beacon node trust the sidecar and dial it: the
/// only place the file's content is built, so what T-045 writes cannot drift from what the
/// link listens on. `--libp2p-addresses` is dialled once at beacon-node startup and is
/// deprecated at v8.2.2; the ENR the link registers on every reconnect is what covers a
/// sidecar restart (MD-01).
pub fn lighthouse_env_line(peer_id: &PeerId, listen: &Multiaddr) -> String {
    format!(
        "FLEET_OVERLAY_TRUSTED_PEER_ARGS=--trusted-peers {peer_id} \
         --libp2p-addresses {listen}/p2p/{peer_id}"
    )
}

/// The lane a message queues in: a known large name by prefix, else by size (D02). The name
/// is the third `/`-separated field of `/eth2/<digest>/<name>/ssz_snappy`.
fn lane_for(topic: &str, payload_len: usize) -> Class {
    let name = topic.split('/').nth(3).unwrap_or("");
    let large_name = LARGE_NAME_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix));
    if large_name || payload_len >= UNKNOWN_LARGE_THRESHOLD_BYTES {
        Class::Large
    } else {
        Class::Small
    }
}

/// The next change to the beacon node's subscriptions. Once the sender is gone this never
/// completes again, so a mirror that stopped leaves the arm quiet instead of spinning the loop.
async fn changed(sets: &mut watch::Receiver<SubscriptionSets>) {
    if sets.changed().await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// Polls the future in `slot` and stays pending while there is none, so an unarmed timer is
/// an arm of the `select!` that never fires.
async fn armed<T>(slot: &mut Pending<T>) -> T {
    match slot {
        Some(future) => future.await,
        None => std::future::pending().await,
    }
}

/// The behaviours the beacon node talks to: gossipsub, and the request/response protocols its
/// peer manager needs answered (§5.2). Every protocol id the sidecar knows is registered
/// [`ProtocolSupport::Inbound`], so there is no path that opens an outbound stream.
#[derive(NetworkBehaviour)]
struct LinkBehaviour {
    /// Gossipsub, built to match the beacon node's on everything the wire depends on.
    gossip: GossipBehaviour,
    /// The eth2 req/resp protocols, answered from the sidecar's own state.
    rpc: request_response::Behaviour<Eth2Codec>,
}

/// The swarm under the node key, with Lighthouse's transport chain and no idle timeout: a
/// quiet link is closed by the beacon node or by nobody.
#[expect(
    clippy::expect_used,
    reason = "noise only refuses a keypair it cannot sign with, and the node key is Ed25519; \
              Lighthouse's build_transport expects the same"
)]
fn build_swarm(
    cfg: &BnLinkConfig,
    node_key: &NodeKey,
    registry: &mut Registry,
) -> Swarm<LinkBehaviour> {
    let Ok(builder) = SwarmBuilder::with_existing_identity(node_key.keypair())
        .with_tokio()
        .with_other_transport(|keypair| {
            tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
                .upgrade(Version::V1)
                .authenticate(noise::Config::new(keypair).expect("an Ed25519 keypair can sign"))
                .multiplex(yamux::Config::default())
                .timeout(DIAL_TIMEOUT)
        });
    let Ok(builder) = builder.with_behaviour(|_| LinkBehaviour {
        gossip: build_behaviour(cfg, registry),
        rpc: request_response::Behaviour::with_codec(
            Eth2Codec,
            proto::all().map(|id| (id, ProtocolSupport::Inbound)),
            request_response::Config::default().with_request_timeout(RPC_REQUEST_TIMEOUT),
        ),
    });
    builder
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::MAX))
        .build()
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeSet, HashSet};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use lighthouse_network::rpc::methods::{MetaData, StatusMessageV2};
    use lighthouse_network::rpc::{GoodbyeReason, StatusMessage};
    use overlay_core::lanes::{ClassLanes, LaneStats, SMALL_LANE_CAPACITY};
    use overlay_core::msgid;
    use overlay_core::topic::{Class, Topic, TopicKind};
    use prometheus_client::registry::Registry;
    use proptest::prelude::*;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use serde_json::json;
    use types::{Epoch, Hash256, Slot};
    use wiremock::{MockServer, ResponseTemplate};

    use super::*;
    use crate::bn_http::BnClient;
    use crate::gossip::wire;
    use crate::node_key::NodeKey;
    use crate::spec::spec_watch;
    use crate::testutil::{
        FakeBn, FakeBnEvent, IDLE_TIMEOUT, RpcAnswer, link_config, node_key, ok_json,
    };

    /// Long enough for a dial, a noise handshake and a gossipsub exchange on a loaded CI box,
    /// short enough that a test which waits in vain still ends inside its 5 s budget.
    const WAIT: Duration = Duration::from_secs(3);
    const BLOCK_TOPIC: &str = "/eth2/6a95a1a9/beacon_block/ssz_snappy";
    const ATTESTATION_TOPIC: &str = "/eth2/6a95a1a9/beacon_attestation_7/ssz_snappy";
    /// `hello`, snappy-compressed: T-006's spec vector input.
    const HELLO_SNAPPY: &[u8] = &[0x05, 0x10, 0x68, 0x65, 0x6c, 0x6c, 0x6f];

    /// A running link and the test's ends of its channels.
    struct Harness {
        peer_id: PeerId,
        link: BnLink,
        commands: mpsc::Sender<BnCommand>,
        spec: watch::Receiver<SpecSnapshot>,
        sets: watch::Sender<SubscriptionSets>,
        lanes: ClassLanes<BnMessage>,
        stats: Arc<Counts>,
    }

    #[derive(Default)]
    struct Counts {
        small: AtomicUsize,
        large: AtomicUsize,
        control: AtomicUsize,
    }

    impl LaneStats for Counts {
        fn dropped(&self, class: Class) {
            match class {
                Class::Small => &self.small,
                Class::Large => &self.large,
            }
            .fetch_add(1, Ordering::Relaxed);
        }

        fn control_dropped(&self) {
            self.control.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A loopback port nothing listens on.
    fn closed_port() -> Multiaddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap()
    }

    async fn identity_requests(http: &MockServer) -> usize {
        http.received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.url.path() == "/eth/v1/node/identity")
            .count()
    }

    /// A link under a fresh node key. The key file is read at spawn and not needed after.
    fn spawn(cfg: LinkConfig, bn: &FakeBn) -> Harness {
        spawn_with_key(cfg, bn, &node_key(&tempfile::tempdir().unwrap()))
    }

    fn spawn_with_key(cfg: LinkConfig, bn: &FakeBn, node_key: &NodeKey) -> Harness {
        spawn_with_spec(cfg, bn, node_key, SpecSnapshot::MAINNET)
    }

    /// A link whose spec watch already holds `spec` when it starts, the way a process that
    /// read the beacon node's spec before spawning the link would leave it.
    fn spawn_with_spec(
        cfg: LinkConfig,
        bn: &FakeBn,
        node_key: &NodeKey,
        spec_value: SpecSnapshot,
    ) -> Harness {
        let (commands, commands_rx) = mpsc::channel(64);
        let (spec_tx, _) = spec_watch();
        spec_tx.send_replace(spec_value);
        // Subscribed after the send, so `changed()` waits for the connect probe's snapshot.
        let spec = spec_tx.subscribe();
        let (sets, sets_rx) = watch::channel(SubscriptionSets::default());
        let stats = Arc::new(Counts::default());
        let lanes = ClassLanes::new(stats.clone());
        let link = BnLink::spawn(
            cfg,
            node_key,
            BnClient::new(bn.http_addr(), Duration::from_secs(2)),
            &mut Registry::default(),
            lanes.pusher(),
            spec_tx,
            sets_rx,
            commands_rx,
        );
        Harness {
            peer_id: node_key.peer_id(),
            link,
            commands,
            spec,
            sets,
            lanes,
            stats,
        }
    }

    /// The address the link bound, with the link's peer id on it, which is what a beacon node
    /// reads out of the sidecar's ENR.
    async fn listen_addr(harness: &Harness) -> Multiaddr {
        let mut listen = harness.link.listen.clone();
        let addr = tokio::time::timeout(WAIT, listen.wait_for(Option::is_some))
            .await
            .expect("the link never reported a listen address")
            .unwrap()
            .clone()
            .expect("a listen address");
        addr.with_p2p(harness.peer_id).unwrap()
    }

    /// Waits until the link has asked for the beacon node's identity `n` times. The next
    /// request is only armed once the previous answer has been handled, so `n` of them mean
    /// `n - 1` answers are in: that is how a test knows the link knows who the beacon node is.
    async fn identity_requests_reach(bn: &FakeBn, n: usize) {
        tokio::time::timeout(WAIT, async {
            while identity_requests(bn.http()).await < n {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the link never asked for the beacon node's identity often enough");
    }

    async fn next_event(control: &mut mpsc::Receiver<BnEvent>) -> BnEvent {
        tokio::time::timeout(WAIT, control.recv())
            .await
            .expect("no control event arrived in time")
            .expect("the link ended")
    }

    /// Skips control events until one satisfies `wanted`.
    async fn wait_for(
        control: &mut mpsc::Receiver<BnEvent>,
        mut wanted: impl FnMut(&BnEvent) -> bool,
    ) -> BnEvent {
        tokio::time::timeout(WAIT, async {
            loop {
                let event = control.recv().await.expect("the link ended");
                if wanted(&event) {
                    return event;
                }
            }
        })
        .await
        .expect("the awaited control event never arrived")
    }

    /// Subscribes the link to `topics` and waits until the fake has seen each subscription,
    /// so a publish from the fake right after reaches the link.
    async fn subscribe_link(harness: &Harness, bn: &mut FakeBn, topics: &[&str]) {
        for topic in topics {
            harness
                .commands
                .send(BnCommand::Subscribe((*topic).to_owned()))
                .await
                .unwrap();
            bn.wait_for(|e| matches!(e, FakeBnEvent::Subscribed { topic: t, .. } if t == topic))
                .await;
        }
    }

    async fn recv_from(lanes: &mut ClassLanes<BnMessage>, class: Class) -> BnMessage {
        tokio::time::timeout(WAIT, lanes.recv_from(class))
            .await
            .unwrap_or_else(|_| panic!("nothing arrived on the {class:?} lane in time"))
    }

    fn decompress(data: &[u8]) -> Vec<u8> {
        snap::raw::Decoder::new().decompress_vec(data).unwrap()
    }

    async fn publish(
        commands: &mpsc::Sender<BnCommand>,
        topic: &str,
        data: &[u8],
    ) -> Result<MessageId, PublishError> {
        let (reply, answer) = oneshot::channel();
        commands
            .send(BnCommand::Publish {
                topic: topic.to_owned(),
                data: data.to_vec(),
                reply,
            })
            .await
            .unwrap();
        tokio::time::timeout(WAIT, answer)
            .await
            .expect("no publish reply in time")
            .unwrap()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn link_connects_and_emits_connected_with_bn_peer_id() {
        let bn = FakeBn::start().await;
        let mut harness = spawn(link_config(&bn), &bn);

        let event = next_event(&mut harness.link.events).await;

        assert_eq!(
            event,
            BnEvent::Connected {
                peer_id: bn.peer_id()
            }
        );
        assert!(!harness.link.task.is_finished());
        drop(harness.commands);
    }

    /// The other direction, which is what MD-01 rests on: the link's own dial can never
    /// succeed, and the beacon node dialling its listen address is what connects them.
    #[tokio::test(flavor = "multi_thread")]
    async fn link_listens_before_dialling_and_accepts_the_bn() {
        let bn = FakeBn::start().await;
        let cfg = LinkConfig {
            libp2p_addr: closed_port(),
            ..link_config(&bn)
        };
        let mut harness = spawn(cfg, &bn);
        let addr = listen_addr(&harness).await;
        identity_requests_reach(&bn, 2).await;

        bn.dial(addr).await;

        assert_eq!(
            next_event(&mut harness.link.events).await,
            BnEvent::Connected {
                peer_id: bn.peer_id()
            }
        );
    }

    /// The sidecar never subscribes here, so it has no mesh for the topic, and the publish
    /// still reaches the fake. Whether that is explicit-peer forwarding or gossipsub's fanout
    /// fill cannot be separated while the beacon node is the sidecar's only peer: a
    /// subscribed peer is a fanout candidate either way, against any BN.
    #[tokio::test(flavor = "multi_thread")]
    async fn publish_without_sidecar_subscription_reaches_the_bn() {
        let mut bn = FakeBn::start().await;
        let mut harness = spawn(link_config(&bn), &bn);
        let mut received = bn.received();
        bn.subscribe(BLOCK_TOPIC).await;
        wait_for(
            &mut harness.link.events,
            |event| matches!(event, BnEvent::Subscribed { topic, .. } if topic == BLOCK_TOPIC),
        )
        .await;

        let id = publish(&harness.commands, BLOCK_TOPIC, HELLO_SNAPPY)
            .await
            .unwrap();

        let (topic, data, bn_id) = tokio::time::timeout(WAIT, received.recv())
            .await
            .expect("the fake never received the publish")
            .unwrap();
        assert_eq!(topic, BLOCK_TOPIC);
        assert_eq!(data, b"hello");
        assert_eq!(bn_id, id);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn link_reconnects_after_fake_bn_restart_with_new_peer_id() {
        let bn = FakeBn::start().await;
        let mut harness = spawn(link_config(&bn), &bn);
        let old_id = bn.peer_id();
        assert_eq!(
            next_event(&mut harness.link.events).await,
            BnEvent::Connected { peer_id: old_id }
        );

        let port = bn.port();
        let http = bn.shutdown().await;
        // The connect probe's BnInfo may land before the swarm notices the close.
        wait_for(&mut harness.link.events, |e| *e == BnEvent::Disconnected).await;
        let bn = FakeBn::start_on(port, http).await;

        assert_ne!(bn.peer_id(), old_id);
        assert_eq!(
            next_event(&mut harness.link.events).await,
            BnEvent::Connected {
                peer_id: bn.peer_id()
            }
        );
    }

    /// With 10 ms doubling to 100 ms, jittered down to half, 500 ms holds a dozen attempts
    /// at most; a loop that redials as fast as the port refuses would make hundreds.
    #[tokio::test(flavor = "multi_thread")]
    async fn link_does_not_spin_when_bn_is_down() {
        let bn = FakeBn::start().await;
        let cfg = LinkConfig {
            libp2p_addr: closed_port(),
            ..link_config(&bn)
        };
        let harness = spawn(cfg, &bn);

        tokio::time::sleep(Duration::from_millis(500)).await;

        let attempts = identity_requests(bn.http()).await;
        assert!((2..=20).contains(&attempts), "{attempts} identity requests");
        drop(harness);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bn_connected_gauge_tracks_state() {
        let bn = FakeBn::start().await;
        let mut harness = spawn(link_config(&bn), &bn);
        let gauge = harness.link.connected.clone();
        assert!(!gauge.load(Ordering::Relaxed));

        wait_for(&mut harness.link.events, |e| {
            matches!(e, BnEvent::Connected { .. })
        })
        .await;
        assert!(gauge.load(Ordering::Relaxed));

        bn.shutdown().await;
        wait_for(&mut harness.link.events, |e| *e == BnEvent::Disconnected).await;
        assert!(!gauge.load(Ordering::Relaxed));
    }

    /// The first outage runs the backoff up to its 100 ms ceiling; after the reconnect, the
    /// second outage must redial within the 10 ms minimum again, jittered down to 5 ms.
    #[tokio::test(flavor = "multi_thread")]
    async fn backoff_resets_after_a_successful_connect_so_the_next_outage_starts_at_min() {
        let bn = FakeBn::start().await;
        let port = bn.port();
        let mut harness = spawn(link_config(&bn), &bn);
        wait_for(&mut harness.link.events, |e| {
            matches!(e, BnEvent::Connected { .. })
        })
        .await;

        let http = bn.shutdown().await;
        wait_for(&mut harness.link.events, |e| *e == BnEvent::Disconnected).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let bn = FakeBn::start_on(port, http).await;
        wait_for(&mut harness.link.events, |e| {
            matches!(e, BnEvent::Connected { .. })
        })
        .await;

        let http = bn.shutdown().await;
        wait_for(&mut harness.link.events, |e| *e == BnEvent::Disconnected).await;
        let before = identity_requests(&http).await;
        tokio::time::sleep(Duration::from_millis(40)).await;
        let after = identity_requests(&http).await;

        assert!(
            after > before,
            "no redial within 40 ms of the second outage"
        );
    }

    /// Two links from the same key file show the beacon node the same peer id, which is the
    /// id the node key reports. That no seed is involved is the DoD's grep over overlay-bn,
    /// not something a test can show.
    #[tokio::test(flavor = "multi_thread")]
    async fn peer_id_comes_from_the_node_key_and_is_stable_across_link_restarts() {
        let mut bn = FakeBn::start().await;
        let dir = tempfile::tempdir().unwrap();
        let expected = node_key(&dir).peer_id();

        let harness = spawn_with_key(link_config(&bn), &bn, &node_key(&dir));
        let first = bn
            .wait_for(|e| matches!(e, FakeBnEvent::Connected(_)))
            .await;
        drop(harness.commands);
        harness.link.task.await.unwrap();
        bn.wait_for(|e| matches!(e, FakeBnEvent::Disconnected(_)))
            .await;
        let harness = spawn_with_key(link_config(&bn), &bn, &node_key(&dir));
        let second = bn
            .wait_for(|e| matches!(e, FakeBnEvent::Connected(_)))
            .await;

        assert_eq!(first, FakeBnEvent::Connected(expected));
        assert_eq!(second, FakeBnEvent::Connected(expected));
        drop(harness);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn connect_probe_emits_bn_info_and_updates_the_spec_watch() {
        let mut bn = FakeBn::start().await;
        let dir = tempfile::tempdir().unwrap();
        let key = node_key(&dir);
        bn.set_version_response(ok_json(json!({"data": {"version": "Lighthouse/v8.2.2"}})))
            .await;
        bn.set_spec_response(ok_json(json!({"data": {"NUMBER_OF_COLUMNS": "64"}})))
            .await;
        bn.set_peers_response(ok_json(json!([{
            "peer_id": key.peer_id().to_string(),
            "peer_info": {"is_trusted": true}
        }])))
        .await;
        let mut harness = spawn_with_key(link_config(&bn), &bn, &key);

        wait_for(&mut harness.link.events, |e| {
            matches!(e, BnEvent::Connected { .. })
        })
        .await;
        let info = next_event(&mut harness.link.events).await;

        assert_eq!(
            info,
            BnEvent::BnInfo {
                version: Some("Lighthouse/v8.2.2".to_owned()),
                trusted: Some(true),
            }
        );
        assert_eq!(harness.spec.borrow().number_of_columns, 64);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn connect_probe_failures_yield_none_fields_and_keep_the_default_spec() {
        let mut bn = FakeBn::start().await;
        bn.set_peers_response(ResponseTemplate::new(404)).await;
        bn.set_version_response(ResponseTemplate::new(503)).await;
        bn.set_spec_response(ResponseTemplate::new(503)).await;
        let mut harness = spawn(link_config(&bn), &bn);

        wait_for(&mut harness.link.events, |e| {
            matches!(e, BnEvent::Connected { .. })
        })
        .await;
        let info = next_event(&mut harness.link.events).await;
        let later =
            tokio::time::timeout(Duration::from_millis(200), harness.link.events.recv()).await;

        assert_eq!(
            info,
            BnEvent::BnInfo {
                version: None,
                trusted: None,
            }
        );
        assert_eq!(*harness.spec.borrow(), SpecSnapshot::MAINNET);
        assert!(later.is_err(), "unexpected event after BnInfo: {later:?}");
        assert!(harness.link.connected.load(Ordering::Relaxed));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn block_lands_in_the_large_lane_and_attestation_in_the_small_lane() {
        let mut bn = FakeBn::start().await;
        let mut harness = spawn(link_config(&bn), &bn);
        wait_for(&mut harness.link.events, |e| {
            matches!(e, BnEvent::Connected { .. })
        })
        .await;
        subscribe_link(&harness, &mut bn, &[BLOCK_TOPIC, ATTESTATION_TOPIC]).await;

        let block_id = bn.publish(BLOCK_TOPIC, b"a block").await.unwrap();
        let attestation_id = bn
            .publish(ATTESTATION_TOPIC, b"an attestation")
            .await
            .unwrap();
        let block = recv_from(&mut harness.lanes, Class::Large).await;
        let attestation = recv_from(&mut harness.lanes, Class::Small).await;

        assert_eq!(
            (block.topic.as_str(), block.id, block.source),
            (BLOCK_TOPIC, block_id, bn.peer_id())
        );
        assert_eq!(decompress(&block.data), b"a block");
        assert_eq!(
            (
                attestation.topic.as_str(),
                attestation.id,
                attestation.source
            ),
            (ATTESTATION_TOPIC, attestation_id, bn.peer_id())
        );
        assert_eq!(decompress(&attestation.data), b"an attestation");
        assert_eq!(harness.stats.small.load(Ordering::Relaxed), 0);
    }

    /// The small lane is never read. Gossipsub delivers in order on one connection, so by
    /// the time the block arrives every attestation has been pushed, and the hundred past
    /// the capacity were dropped rather than waited for.
    #[tokio::test(flavor = "multi_thread")]
    async fn unread_small_lane_does_not_stall_the_swarm_loop_or_the_large_lane() {
        let mut bn = FakeBn::start().await;
        let mut harness = spawn(link_config(&bn), &bn);
        wait_for(&mut harness.link.events, |e| {
            matches!(e, BnEvent::Connected { .. })
        })
        .await;
        subscribe_link(&harness, &mut bn, &[BLOCK_TOPIC, ATTESTATION_TOPIC]).await;

        for i in 0..(SMALL_LANE_CAPACITY + 100) as u32 {
            bn.publish(ATTESTATION_TOPIC, &i.to_le_bytes())
                .await
                .unwrap();
        }
        let block_id = bn.publish(BLOCK_TOPIC, b"a block").await.unwrap();
        let block = recv_from(&mut harness.lanes, Class::Large).await;

        assert_eq!(block.id, block_id);
        assert_eq!(harness.stats.small.load(Ordering::Relaxed), 100);
        assert_eq!(harness.stats.large.load(Ordering::Relaxed), 0);
    }

    /// Every T-005 kind under one fork digest, plus a name the sidecar does not know.
    fn any_topic() -> impl Strategy<Value = String> {
        prop_oneof![
            Just(TopicKind::BeaconBlock),
            Just(TopicKind::BeaconAggregateAndProof),
            (0..64u8).prop_map(TopicKind::Attestation),
            (0..4u8).prop_map(TopicKind::SyncCommittee),
            Just(TopicKind::SyncContributionAndProof),
            Just(TopicKind::VoluntaryExit),
            Just(TopicKind::ProposerSlashing),
            Just(TopicKind::AttesterSlashing),
            Just(TopicKind::BlsToExecutionChange),
            (0..128u8).prop_map(TopicKind::DataColumnSidecar),
            (0..9u8).prop_map(TopicKind::BlobSidecar),
            Just(TopicKind::Other("execution_payload".to_owned())),
        ]
        .prop_map(|kind| format!("/eth2/6a95a1a9/{kind}/ssz_snappy"))
    }

    /// CL-N2 conformance item 6: the id the fake computes with Lighthouse's own id closure
    /// over the decompressed payload equals T-006's id over the compressed bytes, for random
    /// topics and payloads. Cases are drawn inside the async test rather than under
    /// `proptest!`, which would need a runtime per case; a failure prints the case.
    #[tokio::test(flavor = "multi_thread")]
    async fn published_message_id_matches_fake_bn_for_random_payloads() {
        let mut bn = FakeBn::start().await;
        let mut received = bn.received();
        let mut harness = spawn(link_config(&bn), &bn);
        wait_for(&mut harness.link.events, |e| {
            matches!(e, BnEvent::Connected { .. })
        })
        .await;
        let mut runner = TestRunner::default();
        let case = (any_topic(), proptest::collection::vec(any::<u8>(), 8..2048));
        let mut subscribed = HashSet::new();

        for _ in 0..32 {
            let (topic, payload) = case.new_tree(&mut runner).unwrap().current();
            if subscribed.insert(topic.clone()) {
                bn.subscribe(&topic).await;
                wait_for(
                    &mut harness.link.events,
                    |e| matches!(e, BnEvent::Subscribed { topic: t, .. } if *t == topic),
                )
                .await;
            }
            let compressed = snap::raw::Encoder::new().compress_vec(&payload).unwrap();
            let expected = msgid::compute(&topic, &compressed, wire::MAX_PAYLOAD_SIZE as usize);

            let sidecar_id = publish(&harness.commands, &topic, &compressed)
                .await
                .unwrap();
            let (bn_topic, bn_data, bn_id) = tokio::time::timeout(WAIT, received.recv())
                .await
                .unwrap_or_else(|_| panic!("{topic}: the fake never received the publish"))
                .unwrap();

            assert_eq!(bn_topic, topic);
            assert_eq!(bn_data, payload, "{topic}");
            assert_eq!(expected.branch, msgid::Branch::Valid, "{topic}");
            assert_eq!(bn_id.0, expected.id.0, "{topic} payload {payload:02x?}");
            assert_eq!(sidecar_id, bn_id, "{topic}");
        }
    }

    /// A beacon node's view of its own chain, as its peer manager sends it on every new peer.
    fn bn_status() -> StatusMessage {
        StatusMessage::V2(StatusMessageV2 {
            fork_digest: [1, 2, 3, 4],
            finalized_root: Hash256::repeat_byte(0xaa),
            finalized_epoch: Epoch::new(7),
            head_root: Hash256::repeat_byte(0xbb),
            head_slot: Slot::new(250),
            earliest_available_slot: Slot::new(9),
        })
    }

    async fn next_answer(answers: &mut mpsc::Receiver<RpcAnswer>) -> RpcAnswer {
        tokio::time::timeout(WAIT, answers.recv())
            .await
            .expect("the beacon node's request went unanswered")
            .expect("the fake ended")
    }

    /// A connected link, and the fake's end of the RPC.
    async fn connected(bn: &mut FakeBn) -> (Harness, mpsc::Receiver<RpcAnswer>) {
        let answers = bn.responses();
        let harness = spawn(link_config(bn), bn);
        bn.wait_for(|e| matches!(e, FakeBnEvent::Connected(_)))
            .await;
        (harness, answers)
    }

    /// The advertised set a mirror would publish for `names`, all under one fork digest.
    fn advertised(names: &[&str]) -> SubscriptionSets {
        let advertised: BTreeSet<Topic> = names
            .iter()
            .map(|name| Topic::parse(&format!("/eth2/6a95a1a9/{name}/ssz_snappy")).unwrap())
            .collect();
        SubscriptionSets {
            local: advertised.clone(),
            advertised,
        }
    }

    /// Pings until the sidecar answers with `seq`, so a test never races a subscription on
    /// its way to the responder against the request that reads it.
    async fn ping_until(bn: &FakeBn, answers: &mut mpsc::Receiver<RpcAnswer>, seq: u64) {
        tokio::time::timeout(WAIT, async {
            loop {
                bn.send_ping(0).await;
                if next_answer(answers).await == RpcAnswer::Pong(seq) {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("the sidecar never reported sequence number {seq}"));
    }

    /// Lighthouse offers status v2 first, so that is what is negotiated, and the echo comes
    /// back through its own outbound codec: the fields it sent, `earliest_available_slot`
    /// included.
    #[tokio::test(flavor = "multi_thread")]
    async fn fake_bn_status_request_is_answered_with_its_own_fields() {
        let mut bn = FakeBn::start().await;
        let (harness, mut answers) = connected(&mut bn).await;

        bn.send_status(bn_status()).await;

        assert_eq!(
            next_answer(&mut answers).await,
            RpcAnswer::Status(bn_status())
        );
        drop(harness);
    }

    /// A ping is answered with the sidecar's own sequence number, not the one it was sent,
    /// and the metadata request that follows carries the bits of the advertised set.
    /// Lighthouse offers v3 first, so v3 is what it decodes.
    #[tokio::test(flavor = "multi_thread")]
    async fn fake_bn_ping_gets_seq_number_and_metadata_request_gets_current_bitfields() {
        let mut bn = FakeBn::start().await;
        let (harness, mut answers) = connected(&mut bn).await;

        harness
            .sets
            .send(advertised(&["beacon_attestation_3", "sync_committee_1"]))
            .unwrap();
        ping_until(&bn, &mut answers, 1).await;
        bn.request_metadata().await;

        let answer = next_answer(&mut answers).await;
        let RpcAnswer::MetaData(metadata) = &answer else {
            panic!("not a metadata answer: {answer:?}");
        };
        let MetaData::V3(metadata) = metadata.as_ref() else {
            panic!("not metadata v3: {metadata:?}");
        };
        assert_eq!(metadata.seq_number, 1);
        assert!(metadata.attnets.get(3).unwrap());
        assert!(!metadata.attnets.get(4).unwrap());
        assert!(metadata.syncnets.get(1).unwrap());
        assert_eq!(metadata.custody_group_count, 4);
    }

    /// The custody range in the metadata the sidecar answers comes from the beacon node's own
    /// spec, by the connect probe. Without it the sidecar would answer mainnet's floor of 4,
    /// which is out of range on a network that reports fewer groups than that, and Lighthouse
    /// says goodbye to a peer whose count it cannot use.
    #[tokio::test(flavor = "multi_thread")]
    async fn custody_range_from_the_connect_probe_reaches_the_metadata_answer() {
        let mut bn = FakeBn::start().await;
        bn.set_spec_response(ok_json(json!({"data": {
            "CUSTODY_REQUIREMENT": "1",
            "NUMBER_OF_CUSTODY_GROUPS": "1"
        }})))
        .await;
        let (mut harness, mut answers) = connected(&mut bn).await;

        // The probe hands the responder the snapshot before it publishes it here.
        tokio::time::timeout(WAIT, harness.spec.changed())
            .await
            .expect("the connect probe never reported the spec")
            .unwrap();
        bn.request_metadata().await;

        assert_eq!(harness.spec.borrow().custody_requirement, 1);
        assert_eq!(custody_group_count(next_answer(&mut answers).await), 1);
    }

    /// The same range, arriving the other way: a link started on a spec watch that already
    /// holds it answers from it before any probe has been made, which is what a beacon node
    /// that asks for metadata the moment it connects reads.
    #[tokio::test(flavor = "multi_thread")]
    async fn custody_range_the_link_starts_with_reaches_the_metadata_answer() {
        let mut bn = FakeBn::start().await;
        // The probe cannot answer, so nothing but the starting snapshot can set the range.
        bn.set_spec_response(ResponseTemplate::new(503)).await;
        let mut answers = bn.responses();
        let spec = SpecSnapshot {
            custody_requirement: 1,
            number_of_custody_groups: 1,
            ..SpecSnapshot::MAINNET
        };
        let harness = spawn_with_spec(
            link_config(&bn),
            &bn,
            &node_key(&tempfile::tempdir().unwrap()),
            spec,
        );
        bn.wait_for(|e| matches!(e, FakeBnEvent::Connected(_)))
            .await;

        bn.request_metadata().await;

        assert_eq!(custody_group_count(next_answer(&mut answers).await), 1);
        drop(harness);
    }

    /// The count in a metadata answer, which is always v3 over the wire.
    fn custody_group_count(answer: RpcAnswer) -> u64 {
        let RpcAnswer::MetaData(metadata) = &answer else {
            panic!("not a metadata answer: {answer:?}");
        };
        let MetaData::V3(metadata) = metadata.as_ref() else {
            panic!("not metadata v3: {metadata:?}");
        };
        metadata.custody_group_count
    }

    /// The whole path T-014 feeds: the beacon node subscribes, the mirror turns that into a
    /// new advertised set, and the sidecar's next ping reply carries a sequence number one
    /// higher, with the metadata behind it showing the subnet.
    #[tokio::test(flavor = "multi_thread")]
    async fn subscription_change_bumps_seq_number_seen_by_fake_bn_on_the_next_ping() {
        let mut bn = FakeBn::start().await;
        let mut answers = bn.responses();
        let (commands, commands_rx) = mpsc::channel(64);
        let (spec_tx, spec_rx) = spec_watch();
        let (sets, sets_rx) = watch::channel(SubscriptionSets::default());
        let lanes = ClassLanes::new(Arc::new(Counts::default()));
        let link = BnLink::spawn(
            link_config(&bn),
            &node_key(&tempfile::tempdir().unwrap()),
            BnClient::new(bn.http_addr(), Duration::from_secs(2)),
            &mut Registry::default(),
            lanes.pusher(),
            spec_tx,
            sets_rx,
            commands_rx,
        );
        let mirror = crate::mirror::run(link.events, commands, sets, spec_rx);
        bn.wait_for(|e| matches!(e, FakeBnEvent::Connected(_)))
            .await;
        ping_until(&bn, &mut answers, 0).await;

        bn.subscribe(ATTESTATION_TOPIC).await;

        ping_until(&bn, &mut answers, 1).await;
        bn.request_metadata().await;
        let answer = next_answer(&mut answers).await;
        let RpcAnswer::MetaData(metadata) = &answer else {
            panic!("not a metadata answer: {answer:?}");
        };
        assert!(metadata.attnets().get(7).unwrap());
        mirror.abort();
    }

    /// The beacon node's farewell. Lighthouse writes the goodbye and closes the connection
    /// behind it, so whether the sidecar reads that last request before the stream goes with
    /// the connection is a race no wire rule settles; what holds either way is that the link
    /// sees the close and T-013's backoff brings it back to the same fake. What the sidecar
    /// does with a goodbye it does read is `goodbye_is_reported_with_its_reason`.
    #[tokio::test(flavor = "multi_thread")]
    async fn goodbye_from_fake_bn_closes_and_the_link_reconnects() {
        let mut bn = FakeBn::start().await;
        let (mut harness, _answers) = connected(&mut bn).await;
        wait_for(&mut harness.link.events, |e| {
            matches!(e, BnEvent::Connected { .. })
        })
        .await;

        bn.send_goodbye(GoodbyeReason::TooManyPeers).await;

        wait_for(&mut harness.link.events, |e| *e == BnEvent::Disconnected).await;
        let back = wait_for(&mut harness.link.events, |e| {
            matches!(e, BnEvent::Connected { .. })
        })
        .await;
        assert_eq!(
            back,
            BnEvent::Connected {
                peer_id: bn.peer_id()
            }
        );
        assert!(harness.link.connected.load(Ordering::Relaxed));
    }

    /// The same farewell as an ordinary request, which leaves Lighthouse's handler active and
    /// its connection open, so the disconnect that follows can only be the sidecar's own.
    #[tokio::test(flavor = "multi_thread")]
    async fn goodbye_request_makes_the_sidecar_close_the_connection() {
        let mut bn = FakeBn::start().await;
        let (mut harness, _answers) = connected(&mut bn).await;
        wait_for(&mut harness.link.events, |e| {
            matches!(e, BnEvent::Connected { .. })
        })
        .await;

        bn.send_goodbye_request(GoodbyeReason::ClientShutdown).await;

        wait_for(&mut harness.link.events, |e| *e == BnEvent::Disconnected).await;
    }

    /// A protocol the sidecar registers so the negotiation succeeds and refuses so the beacon
    /// node gets a well-formed answer. Lighthouse reads the result code and reports it as an
    /// error for the request, not as a broken peer.
    #[tokio::test(flavor = "multi_thread")]
    async fn fake_bn_blocks_by_range_request_gets_resource_unavailable() {
        let mut bn = FakeBn::start().await;
        let (harness, mut answers) = connected(&mut bn).await;

        bn.request_blocks_by_range(0, 4).await;

        let answer = next_answer(&mut answers).await;
        let RpcAnswer::Error(text) = &answer else {
            panic!("blocks by range was answered: {answer:?}");
        };
        assert!(text.contains("ResourceUnavailable"), "{text}");
        assert!(text.contains("BlocksByRange"), "{text}");
        drop(harness);
    }

    /// The behaviour is registered inbound only, so there is no path that opens an outbound
    /// stream. Two seconds of a live link, with one request answered so the link is doing
    /// something, and the beacon node is asked for nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn sidecar_never_initiates_a_request() {
        let mut bn = FakeBn::start().await;
        let mut inbound = bn.inbound_requests();
        let (harness, mut answers) = connected(&mut bn).await;
        bn.send_status(bn_status()).await;
        next_answer(&mut answers).await;

        tokio::time::sleep(Duration::from_secs(2)).await;

        assert_eq!(inbound.try_recv().ok(), None);
        assert!(harness.link.connected.load(Ordering::Relaxed));
    }

    /// The fake runs Lighthouse's own idle timeout and the sidecar never grafts it into a
    /// gossipsub mesh, so what holds a silent link open is the request-response handler on
    /// each side. Twelve seconds of nothing, and the link is still there and still answers.
    #[tokio::test(flavor = "multi_thread")]
    async fn quiet_link_survives_the_fake_bns_ten_second_idle_timeout() {
        let mut bn = FakeBn::start().await;
        let (harness, mut answers) = connected(&mut bn).await;

        tokio::time::sleep(IDLE_TIMEOUT + Duration::from_secs(2)).await;

        assert!(harness.link.connected.load(Ordering::Relaxed));
        bn.send_ping(0).await;
        assert_eq!(next_answer(&mut answers).await, RpcAnswer::Pong(0));
    }

    /// The one line T-045 writes to `/run/fleet-overlay/lighthouse.env`, which the Lighthouse
    /// unit reads with `EnvironmentFile=-` and the operator appends to `ExecStart`.
    #[test]
    fn env_line_carries_both_flags() {
        let peer_id = node_key(&tempfile::tempdir().unwrap()).peer_id();
        let listen: Multiaddr = "/ip4/127.0.0.1/tcp/7787".parse().unwrap();

        let line = lighthouse_env_line(&peer_id, &listen);

        assert_eq!(
            line,
            format!(
                "FLEET_OVERLAY_TRUSTED_PEER_ARGS=--trusted-peers {peer_id} \
                 --libp2p-addresses /ip4/127.0.0.1/tcp/7787/p2p/{peer_id}"
            )
        );
    }

    #[test]
    fn lane_for_takes_known_large_names_by_prefix_and_others_by_size() {
        let topic = |name: &str| format!("/eth2/6a95a1a9/{name}/ssz_snappy");
        let threshold = overlay_core::topic::UNKNOWN_LARGE_THRESHOLD_BYTES;

        for name in ["beacon_block", "data_column_sidecar_127", "blob_sidecar_3"] {
            assert_eq!(lane_for(&topic(name), 1), Class::Large, "{name}");
        }
        for name in [
            "beacon_attestation_63",
            "beacon_aggregate_and_proof",
            "sync_committee_contribution_and_proof",
            "execution_payload",
        ] {
            assert_eq!(
                lane_for(&topic(name), threshold - 1),
                Class::Small,
                "{name}"
            );
            assert_eq!(lane_for(&topic(name), threshold), Class::Large, "{name}");
        }
        assert_eq!(lane_for("not a topic", 1), Class::Small);
        assert_eq!(lane_for("not a topic", threshold), Class::Large);
    }

    #[test]
    fn link_config_from_bn_parses_the_address_and_uses_the_5_3_backoff() {
        let cfg = LinkConfig::from_config(&Bn::default()).unwrap();

        assert_eq!(cfg.libp2p_addr.to_string(), "/ip4/127.0.0.1/tcp/9000");
        assert_eq!(cfg.backoff_min, Duration::from_millis(500));
        assert_eq!(cfg.backoff_max, Duration::from_secs(30));
        assert!(cfg.gossip.idontwant_on_publish);
        assert!(
            LinkConfig::from_config(&Bn {
                libp2p_addr: "127.0.0.1:9000".to_owned(),
                ..Bn::default()
            })
            .is_err()
        );
    }

    /// The burst the capacity is sized for: the fake holds as many subscriptions as the
    /// channel has slots when the link connects, and nothing reads the events. Connected
    /// takes one, so at least one Subscribed is dropped and counted.
    #[tokio::test(flavor = "multi_thread")]
    async fn full_control_channel_drops_the_event_and_counts_control() {
        let bn = FakeBn::start().await;
        for i in 0..CONTROL_CHANNEL_CAPACITY {
            bn.subscribe(&format!("/eth2/6a95a1a9/topic_{i}/ssz_snappy"))
                .await;
        }
        let mut harness = spawn(link_config(&bn), &bn);

        tokio::time::timeout(WAIT, async {
            while harness.stats.control.load(Ordering::Relaxed) == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("no control drop was counted");

        assert!(matches!(
            next_event(&mut harness.link.events).await,
            BnEvent::Connected { .. }
        ));
    }
}
