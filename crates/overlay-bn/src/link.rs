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
use libp2p::swarm::{ConnectionError, Swarm, SwarmEvent};
use libp2p::{Multiaddr, PeerId, SwarmBuilder, Transport, multiaddr, noise, tcp, yamux};
use overlay_core::backoff::Backoff;
use overlay_core::config::Bn;
use overlay_core::lanes::LanePusher;
use overlay_core::topic::{Class, UNKNOWN_LARGE_THRESHOLD_BYTES};
use prometheus_client::registry::Registry;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::bn_http::{BnClient, BnHttpError, PeerInfo};
use crate::gossip::{BnLinkConfig, GossipBehaviour, build_behaviour};
use crate::node_key::NodeKey;
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
    /// once; every later one waits for the backoff. `registry` receives gossipsub's metrics.
    pub fn spawn(
        cfg: LinkConfig,
        node_key: &NodeKey,
        bn_client: BnClient,
        registry: &mut Registry,
        lanes: LanePusher<BnMessage>,
        spec: watch::Sender<SpecSnapshot>,
        commands: mpsc::Receiver<BnCommand>,
    ) -> Self {
        let connected = Arc::new(AtomicBool::new(false));
        let (control, events) = mpsc::channel(CONTROL_CHANNEL_CAPACITY);
        let link = Link {
            swarm: build_swarm(&cfg.gossip, node_key, registry),
            backoff: Backoff::new(cfg.backoff_min, cfg.backoff_max),
            own_peer_id: node_key.peer_id(),
            cfg,
            bn_client,
            control,
            lanes,
            spec,
            commands,
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
    swarm: Swarm<GossipBehaviour>,
    cfg: LinkConfig,
    bn_client: BnClient,
    own_peer_id: PeerId,
    control: mpsc::Sender<BnEvent>,
    lanes: LanePusher<BnMessage>,
    spec: watch::Sender<SpecSnapshot>,
    commands: mpsc::Receiver<BnCommand>,
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

    fn on_swarm_event(&mut self, event: SwarmEvent<gossipsub::Event>) {
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
            SwarmEvent::Behaviour(gossipsub::Event::Message {
                propagation_source,
                message_id,
                message,
            }) => {
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
            SwarmEvent::Behaviour(gossipsub::Event::Subscribed { peer_id, topic, .. }) => {
                self.emit(BnEvent::Subscribed {
                    peer: peer_id,
                    topic: topic.into_string(),
                });
            }
            SwarmEvent::Behaviour(gossipsub::Event::Unsubscribed { peer_id, topic }) => {
                self.emit(BnEvent::Unsubscribed {
                    peer: peer_id,
                    topic: topic.into_string(),
                });
            }
            _ => {}
        }
    }

    /// Makes the beacon node the explicit peer, reports it, and starts the HTTP probe, which
    /// runs beside the swarm rather than in front of it.
    fn on_connected(&mut self, peer_id: PeerId) {
        self.swarm.behaviour_mut().add_explicit_peer(&peer_id);
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
        self.swarm.behaviour_mut().remove_explicit_peer(&peer_id);
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
            self.spec.send_replace(snapshot);
        }
        self.emit(BnEvent::BnInfo {
            version: version.ok(),
            trusted: peer_info.ok().flatten().map(|peer| peer.is_trusted),
        });
    }

    fn on_command(&mut self, command: BnCommand) {
        let gossip = self.swarm.behaviour_mut();
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

/// Polls the future in `slot` and stays pending while there is none, so an unarmed timer is
/// an arm of the `select!` that never fires.
async fn armed<T>(slot: &mut Pending<T>) -> T {
    match slot {
        Some(future) => future.await,
        None => std::future::pending().await,
    }
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
) -> Swarm<GossipBehaviour> {
    let Ok(builder) = SwarmBuilder::with_existing_identity(node_key.keypair())
        .with_tokio()
        .with_other_transport(|keypair| {
            tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
                .upgrade(Version::V1)
                .authenticate(noise::Config::new(keypair).expect("an Ed25519 keypair can sign"))
                .multiplex(yamux::Config::default())
                .timeout(DIAL_TIMEOUT)
        });
    let Ok(builder) = builder.with_behaviour(|_| build_behaviour(cfg, registry));
    builder
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::MAX))
        .build()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use lighthouse_network::rpc::StatusMessage;
    use lighthouse_network::rpc::methods::StatusMessageV2;
    use overlay_core::lanes::{ClassLanes, LaneStats, SMALL_LANE_CAPACITY};
    use overlay_core::msgid;
    use overlay_core::topic::{Class, TopicKind};
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
    use crate::testutil::{FakeBn, FakeBnEvent, RpcAnswer, link_config, node_key, ok_json};

    /// Long enough for a dial, a noise handshake and a gossipsub exchange on a loaded CI box,
    /// short enough that a test which waits in vain still ends inside its 5 s budget.
    const WAIT: Duration = Duration::from_secs(3);
    const BLOCK_TOPIC: &str = "/eth2/6a95a1a9/beacon_block/ssz_snappy";
    const ATTESTATION_TOPIC: &str = "/eth2/6a95a1a9/beacon_attestation_7/ssz_snappy";
    /// `hello`, snappy-compressed: T-006's spec vector input.
    const HELLO_SNAPPY: &[u8] = &[0x05, 0x10, 0x68, 0x65, 0x6c, 0x6c, 0x6f];

    /// A running link and the test's ends of its channels.
    struct Harness {
        link: BnLink,
        commands: mpsc::Sender<BnCommand>,
        spec: watch::Receiver<SpecSnapshot>,
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
        let (commands, commands_rx) = mpsc::channel(64);
        let (spec_tx, spec) = spec_watch();
        let stats = Arc::new(Counts::default());
        let lanes = ClassLanes::new(stats.clone());
        let link = BnLink::spawn(
            cfg,
            node_key,
            BnClient::new(bn.http_addr(), Duration::from_secs(2)),
            &mut Registry::default(),
            lanes.pusher(),
            spec_tx,
            commands_rx,
        );
        Harness {
            link,
            commands,
            spec,
            lanes,
            stats,
        }
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
