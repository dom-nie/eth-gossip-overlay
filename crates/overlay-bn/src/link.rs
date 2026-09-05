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
//! `nodelay`, noise, yamux, a 10 s upgrade timeout. No DNS layer, because the sidecar dials a
//! literal address, and no identify behaviour: Lighthouse ignores identify errors, so the
//! only cost is that the beacon node lists the sidecar's client as unknown.

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
use prometheus_client::registry::Registry;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::bn_http::{BnClient, BnHttpError};
use crate::gossip::{BnLinkConfig, GossipBehaviour, build_behaviour};
use crate::node_key::NodeKey;

/// The first delay before redialling a beacon node that went away; §5.3 uses the same
/// numbers for overlay reconnects.
pub const BACKOFF_MIN: Duration = Duration::from_millis(500);
/// The delay the backoff doubles up to.
pub const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// Lighthouse's own bound on the noise and yamux upgrade (`build_transport`).
const UPGRADE_TIMEOUT: Duration = Duration::from_secs(10);

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
}

impl BnLink {
    /// Builds the swarm under the node key and starts the task. The first dial happens at
    /// once; every later one waits for the backoff.
    pub fn spawn(
        cfg: LinkConfig,
        node_key: &NodeKey,
        bn_client: BnClient,
        registry: &mut Registry,
        control: mpsc::Sender<BnEvent>,
        commands: mpsc::Receiver<BnCommand>,
    ) -> Self {
        let connected = Arc::new(AtomicBool::new(false));
        let link = Link {
            swarm: build_swarm(&cfg.gossip, node_key, registry),
            backoff: Backoff::new(cfg.backoff_min, cfg.backoff_max),
            cfg,
            bn_client,
            control,
            commands,
            connected: connected.clone(),
            bn_peer: None,
            reconnect: None,
        };
        Self {
            task: tokio::spawn(link.run()),
            connected,
        }
    }
}

/// A future the loop polls only while it is armed.
type Pending<T> = Option<Pin<Box<dyn Future<Output = T> + Send>>>;

struct Link {
    swarm: Swarm<GossipBehaviour>,
    cfg: LinkConfig,
    bn_client: BnClient,
    control: mpsc::Sender<BnEvent>,
    commands: mpsc::Receiver<BnCommand>,
    connected: Arc<AtomicBool>,
    backoff: Backoff,
    /// The beacon node this link is connected to, while it is.
    bn_peer: Option<PeerId>,
    reconnect: Pending<Result<PeerId, BnHttpError>>,
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
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                self.swarm.behaviour_mut().add_explicit_peer(&peer_id);
                self.bn_peer = Some(peer_id);
                self.connected.store(true, Ordering::Relaxed);
                self.backoff.reset();
                self.emit(BnEvent::Connected { peer_id });
            }
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

    /// The explicit peer is removed before the redial so gossipsub does not dial it too, with
    /// no address, on its own schedule.
    fn on_closed(&mut self, peer_id: PeerId, cause: Option<ConnectionError>) {
        tracing::warn!(%peer_id, ?cause, "connection to the beacon node closed");
        self.swarm.behaviour_mut().remove_explicit_peer(&peer_id);
        if self.bn_peer.take().is_some() {
            self.connected.store(false, Ordering::Relaxed);
            self.emit(BnEvent::Disconnected);
        }
        self.retry_later();
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

    /// Hands `event` to the control channel without waiting. A full channel drops it and
    /// says so at error level: the consumer is not keeping up with a handful of events.
    fn emit(&self, event: BnEvent) {
        match self.control.try_send(event) {
            Ok(()) | Err(TrySendError::Closed(_)) => {}
            Err(TrySendError::Full(event)) => {
                tracing::error!(?event, "control channel full; event dropped");
            }
        }
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
                .timeout(UPGRADE_TIMEOUT)
        });
    let Ok(builder) = builder.with_behaviour(|_| build_behaviour(cfg, registry));
    builder
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::MAX))
        .build()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use prometheus_client::registry::Registry;
    use serde_json::json;
    use wiremock::{MockServer, ResponseTemplate};

    use super::*;
    use crate::bn_http::BnClient;
    use crate::gossip::BnLinkConfig;
    use crate::node_key::NodeKey;
    use crate::spec::spec_watch;
    use crate::testutil::{FakeBn, FakeBnEvent, ok_json};

    /// Long enough for a dial, a noise handshake and a gossipsub exchange on a loaded CI box,
    /// short enough that a test which waits in vain still ends inside its 5 s budget.
    const WAIT: Duration = Duration::from_secs(3);
    const BLOCK_TOPIC: &str = "/eth2/6a95a1a9/beacon_block/ssz_snappy";
    /// `hello`, snappy-compressed: T-006's spec vector input.
    const HELLO_SNAPPY: &[u8] = &[0x05, 0x10, 0x68, 0x65, 0x6c, 0x6c, 0x6f];

    fn link_config(bn: &FakeBn) -> LinkConfig {
        LinkConfig {
            libp2p_addr: bn.addr(),
            backoff_min: Duration::from_millis(10),
            backoff_max: Duration::from_millis(100),
            gossip: BnLinkConfig {
                idontwant_on_publish: true,
            },
        }
    }

    /// A running link and the test's ends of its channels.
    struct Harness {
        link: BnLink,
        control: mpsc::Receiver<BnEvent>,
        commands: mpsc::Sender<BnCommand>,
        spec: watch::Receiver<SpecSnapshot>,
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

    fn node_key(dir: &tempfile::TempDir) -> NodeKey {
        NodeKey::load_or_create(&dir.path().join("node.key")).unwrap()
    }

    /// A link under a fresh node key. The key file is read at spawn and not needed after.
    fn spawn(cfg: LinkConfig, bn: &FakeBn) -> Harness {
        spawn_with_key(cfg, bn, &node_key(&tempfile::tempdir().unwrap()))
    }

    fn spawn_with_key(cfg: LinkConfig, bn: &FakeBn, node_key: &NodeKey) -> Harness {
        let (control_tx, control) = mpsc::channel(64);
        let (commands, commands_rx) = mpsc::channel(64);
        let (spec_tx, spec) = spec_watch();
        let link = BnLink::spawn(
            cfg,
            node_key,
            BnClient::new(bn.http_addr(), Duration::from_secs(2)),
            &mut Registry::default(),
            control_tx,
            spec_tx,
            commands_rx,
        );
        Harness {
            link,
            control,
            commands,
            spec,
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

        let event = next_event(&mut harness.control).await;

        assert_eq!(
            event,
            BnEvent::Connected {
                peer_id: bn.peer_id()
            }
        );
        assert!(!harness.link.task.is_finished());
        drop(harness.commands);
    }

    /// The sidecar never subscribes here, so it has no mesh for the topic; the message reaches
    /// the fake only because it is the explicit peer.
    #[tokio::test(flavor = "multi_thread")]
    async fn link_adds_bn_as_explicit_peer() {
        let mut bn = FakeBn::start().await;
        let mut harness = spawn(link_config(&bn), &bn);
        let mut received = bn.received();
        bn.subscribe(BLOCK_TOPIC).await;
        wait_for(
            &mut harness.control,
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
            next_event(&mut harness.control).await,
            BnEvent::Connected { peer_id: old_id }
        );

        let port = bn.port();
        let http = bn.shutdown().await;
        assert_eq!(
            next_event(&mut harness.control).await,
            BnEvent::Disconnected
        );
        let bn = FakeBn::start_on(port, http).await;

        assert_ne!(bn.peer_id(), old_id);
        assert_eq!(
            next_event(&mut harness.control).await,
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

        wait_for(&mut harness.control, |e| {
            matches!(e, BnEvent::Connected { .. })
        })
        .await;
        assert!(gauge.load(Ordering::Relaxed));

        bn.shutdown().await;
        wait_for(&mut harness.control, |e| *e == BnEvent::Disconnected).await;
        assert!(!gauge.load(Ordering::Relaxed));
    }

    /// The first outage runs the backoff up to its 100 ms ceiling; after the reconnect, the
    /// second outage must redial within the 10 ms minimum again, jittered down to 5 ms.
    #[tokio::test(flavor = "multi_thread")]
    async fn backoff_resets_after_a_successful_connect_so_the_next_outage_starts_at_min() {
        let bn = FakeBn::start().await;
        let port = bn.port();
        let mut harness = spawn(link_config(&bn), &bn);
        wait_for(&mut harness.control, |e| {
            matches!(e, BnEvent::Connected { .. })
        })
        .await;

        let http = bn.shutdown().await;
        wait_for(&mut harness.control, |e| *e == BnEvent::Disconnected).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let bn = FakeBn::start_on(port, http).await;
        wait_for(&mut harness.control, |e| {
            matches!(e, BnEvent::Connected { .. })
        })
        .await;

        let http = bn.shutdown().await;
        wait_for(&mut harness.control, |e| *e == BnEvent::Disconnected).await;
        let before = identity_requests(&http).await;
        tokio::time::sleep(Duration::from_millis(40)).await;
        let after = identity_requests(&http).await;

        assert!(
            after > before,
            "no redial within 40 ms of the second outage"
        );
    }

    /// Two links from the same key file show the beacon node the same peer id, which is the
    /// id the node key reports; a key made elsewhere gives another, because nothing but the
    /// random file decides it.
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
        let other = node_key(&tempfile::tempdir().unwrap()).peer_id();
        assert_ne!(other, expected);
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

        wait_for(&mut harness.control, |e| {
            matches!(e, BnEvent::Connected { .. })
        })
        .await;
        let info = next_event(&mut harness.control).await;

        assert_eq!(
            info,
            BnEvent::BnInfo {
                version: Some("Lighthouse/v8.2.2".to_owned()),
                trusted: Some(true),
            }
        );
        assert_eq!(harness.spec.borrow().number_of_columns, 64);
    }
}
