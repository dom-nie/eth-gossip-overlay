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
use std::time::Duration;

use libp2p::core::upgrade::Version;
use libp2p::futures::StreamExt;
use libp2p::gossipsub::{self, IdentTopic, MessageAcceptance, MessageId, PublishError};
use libp2p::swarm::{Swarm, SwarmEvent};
use libp2p::{Multiaddr, PeerId, SwarmBuilder, Transport, multiaddr, noise, tcp, yamux};
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
        let link = Link {
            swarm: build_swarm(&cfg.gossip, node_key, registry),
            cfg,
            bn_client,
            control,
            commands,
            reconnect: None,
        };
        Self {
            task: tokio::spawn(link.run()),
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

    fn on_identity(&mut self, identity: Result<PeerId, BnHttpError>) {
        let peer_id = match identity {
            Ok(peer_id) => peer_id,
            Err(err) => {
                tracing::warn!(%err, "beacon node identity unavailable");
                return;
            }
        };
        let addr = match self.cfg.libp2p_addr.clone().with_p2p(peer_id) {
            Ok(addr) => addr,
            Err(addr) => {
                tracing::error!(%addr, %peer_id, "bn.libp2p_addr names another peer id");
                return;
            }
        };
        if let Err(err) = self.swarm.dial(addr) {
            tracing::warn!(%err, "dial refused");
        }
    }

    fn on_swarm_event(&mut self, event: SwarmEvent<gossipsub::Event>) {
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                self.swarm.behaviour_mut().add_explicit_peer(&peer_id);
                self.emit(BnEvent::Connected { peer_id });
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
    use std::time::Duration;

    use prometheus_client::registry::Registry;

    use super::*;
    use crate::bn_http::BnClient;
    use crate::gossip::BnLinkConfig;
    use crate::node_key::NodeKey;
    use crate::testutil::FakeBn;

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
        _dir: tempfile::TempDir,
    }

    fn node_key(dir: &tempfile::TempDir) -> NodeKey {
        NodeKey::load_or_create(&dir.path().join("node.key")).unwrap()
    }

    fn spawn(cfg: LinkConfig, bn: &FakeBn) -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let (control_tx, control) = mpsc::channel(64);
        let (commands, commands_rx) = mpsc::channel(64);
        let link = BnLink::spawn(
            cfg,
            &node_key(&dir),
            BnClient::new(bn.http_addr(), Duration::from_secs(2)),
            &mut Registry::default(),
            control_tx,
            commands_rx,
        );
        Harness {
            link,
            control,
            commands,
            _dir: dir,
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
}
