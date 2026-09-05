//! Test fixtures for the BN link.
//!
//! [`FakeBn`] is a beacon node as far as the sidecar can tell: Lighthouse's own transport and
//! snappy transform under its gossipsub parameters, listening on loopback, next to a mock of
//! the four HTTP endpoints the link reads. A test points a real link at it:
//!
//! ```ignore
//! let mut bn = FakeBn::start().await;
//! let client = BnClient::new(bn.http_addr(), Duration::from_secs(2));
//! let link = BnLink::spawn(link_config(bn.addr()), &node_key, client, ..);
//! // BnEvent::Connected { peer_id: bn.peer_id() } arrives on the control channel.
//! bn.subscribe(TOPIC).await;
//! // BnEvent::Subscribed { .. } arrives; now a publish from the link reaches the fake:
//! let (topic, decompressed, id) = bn.received().recv().await.unwrap();
//! ```
//!
//! The two-swarm helpers at the bottom ([`connected_pair`], [`subscribe_both`],
//! [`next_message`]) join two of the sidecar's own behaviours over the memory transport, for
//! tests that need the protocol code and no beacon node at all.

use std::time::Duration;

use libp2p::core::transport::MemoryTransport;
use libp2p::core::upgrade::Version;
use libp2p::futures::StreamExt;
use libp2p::gossipsub::{
    self, AllowAllSubscriptionFilter, IdentTopic, Message, MessageAcceptance, MessageAuthenticity,
    MessageId, ValidationMode,
};
use libp2p::swarm::{Swarm, SwarmEvent};
use libp2p::{Multiaddr, PeerId, SwarmBuilder, Transport, noise, yamux};
use lighthouse_network::types::SnappyTransform;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use types::ChainSpec;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::gossip::GossipBehaviour;

/// Long enough for a noise handshake plus a few gossipsub round trips on a loaded CI box.
const WAIT: Duration = Duration::from_secs(5);

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
}

/// A message the fake received: the topic, the payload as its snappy transform decompressed
/// it, and the id its copy of Lighthouse's id function gave it.
pub type Received = (String, Vec<u8>, MessageId);

type LighthouseBehaviour = gossipsub::Behaviour<SnappyTransform, AllowAllSubscriptionFilter>;

enum Cmd {
    Subscribe(String),
}

impl FakeBn {
    /// A fake on a fresh loopback port with a fresh key, next to a fresh mock server.
    pub async fn start() -> Self {
        Self::start_on(0, MockServer::start().await).await
    }

    /// A fake with a fresh key on `port` (0 for any), served by `http`, whose identity
    /// endpoint is repointed at the new key. This is how a test restarts the beacon node
    /// behind the HTTP endpoint a link was configured with.
    pub async fn start_on(port: u16, http: MockServer) -> Self {
        let mut swarm = lighthouse_swarm();
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
        let task = tokio::spawn(drive(swarm, command_rx, received_tx));
        let bn = Self {
            task,
            peer_id,
            port,
            http,
            commands,
            received: Some(received),
        };
        bn.remount().await;
        bn
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

    /// Subscribes the fake to `topic`; the link sees `BnEvent::Subscribed` once it has.
    pub async fn subscribe(&self, topic: &str) {
        self.commands
            .send(Cmd::Subscribe(topic.to_owned()))
            .await
            .unwrap();
    }

    /// Everything the fake receives, in order. Taken once per fake.
    pub fn received(&mut self) -> mpsc::Receiver<Received> {
        self.received.take().expect("received() is taken once")
    }

    /// Drops the swarm, which closes its connections and frees the port, and hands back the
    /// mock server so a replacement can be started behind the same HTTP endpoint.
    pub async fn shutdown(self) -> MockServer {
        self.task.abort();
        let _ = self.task.await;
        self.http
    }

    async fn remount(&self) {
        self.http.reset().await;
        let spec = json!({"data": {
            "DATA_COLUMN_SIDECAR_SUBNET_COUNT": "128",
            "NUMBER_OF_COLUMNS": "128",
            "NUMBER_OF_CUSTODY_GROUPS": "128",
            "MAX_PAYLOAD_SIZE": "10485760",
            "SECONDS_PER_SLOT": "12",
            "SLOTS_PER_EPOCH": "32"
        }});
        for (at, response) in [
            (
                "/eth/v1/node/identity",
                json!({"data": {"peer_id": self.peer_id.to_string()}}),
            ),
            (
                "/eth/v1/node/version",
                json!({"data": {"version": "Lighthouse/v8.2.2-e423a66/x86_64-linux"}}),
            ),
            ("/eth/v1/config/spec", spec),
            ("/lighthouse/peers", json!([])),
        ] {
            Mock::given(method("GET"))
                .and(path(at))
                .respond_with(ResponseTemplate::new(200).set_body_json(response))
                .mount(&self.http)
                .await;
        }
    }
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
async fn drive(
    mut swarm: Swarm<LighthouseBehaviour>,
    mut commands: mpsc::Receiver<Cmd>,
    received: mpsc::Sender<Received>,
) {
    loop {
        tokio::select! {
            event = swarm.select_next_some() => match event {
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    swarm.behaviour_mut().add_explicit_peer(&peer_id);
                }
                SwarmEvent::Behaviour(gossipsub::Event::Message {
                    propagation_source,
                    message_id,
                    message,
                }) => {
                    swarm.behaviour_mut().report_message_validation_result(
                        &message_id,
                        &propagation_source,
                        MessageAcceptance::Accept,
                    );
                    let _ = received.try_send((message.topic.into_string(), message.data, message_id));
                }
                _ => {}
            },
            command = commands.recv() => match command {
                Some(Cmd::Subscribe(topic)) => {
                    swarm.behaviour_mut().subscribe(&IdentTopic::new(topic)).unwrap();
                }
                None => return,
            },
        }
    }
}

/// Lighthouse's swarm as `service/mod.rs` builds it for a node without QUIC or mplex: its
/// `build_transport` (TCP nodelay, noise, yamux, 10 s upgrade timeout) and its 10 s idle
/// connection timeout (`service/mod.rs:498`).
fn lighthouse_swarm() -> Swarm<LighthouseBehaviour> {
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
        .with_behaviour(|_| lighthouse_behaviour())
        .unwrap()
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(10)))
        .build()
}

/// The behaviour as `service/mod.rs:341-350` constructs it, minus the whitelist filter (every
/// topic a test uses is one the beacon node would allow) and the peer scoring (trusted peers
/// are exempt from it anyway).
fn lighthouse_behaviour() -> LighthouseBehaviour {
    let spec = ChainSpec::mainnet();
    gossipsub::Behaviour::new_with_subscription_filter_and_transform(
        MessageAuthenticity::Anonymous,
        lighthouse_gossipsub_config(&spec),
        AllowAllSubscriptionFilter::default(),
        SnappyTransform::new(spec.max_payload_size as usize, spec.max_compressed_len()),
    )
    .unwrap()
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

/// The `prefix` and `gossip_message_id` closures of `gossipsub_config`
/// (`config.rs:459-491`), verbatim on their altair branch: every live fork has altair enabled,
/// so the pre-altair branch and the fork-context lookup that selects it are left out.
/// `message.data` is what the snappy transform already decompressed.
fn lighthouse_message_id(message: &gossipsub::Message) -> MessageId {
    let prefix = ChainSpec::mainnet().message_domain_valid_snappy;
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
