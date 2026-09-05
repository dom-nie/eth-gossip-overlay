//! Two gossipsub behaviours joined in-process over libp2p's memory transport, so a test can
//! push a message through the real protocol code with nothing on the network. Every BN-link
//! ticket needs this pair; T-013 grows the far side into `FakeBn`.
//!
//! ```ignore
//! let mut registry = Registry::default();
//! let (mut sidecar, mut bn) = testutil::connected_pair(
//!     build_behaviour(&cfg, &mut registry),
//!     build_behaviour(&cfg, &mut registry),
//! )
//! .await;
//! let topic = testutil::subscribe_both(&mut sidecar, &mut bn, TOPIC).await;
//! sidecar.behaviour_mut().publish(topic, compressed.clone()).unwrap();
//! let received = testutil::next_message(&mut sidecar, &mut bn).await;
//! assert_eq!(received.data, compressed);
//! ```

use std::time::Duration;

use libp2p::core::transport::MemoryTransport;
use libp2p::core::upgrade::Version;
use libp2p::futures::StreamExt;
use libp2p::gossipsub::{self, IdentTopic, Message};
use libp2p::swarm::{Swarm, SwarmEvent};
use libp2p::{SwarmBuilder, Transport, noise, yamux};

use crate::gossip::GossipBehaviour;

/// Long enough for a noise handshake plus a few gossipsub round trips on a loaded CI box.
const WAIT: Duration = Duration::from_secs(5);

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
