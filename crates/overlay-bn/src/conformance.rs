//! CL-N2's conformance suite: the six Lighthouse behaviours the design leans on that no
//! specification promises, one named test each, so a Lighthouse release that changes one
//! fails by name instead of degrading the fleet quietly.
//!
//! | CL-N2 | Assumption | Test |
//! |---|---|---|
//! | (1) | a trusted peer is admitted whenever the beacon node is under its inbound cap, is dialled by the beacon node through `--libp2p-addresses` at startup and through `add_peer` on demand under the outbound cap, and is never pruned once connected (MD-01) | under the cap and never pruned: `matrix_trusted_peer_is_admitted_under_the_inbound_cap_and_never_pruned`, `tests/matrix.rs`; the beacon node dialling: T-020's test 10 |
//! | (2) | a trusted peer is not disconnected or banned after one invalid message and a period of duplicates only | `matrix_trusted_peer_survives_one_invalid_message_and_a_period_of_duplicates_only`, `tests/matrix.rs` |
//! | (3) | the BN forwards a validated message to an explicit peer that is subscribed but not in the mesh | `bn_forwards_validated_message_to_a_subscribed_explicit_peer_outside_its_mesh`, here |
//! | (4) | the BN's `publish` reaches an explicit peer on a topic the BN is not subscribed to, and the sidecar's subscription is still required | `bn_publish_reaches_explicit_peer_on_a_topic_the_bn_is_not_subscribed_to_and_needs_the_sidecar_subscription`, here |
//! | (5) | the BN honours IDONTWANT from an explicit peer, and with `gossipsub-partial-messages` still sends full messages to a peer that did not negotiate them | `bn_honours_idontwant_from_explicit_peer_and_sends_full_messages_without_partial_message_negotiation`, here |
//! | (6) | message-id agreement | `published_message_id_matches_fake_bn_for_random_payloads`, `link.rs` (T-013) |
//!
//! The tests here run against [`FakeBn`], the fork's gossipsub under Lighthouse's own
//! transport, transform and parameters. They prove the fork's behaviour, which the beacon node
//! compiles unchanged; whether a Lighthouse release still configures it that way is what the
//! matrix checks with a real binary.

use std::sync::Arc;
use std::time::Duration;

use libp2p::PeerId;
use libp2p::gossipsub::{MessageId, PublishError};
use overlay_core::lanes::ClassLanes;
use overlay_core::topic::{Class, SubscriptionSets};
use prometheus_client::registry::Registry;
use tokio::sync::{mpsc, oneshot, watch};

use crate::bn_http::BnClient;
use crate::link::{BnCommand, BnEvent, BnLink, BnMessage};
use crate::spec::spec_watch;
use crate::testutil::{FakeBn, FakeBnEvent, link_config, node_key};

/// Long enough for a dial, a heartbeat and a gossipsub exchange on a loaded CI box.
const WAIT: Duration = Duration::from_secs(5);
const BLOCK: &str = "/eth2/6a95a1a9/beacon_block/ssz_snappy";

/// A link to a fake, with the test's ends of its channels.
struct Sidecar {
    peer_id: PeerId,
    link: BnLink,
    commands: mpsc::Sender<BnCommand>,
    lanes: ClassLanes<BnMessage>,
}

/// Spawns a link to `bn` and waits for it to connect.
async fn connected_sidecar(bn: &FakeBn) -> Sidecar {
    let (commands, commands_rx) = mpsc::channel(64);
    let (spec_tx, _spec) = spec_watch();
    let (_sets, sets) = watch::channel(SubscriptionSets::default());
    let lanes = ClassLanes::new(Arc::new(()));
    let key = node_key(&tempfile::tempdir().unwrap());
    let link = BnLink::spawn(
        link_config(bn),
        &key,
        BnClient::new(bn.http_addr(), Duration::from_secs(2)),
        &mut Registry::default(),
        lanes.pusher(),
        spec_tx,
        sets,
        commands_rx,
    );
    let mut sidecar = Sidecar {
        peer_id: key.peer_id(),
        link,
        commands,
        lanes,
    };
    sidecar
        .wait_for(|e| matches!(e, BnEvent::Connected { .. }))
        .await;
    sidecar
}

impl Sidecar {
    async fn wait_for(&mut self, mut wanted: impl FnMut(&BnEvent) -> bool) -> BnEvent {
        tokio::time::timeout(WAIT, async {
            loop {
                let event = self.link.events.recv().await.expect("the link ended");
                if wanted(&event) {
                    return event;
                }
            }
        })
        .await
        .expect("the awaited link event never arrived")
    }

    /// Subscribes the link to `topic` and waits until the fake has seen the subscription.
    async fn subscribe(&self, bn: &mut FakeBn, topic: &str) {
        self.commands
            .send(BnCommand::Subscribe(topic.to_owned()))
            .await
            .unwrap();
        let own = self.peer_id;
        bn.wait_for(|e| {
            matches!(e, FakeBnEvent::Subscribed { peer, topic: t } if *peer == own && t == topic)
        })
        .await;
    }

    async fn recv_large(&mut self) -> BnMessage {
        tokio::time::timeout(WAIT, self.lanes.recv_from(Class::Large))
            .await
            .expect("nothing arrived on the large lane in time")
    }

    async fn publish(&self, topic: &str, data: &[u8]) -> MessageId {
        let (reply, answer) = oneshot::channel();
        self.commands
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
            .unwrap()
    }

    /// Whether the large lane stays empty for a second.
    async fn nothing_large_within_a_second(&mut self) -> bool {
        tokio::time::timeout(Duration::from_secs(1), self.lanes.recv_from(Class::Large))
            .await
            .is_err()
    }
}

fn decompress(data: &[u8]) -> Vec<u8> {
    snap::raw::Decoder::new().decompress_vec(data).unwrap()
}

/// CL-N2 (3). A public peer of the fake, grafted into its mesh for the topic, publishes; the
/// fake validates and forwards to the sidecar, which is subscribed, explicit and never
/// grafted: the fork rejects GRAFT to or from an explicit peer, so the sidecar's mesh
/// parameters are bookkeeping and the forward can only be the explicit-peer path.
#[tokio::test(flavor = "multi_thread")]
async fn bn_forwards_validated_message_to_a_subscribed_explicit_peer_outside_its_mesh() {
    let mut bn = FakeBn::start().await;
    let mut sidecar = connected_sidecar(&bn).await;
    bn.subscribe(BLOCK).await;
    sidecar.subscribe(&mut bn, BLOCK).await;
    let public = bn.attach_public_peer(BLOCK).await;
    tokio::time::timeout(WAIT, async {
        while !bn.mesh_peers(BLOCK).await.contains(&public.peer_id()) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the fake never grafted its public peer");

    let id = public.publish(BLOCK, b"from the public network").await;
    let forwarded = sidecar.recv_large().await;

    assert_eq!(
        (forwarded.id, forwarded.source, forwarded.topic.as_str()),
        (id, bn.peer_id(), BLOCK)
    );
    assert_eq!(decompress(&forwarded.data), b"from the public network");
    let mesh = bn.mesh_peers(BLOCK).await;
    assert!(mesh.contains(&public.peer_id()), "{mesh:?}");
    assert!(!mesh.contains(&sidecar.peer_id), "{mesh:?}");
}

/// CL-N2 (4). The fake never subscribes to the topic. Before the sidecar subscribes, the
/// fake's `publish` has no recipient and refuses; after, the message reaches the sidecar
/// through the explicit-peer path, which is the only one a non-subscribed publisher has
/// besides fanout, and fanout never holds an explicit peer.
#[tokio::test(flavor = "multi_thread")]
async fn bn_publish_reaches_explicit_peer_on_a_topic_the_bn_is_not_subscribed_to_and_needs_the_sidecar_subscription()
 {
    let mut bn = FakeBn::start().await;
    let mut sidecar = connected_sidecar(&bn).await;

    let refused = bn.publish(BLOCK, b"nobody listens").await;
    let heard_nothing = sidecar.nothing_large_within_a_second().await;
    sidecar.subscribe(&mut bn, BLOCK).await;
    let id = bn.publish(BLOCK, b"the sidecar listens").await.unwrap();
    let delivered = sidecar.recv_large().await;

    assert!(
        matches!(refused, Err(PublishError::NoPeersSubscribedToTopic)),
        "{refused:?}"
    );
    assert!(heard_nothing);
    assert_eq!((delivered.id, delivered.source), (id, bn.peer_id()));
    assert_eq!(decompress(&delivered.data), b"the sidecar listens");
}

/// CL-N2 (5). With `idontwant_on_publish` the sidecar sends an IDONTWANT ahead of any
/// publish above the 1000-byte threshold, to every recipient including its explicit peer;
/// the fake counts it in the fork's `idontwant_msgs` metric and records the id against the
/// sidecar, which is what its `forward_msg` consults. That is as far as a fake can take
/// "honours": the fork skips a peer that announced IDONTWANT for the id, but every way the
/// sidecar can send one also hands the fake the message itself (or makes the sidecar an
/// originating peer of it), so no forward to the sidecar is ever due and the skip cannot be
/// seen from outside. What is asserted is the wire exchange and the count; the skip is the
/// fork's code, which the beacon node compiles unchanged.
///
/// The other half: both sides negotiate `/meshsub/1.3.0`, but neither registers the topic for
/// partial messages, so a payload above the threshold arrives as one whole message with the
/// beacon node's compressed bytes untouched.
#[tokio::test(flavor = "multi_thread")]
async fn bn_honours_idontwant_from_explicit_peer_and_sends_full_messages_without_partial_message_negotiation()
 {
    let mut bn = FakeBn::start_with_metrics().await;
    let mut received = bn.received();
    let mut sidecar = connected_sidecar(&bn).await;
    bn.subscribe(BLOCK).await;
    sidecar.subscribe(&mut bn, BLOCK).await;
    let incompressible: Vec<u8> = (0..4096u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect();
    let compressed = snap::raw::Encoder::new()
        .compress_vec(&incompressible)
        .unwrap();
    assert!(compressed.len() > crate::gossip::IDONTWANT_MESSAGE_SIZE_THRESHOLD);

    let id = sidecar.publish(BLOCK, &compressed).await;
    let (topic, data, bn_id) = tokio::time::timeout(WAIT, received.recv())
        .await
        .expect("the fake never received the publish")
        .unwrap();
    let idontwants = bn.idontwant_msgs();
    let bn_id_back = bn.publish(BLOCK, &incompressible[..2048]).await.unwrap();
    let whole = sidecar.recv_large().await;

    assert_eq!(
        (topic.as_str(), data, bn_id),
        (BLOCK, incompressible.clone(), id)
    );
    assert!(idontwants > 0, "{}", bn.metrics_text());
    assert_eq!(whole.id, bn_id_back);
    assert_eq!(
        whole.data,
        snap::raw::Encoder::new()
            .compress_vec(&incompressible[..2048])
            .unwrap()
    );
}
