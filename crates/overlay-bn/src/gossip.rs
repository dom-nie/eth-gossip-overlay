//! The gossipsub behaviour on the BN link.

use std::time::Duration;

use libp2p::gossipsub::{
    AllowAllSubscriptionFilter, Behaviour, Config, ConfigBuilder, IdentityTransform, Message,
    MessageAuthenticity, MessageId, MetricsConfig, ValidationMode,
};
use overlay_core::msgid;
use prometheus_client::registry::Registry;

pub mod wire;

/// How long gossipsub remembers an id it has received or published, so the same message is
/// never handed to the router or the beacon node twice. Twice the seen cache; the beacon node's
/// own cache, two epochs, is the backstop for anything older.
pub const DUPLICATE_CACHE_TIME: Duration = Duration::from_secs(120);

/// No IHAVE gossip at all: the beacon node is an explicit peer and gets every message
/// forwarded outright, so gossip could only ever advertise what it already has.
pub const GOSSIP_LAZY: usize = 0;
/// The fraction of non-mesh peers to gossip to, likewise zero.
pub const GOSSIP_FACTOR: f64 = 0.0;
/// Heartbeats of history an IHAVE could cover; the minimum, since none is sent.
pub const HISTORY_GOSSIP: usize = 1;
/// Heartbeats a full message stays in the message cache for IWANT and late validation. The
/// fork's default; nothing here asks for more.
pub const HISTORY_LENGTH: usize = 5;
/// Mesh bounds at their minimum. An explicit peer is never grafted, so a mesh of one exists
/// only in gossipsub's bookkeeping; `mesh_outbound_min(0)` is what makes a mesh of one legal.
pub const MESH_N_LOW: usize = 1;
/// See [`MESH_N_LOW`].
pub const MESH_N: usize = 1;
/// See [`MESH_N_LOW`].
pub const MESH_N_HIGH: usize = 1;
/// See [`MESH_N_LOW`].
pub const MESH_OUTBOUND_MIN: usize = 0;
/// Messages at or above this size get an IDONTWANT sent ahead of them; the same 1 kB Lighthouse
/// defaults to, so both ends draw the line in the same place.
pub const IDONTWANT_MESSAGE_SIZE_THRESHOLD: usize = 1000;

/// The behaviour type the BN link runs: identity transform, so payloads stay compressed, and
/// no subscription filter, because the only peer is the operator's own beacon node.
pub type GossipBehaviour = Behaviour<IdentityTransform, AllowAllSubscriptionFilter>;

/// What the operator's config contributes to the gossipsub parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BnLinkConfig {
    /// `bn.idontwant_on_publish`: send the beacon node an IDONTWANT ahead of each publish.
    pub idontwant_on_publish: bool,
}

/// The spec's message id over the compressed bytes gossipsub hands over: T-006 decompresses
/// inside the hash, which is what lets the transform stay the identity. The branch is dropped
/// here because gossipsub only wants an id; the receive paths decide what to do with a payload
/// that took the invalid branch.
pub fn message_id_fn(message: &Message) -> MessageId {
    let computed = msgid::compute(
        message.topic.as_str(),
        &message.data,
        wire::MAX_TRANSMIT_SIZE as usize,
    );
    MessageId::new(&computed.id.0)
}

/// The gossipsub parameters, exposed on their own so tests can read the getters.
#[expect(
    clippy::expect_used,
    reason = "every value the builder validates is a constant in this function; a test builds it"
)]
pub fn config(cfg: &BnLinkConfig) -> Config {
    ConfigBuilder::default()
        .max_transmit_size(wire::MAX_TRANSMIT_SIZE as usize)
        .validation_mode(ValidationMode::Anonymous)
        .validate_messages()
        .message_id_fn(message_id_fn)
        .duplicate_cache_time(DUPLICATE_CACHE_TIME)
        .gossip_lazy(GOSSIP_LAZY)
        .gossip_factor(GOSSIP_FACTOR)
        .history_gossip(HISTORY_GOSSIP)
        .history_length(HISTORY_LENGTH)
        .mesh_n_low(MESH_N_LOW)
        .mesh_n(MESH_N)
        .mesh_n_high(MESH_N_HIGH)
        .mesh_outbound_min(MESH_OUTBOUND_MIN)
        .flood_publish(false)
        .idontwant_message_size_threshold(IDONTWANT_MESSAGE_SIZE_THRESHOLD)
        .idontwant_on_publish(cfg.idontwant_on_publish)
        .build()
        .expect("constant gossipsub parameters pass the builder's checks")
}

/// The behaviour, with its metrics registered under `overlay_gossipsub_` in `registry`.
#[expect(
    clippy::expect_used,
    reason = "construction only fails when privacy and validation mode disagree; both are constants here"
)]
pub fn build_behaviour(cfg: &BnLinkConfig, registry: &mut Registry) -> GossipBehaviour {
    Behaviour::new_with_subscription_filter_and_transform(
        MessageAuthenticity::Anonymous,
        config(cfg),
        AllowAllSubscriptionFilter::default(),
        IdentityTransform,
    )
    .expect("anonymous authenticity matches anonymous validation")
    .with_metrics(
        registry.sub_registry_with_prefix("overlay_gossipsub"),
        MetricsConfig::default(),
    )
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use libp2p::gossipsub::{Message, TopicHash};
    use overlay_core::msgid;
    use prometheus_client::registry::Registry;

    use super::*;
    use crate::testutil;

    const TOPIC: &str = "/eth2/6a95a1a9/beacon_block/ssz_snappy";
    /// `hello`, snappy-compressed: T-006's spec vector input.
    const HELLO_SNAPPY: &[u8] = &[0x05, 0x10, 0x68, 0x65, 0x6c, 0x6c, 0x6f];

    fn cfg() -> BnLinkConfig {
        BnLinkConfig {
            idontwant_on_publish: true,
        }
    }

    fn message(data: &[u8]) -> Message {
        Message {
            source: None,
            data: data.to_vec(),
            sequence_number: None,
            topic: TopicHash::from_raw(TOPIC),
        }
    }

    #[test]
    fn message_id_matches_core_compute_for_compressed_payload() {
        let payload: Vec<u8> = (0..240u32).map(|i| (i * 7 % 251) as u8).collect();
        let compressed = snap::raw::Encoder::new().compress_vec(&payload).unwrap();
        let expected = msgid::compute(TOPIC, &compressed, wire::MAX_TRANSMIT_SIZE as usize);
        assert_eq!(expected.branch, msgid::Branch::Valid);

        let id = config(&cfg()).message_id(&message(&compressed));

        assert_eq!(id.0, expected.id.0);
    }

    /// T-006's known-answer vectors: `hello` compressed, and the same bytes cut short so they
    /// take the spec's invalid-snappy branch.
    #[test]
    fn message_id_matches_spec_vectors_through_the_config() {
        let config = config(&cfg());
        let hex = |id: MessageId| id.0.iter().map(|b| format!("{b:02x}")).collect::<String>();

        assert_eq!(
            hex(config.message_id(&message(HELLO_SNAPPY))),
            "d1346976629ef3d2c04a2a53ccacb9499c3db63a"
        );
        assert_eq!(
            hex(config.message_id(&message(&HELLO_SNAPPY[..3]))),
            "0c900438f873351253246db4766f6035ababcbb0"
        );
    }

    #[test]
    fn validation_mode_is_anonymous() {
        assert!(
            matches!(config(&cfg()).validation_mode(), ValidationMode::Anonymous),
            "eth2 gossip carries no signature, sequence number or author; anything else is rejected"
        );
    }

    #[test]
    fn messages_wait_for_application_validation() {
        assert!(
            config(&cfg()).validate_messages(),
            "Lighthouse forwards nothing until the application reports on it, and neither may the sidecar"
        );
    }

    #[test]
    fn max_transmit_size_equals_lighthouse() {
        let lighthouse = types::ChainSpec::mainnet().max_message_size() as u64;

        assert_eq!(wire::MAX_TRANSMIT_SIZE, lighthouse);
        assert_eq!(config(&cfg()).max_transmit_size() as u64, lighthouse);
    }

    #[test]
    fn duplicate_cache_time_is_the_sidecar_policy_value_not_lighthouses() {
        let config = config(&cfg());

        assert_eq!(config.duplicate_cache_time(), DUPLICATE_CACHE_TIME);
        assert_eq!(
            DUPLICATE_CACHE_TIME,
            Duration::from_secs(120),
            "twice the seen cache; Lighthouse's own is two epochs (768 s on mainnet) and is the backstop"
        );
    }

    /// One explicit peer that is never in the mesh: nothing to gossip to, nothing to graft,
    /// nothing to exchange peers with.
    #[test]
    fn local_policy_parameters_are_set() {
        let config = config(&cfg());

        assert_eq!(config.gossip_lazy(), 0);
        assert_eq!(config.gossip_factor(), 0.0);
        assert_eq!(config.history_gossip(), 1);
        assert_eq!(config.history_length(), 5, "the fork's default");
        assert_eq!(config.mesh_n_low(), 1);
        assert_eq!(config.mesh_n(), 1);
        assert_eq!(config.mesh_n_high(), 1);
        assert_eq!(config.mesh_outbound_min(), 0);
        assert!(!config.do_px());
        assert!(!config.flood_publish());
        assert_eq!(config.idontwant_message_size_threshold(), 1000);
    }

    #[tokio::test]
    async fn payload_is_not_decompressed_by_transform() {
        let mut registry = Registry::default();
        let (mut sidecar, mut bn) = testutil::connected_pair(
            build_behaviour(&cfg(), &mut registry),
            build_behaviour(&cfg(), &mut registry),
        )
        .await;
        let topic = testutil::subscribe_both(&mut sidecar, &mut bn, TOPIC).await;

        sidecar
            .behaviour_mut()
            .publish(topic, HELLO_SNAPPY.to_vec())
            .unwrap();
        let received = testutil::next_message(&mut sidecar, &mut bn).await;

        assert_eq!(received.data, HELLO_SNAPPY);
    }
}
