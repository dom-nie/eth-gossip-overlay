//! The gossipsub behaviour on the BN link.

use libp2p::gossipsub::{
    AllowAllSubscriptionFilter, Behaviour, Config, ConfigBuilder, IdentityTransform,
    MessageAuthenticity, MetricsConfig, ValidationMode,
};
use prometheus_client::registry::Registry;

/// The behaviour type the BN link runs: identity transform, so payloads stay compressed, and
/// no subscription filter, because the only peer is the operator's own beacon node.
pub type GossipBehaviour = Behaviour<IdentityTransform, AllowAllSubscriptionFilter>;

/// What the operator's config contributes to the gossipsub parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BnLinkConfig {
    /// `bn.idontwant_on_publish`: send the beacon node an IDONTWANT ahead of each publish.
    pub idontwant_on_publish: bool,
}

/// The gossipsub parameters, exposed on their own so tests can read the getters.
#[expect(
    clippy::expect_used,
    reason = "every value the builder validates is a constant in this function; a test builds it"
)]
pub fn config(cfg: &BnLinkConfig) -> Config {
    ConfigBuilder::default()
        .validation_mode(ValidationMode::Anonymous)
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
