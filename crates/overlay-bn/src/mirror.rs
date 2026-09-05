//! The mirror of the beacon node's subscriptions (§5.2): whatever topic the beacon node
//! subscribes to, the sidecar subscribes to as well, which is what makes the beacon node
//! forward that topic's validated messages to it, and the same set is what the sidecar
//! advertises to its siblings. The sidecar never computes a topic name, so a fork digest
//! change needs no sidecar release (§3 principle 6).

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use libp2p::identity::Keypair;

    use super::*;

    static BN: LazyLock<PeerId> =
        LazyLock::new(|| Keypair::generate_ed25519().public().to_peer_id());
    const ATTESTATION_3: &str = "/eth2/00000000/beacon_attestation_3/ssz_snappy";

    fn subscribed(topic: &str) -> BnEvent {
        BnEvent::Subscribed {
            peer: *BN,
            topic: topic.to_owned(),
        }
    }

    /// The sets a plain mirror of `topics` has.
    fn sets(topics: &[&str]) -> SubscriptionSets {
        SubscriptionSets::mirrored(topics.iter().map(|t| Topic::parse(t).unwrap()).collect())
    }

    #[test]
    fn subscribe_event_produces_subscribe_action_and_changed_sets() {
        let mut mirror = Mirror::new(*BN);

        let actions = mirror.on_bn_event(&subscribed(ATTESTATION_3));

        assert_eq!(
            actions,
            vec![
                MirrorAction::Subscribe(ATTESTATION_3.to_owned()),
                MirrorAction::Changed(sets(&[ATTESTATION_3])),
            ]
        );
        assert_eq!(mirror.sets(), &sets(&[ATTESTATION_3]));
    }
}
