//! The mirror of the beacon node's subscriptions (§5.2): whatever topic the beacon node
//! subscribes to, the sidecar subscribes to as well, which is what makes the beacon node
//! forward that topic's validated messages to it, and the same set is what the sidecar
//! advertises to its siblings. The sidecar never computes a topic name, so a fork digest
//! change needs no sidecar release (§3 principle 6).
//!
//! [`Mirror`] is pure: it takes the link's events and returns the actions they call for.

use std::collections::BTreeMap;

use libp2p::PeerId;
use overlay_core::topic::{SubscriptionSets, Topic};

use crate::link::BnEvent;

/// What a beacon node event asks the shell to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MirrorAction {
    /// Subscribe the sidecar's gossipsub instance to the full topic string.
    Subscribe(String),
    /// Unsubscribe it from the full topic string.
    Unsubscribe(String),
    /// The sets changed; this is their whole new value.
    Changed(SubscriptionSets),
}

/// The beacon node's subscriptions as the link reports them. Events from any other peer are
/// ignored: the sidecar has one peer, but the event carries an id, so it is checked.
#[derive(Debug)]
pub struct Mirror {
    bn: PeerId,
    /// Every topic string the beacon node is subscribed to, with its parse. One that does not
    /// parse is still mirrored to gossipsub; it only stays out of the sets.
    topics: BTreeMap<String, Option<Topic>>,
    sets: SubscriptionSets,
}

impl Mirror {
    /// A mirror of nothing yet, filtering on `bn` until a `Connected` names the real id.
    pub fn new(bn: PeerId) -> Self {
        Self {
            bn,
            topics: BTreeMap::new(),
            sets: SubscriptionSets::default(),
        }
    }

    /// The current sets.
    pub fn sets(&self) -> &SubscriptionSets {
        &self.sets
    }

    /// Applies `ev` and returns what the shell has to do about it, in order.
    pub fn on_bn_event(&mut self, ev: &BnEvent) -> Vec<MirrorAction> {
        match ev {
            BnEvent::Connected { peer_id } => {
                self.bn = *peer_id;
                Vec::new()
            }
            BnEvent::Subscribed { peer, topic } if *peer == self.bn => self.subscribe(topic),
            BnEvent::Unsubscribed { peer, topic } if *peer == self.bn => self.unsubscribe(topic),
            BnEvent::Disconnected => self.disconnected(),
            _ => Vec::new(),
        }
    }

    fn subscribe(&mut self, topic: &str) -> Vec<MirrorAction> {
        if self.topics.contains_key(topic) {
            return Vec::new();
        }
        let parsed = Topic::parse(topic).ok();
        self.topics.insert(topic.to_owned(), parsed);
        vec![MirrorAction::Subscribe(topic.to_owned()), self.changed()]
    }

    fn unsubscribe(&mut self, topic: &str) -> Vec<MirrorAction> {
        if self.topics.remove(topic).is_none() {
            return Vec::new();
        }
        vec![MirrorAction::Unsubscribe(topic.to_owned()), self.changed()]
    }

    /// Nothing survives a disconnect: the beacon node re-announces everything on reconnect.
    fn disconnected(&mut self) -> Vec<MirrorAction> {
        if self.topics.is_empty() {
            return Vec::new();
        }
        let mut actions: Vec<_> = std::mem::take(&mut self.topics)
            .into_keys()
            .map(MirrorAction::Unsubscribe)
            .collect();
        actions.push(self.changed());
        actions
    }

    /// Rebuilds the sets from the parsed topics and reports them.
    fn changed(&mut self) -> MirrorAction {
        self.sets = SubscriptionSets::mirrored(self.topics.values().flatten().cloned().collect());
        MirrorAction::Changed(self.sets.clone())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use libp2p::identity::Keypair;

    use super::*;

    static BN: LazyLock<PeerId> =
        LazyLock::new(|| Keypair::generate_ed25519().public().to_peer_id());
    const ATTESTATION_3: &str = "/eth2/00000000/beacon_attestation_3/ssz_snappy";
    const BLOCK: &str = "/eth2/00000000/beacon_block/ssz_snappy";

    fn subscribed(topic: &str) -> BnEvent {
        BnEvent::Subscribed {
            peer: *BN,
            topic: topic.to_owned(),
        }
    }

    fn unsubscribed(topic: &str) -> BnEvent {
        BnEvent::Unsubscribed {
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

    #[test]
    fn unsubscribe_event_produces_unsubscribe_and_changed_sets() {
        let mut mirror = Mirror::new(*BN);
        mirror.on_bn_event(&subscribed(ATTESTATION_3));

        let actions = mirror.on_bn_event(&unsubscribed(ATTESTATION_3));

        assert_eq!(
            actions,
            vec![
                MirrorAction::Unsubscribe(ATTESTATION_3.to_owned()),
                MirrorAction::Changed(sets(&[])),
            ]
        );
        assert_eq!(mirror.sets(), &sets(&[]));
    }

    #[test]
    fn duplicate_subscribe_is_idempotent_no_actions() {
        let mut mirror = Mirror::new(*BN);
        mirror.on_bn_event(&subscribed(ATTESTATION_3));

        let actions = mirror.on_bn_event(&subscribed(ATTESTATION_3));

        assert_eq!(actions, vec![]);
        assert_eq!(mirror.sets(), &sets(&[ATTESTATION_3]));
    }

    #[test]
    fn unsubscribe_of_unknown_topic_produces_no_actions() {
        let mut mirror = Mirror::new(*BN);

        let actions = mirror.on_bn_event(&unsubscribed(ATTESTATION_3));

        assert_eq!(actions, vec![]);
        assert_eq!(mirror.sets(), &sets(&[]));
    }

    #[test]
    fn disconnected_clears_both_sets_and_emits_unsubscribe_for_each_topic() {
        let mut mirror = Mirror::new(*BN);
        mirror.on_bn_event(&subscribed(ATTESTATION_3));
        mirror.on_bn_event(&subscribed(BLOCK));

        let actions = mirror.on_bn_event(&BnEvent::Disconnected);

        assert_eq!(
            actions,
            vec![
                MirrorAction::Unsubscribe(ATTESTATION_3.to_owned()),
                MirrorAction::Unsubscribe(BLOCK.to_owned()),
                MirrorAction::Changed(sets(&[])),
            ]
        );
        assert_eq!(mirror.sets(), &sets(&[]));
    }

    #[test]
    fn events_from_a_peer_other_than_the_bn_are_ignored() {
        let mut mirror = Mirror::new(*BN);
        let other = Keypair::generate_ed25519().public().to_peer_id();

        let actions = mirror.on_bn_event(&BnEvent::Subscribed {
            peer: other,
            topic: ATTESTATION_3.to_owned(),
        });

        assert_eq!(actions, vec![]);
        assert_eq!(mirror.sets(), &sets(&[]));
    }

    /// A restarted beacon node has a new peer id; its subscriptions must not be ignored.
    #[test]
    fn connected_moves_the_peer_filter_to_the_new_bn() {
        let mut mirror = Mirror::new(*BN);
        let restarted = Keypair::generate_ed25519().public().to_peer_id();
        mirror.on_bn_event(&BnEvent::Connected {
            peer_id: restarted,
        });

        let actions = mirror.on_bn_event(&BnEvent::Subscribed {
            peer: restarted,
            topic: ATTESTATION_3.to_owned(),
        });

        assert_eq!(actions.len(), 2);
        assert_eq!(mirror.sets(), &sets(&[ATTESTATION_3]));
    }

    #[test]
    fn unparsable_topic_is_still_mirrored() {
        let mut mirror = Mirror::new(*BN);
        let raw = "/eth2/00000000/beacon_attestation_/ssz_snappy";

        let actions = mirror.on_bn_event(&subscribed(raw));

        assert_eq!(actions, vec![MirrorAction::Subscribe(raw.to_owned())]);
        assert_eq!(mirror.sets(), &sets(&[]));
        assert_eq!(
            mirror.on_bn_event(&BnEvent::Disconnected),
            vec![MirrorAction::Unsubscribe(raw.to_owned())]
        );
    }
}
