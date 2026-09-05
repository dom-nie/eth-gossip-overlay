//! The mirror of the beacon node's subscriptions (§5.2): whatever topic the beacon node
//! subscribes to, the sidecar subscribes to as well, which is what makes the beacon node
//! forward that topic's validated messages to it, and the same set is what the sidecar
//! advertises to its siblings. The sidecar never computes a topic name, so a fork digest
//! change needs no sidecar release (§3 principle 6).
//!
//! [`Mirror`] is pure: it takes the link's events and returns the actions they call for.
//! [`run`] is the shell that applies them to the link and to a `watch` of the sets.

use std::collections::{BTreeMap, BTreeSet};

use libp2p::PeerId;
use overlay_core::topic::{SubscriptionSets, Topic};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::link::{BnCommand, BnEvent};

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
    /// Unparsable strings already warned about, so a beacon node that re-announces one on
    /// every reconnect does not repeat the warning.
    warned: BTreeSet<String>,
}

impl Mirror {
    /// A mirror of nothing yet, filtering on `bn` until a `Connected` names the real id.
    pub fn new(bn: PeerId) -> Self {
        Self {
            bn,
            topics: BTreeMap::new(),
            sets: SubscriptionSets::default(),
            warned: BTreeSet::new(),
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
        let parsed = match Topic::parse(topic) {
            Ok(parsed) => Some(parsed),
            Err(err) => {
                if self.warned.insert(topic.to_owned()) {
                    tracing::warn!(topic, %err, "mirroring a topic the sidecar cannot parse");
                }
                None
            }
        };
        self.topics.insert(topic.to_owned(), parsed);
        let mut actions = vec![MirrorAction::Subscribe(topic.to_owned())];
        actions.extend(self.changed());
        actions
    }

    fn unsubscribe(&mut self, topic: &str) -> Vec<MirrorAction> {
        if self.topics.remove(topic).is_none() {
            return Vec::new();
        }
        let mut actions = vec![MirrorAction::Unsubscribe(topic.to_owned())];
        actions.extend(self.changed());
        actions
    }

    /// Nothing survives a disconnect: the beacon node re-announces everything on reconnect.
    fn disconnected(&mut self) -> Vec<MirrorAction> {
        let mut actions: Vec<_> = std::mem::take(&mut self.topics)
            .into_keys()
            .map(MirrorAction::Unsubscribe)
            .collect();
        actions.extend(self.changed());
        actions
    }

    /// Rebuilds the sets from the parsed topics and reports them if they differ from before.
    fn changed(&mut self) -> Option<MirrorAction> {
        let sets = SubscriptionSets::mirrored(self.topics.values().flatten().cloned().collect());
        if sets == self.sets {
            return None;
        }
        self.sets = sets;
        Some(MirrorAction::Changed(self.sets.clone()))
    }
}

/// Drives a [`Mirror`] from the link's `events` until they close or the link stops taking
/// commands: subscriptions become [`BnCommand`]s, and every change lands on `sets`, whose
/// receivers only ever want the latest value. `bn` is the peer id to filter on until the
/// first `Connected` names the real one. This shell may wait on the command channel; the
/// swarm loop is on the other end of it, and it is the one that never waits.
pub fn run(
    mut events: mpsc::Receiver<BnEvent>,
    commands: mpsc::Sender<BnCommand>,
    sets: watch::Sender<SubscriptionSets>,
    bn: PeerId,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut mirror = Mirror::new(bn);
        while let Some(event) = events.recv().await {
            for action in mirror.on_bn_event(&event) {
                let command = match action {
                    MirrorAction::Subscribe(topic) => BnCommand::Subscribe(topic),
                    MirrorAction::Unsubscribe(topic) => BnCommand::Unsubscribe(topic),
                    MirrorAction::Changed(new) => {
                        sets.send_replace(new);
                        continue;
                    }
                };
                if commands.send(command).await.is_err() {
                    return;
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, LazyLock};
    use std::time::Duration;

    use libp2p::identity::Keypair;
    use overlay_core::lanes::ClassLanes;
    use prometheus_client::registry::Registry;

    use super::*;
    use crate::bn_http::BnClient;
    use crate::link::BnLink;
    use crate::spec::spec_watch;
    use crate::testutil::{FakeBn, FakeBnEvent, link_config, node_key};

    /// Long enough for a dial and a gossipsub exchange on a loaded CI box.
    const WAIT: Duration = Duration::from_secs(3);

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
    fn mirrored(topics: &[&str]) -> SubscriptionSets {
        SubscriptionSets::mirrored(topics.iter().map(|t| Topic::parse(t).unwrap()).collect())
    }

    /// A link to `bn` with the mirror shell on its events, and the watch the shell feeds.
    /// Neither task is kept: the runtime drops them with the test.
    fn mirrored_link(bn: &FakeBn) -> watch::Receiver<SubscriptionSets> {
        let (commands, commands_rx) = mpsc::channel(64);
        let (spec, _) = spec_watch();
        let lanes = ClassLanes::new(Arc::new(()));
        let link = BnLink::spawn(
            link_config(bn),
            &node_key(&tempfile::tempdir().unwrap()),
            BnClient::new(bn.http_addr(), Duration::from_secs(2)),
            &mut Registry::default(),
            lanes.pusher(),
            spec,
            commands_rx,
        );
        let (sets, watch) = watch::channel(SubscriptionSets::default());
        run(link.events, commands, sets, bn.peer_id());
        watch
    }

    async fn wait_connected(bn: &mut FakeBn) {
        tokio::time::timeout(
            WAIT,
            bn.wait_for(|e| matches!(e, FakeBnEvent::Connected(_))),
        )
        .await
        .expect("the link never connected to the fake");
    }

    async fn wait_sets(
        watch: &mut watch::Receiver<SubscriptionSets>,
        wanted: impl FnMut(&SubscriptionSets) -> bool,
    ) {
        tokio::time::timeout(WAIT, watch.wait_for(wanted))
            .await
            .expect("the sets never reached the awaited value")
            .unwrap();
    }

    #[test]
    fn subscribe_event_produces_subscribe_action_and_changed_sets() {
        let mut mirror = Mirror::new(*BN);

        let actions = mirror.on_bn_event(&subscribed(ATTESTATION_3));

        assert_eq!(
            actions,
            vec![
                MirrorAction::Subscribe(ATTESTATION_3.to_owned()),
                MirrorAction::Changed(mirrored(&[ATTESTATION_3])),
            ]
        );
        assert_eq!(mirror.sets(), &mirrored(&[ATTESTATION_3]));
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
                MirrorAction::Changed(mirrored(&[])),
            ]
        );
        assert_eq!(mirror.sets(), &mirrored(&[]));
    }

    #[test]
    fn duplicate_subscribe_is_idempotent_no_actions() {
        let mut mirror = Mirror::new(*BN);
        mirror.on_bn_event(&subscribed(ATTESTATION_3));

        let actions = mirror.on_bn_event(&subscribed(ATTESTATION_3));

        assert_eq!(actions, vec![]);
        assert_eq!(mirror.sets(), &mirrored(&[ATTESTATION_3]));
    }

    #[test]
    fn unsubscribe_of_unknown_topic_produces_no_actions() {
        let mut mirror = Mirror::new(*BN);

        let actions = mirror.on_bn_event(&unsubscribed(ATTESTATION_3));

        assert_eq!(actions, vec![]);
        assert_eq!(mirror.sets(), &mirrored(&[]));
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
                MirrorAction::Changed(mirrored(&[])),
            ]
        );
        assert_eq!(mirror.sets(), &mirrored(&[]));
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
        assert_eq!(mirror.sets(), &mirrored(&[]));
    }

    /// A restarted beacon node has a new peer id; its subscriptions must not be ignored.
    #[test]
    fn connected_moves_the_peer_filter_to_the_new_bn() {
        let mut mirror = Mirror::new(*BN);
        let restarted = Keypair::generate_ed25519().public().to_peer_id();
        mirror.on_bn_event(&BnEvent::Connected { peer_id: restarted });

        let actions = mirror.on_bn_event(&BnEvent::Subscribed {
            peer: restarted,
            topic: ATTESTATION_3.to_owned(),
        });

        assert_eq!(actions.len(), 2);
        assert_eq!(mirror.sets(), &mirrored(&[ATTESTATION_3]));
    }

    #[test]
    fn unparsable_topic_is_still_mirrored() {
        let mut mirror = Mirror::new(*BN);
        let raw = "/eth2/00000000/beacon_attestation_/ssz_snappy";

        let actions = mirror.on_bn_event(&subscribed(raw));

        assert_eq!(actions, vec![MirrorAction::Subscribe(raw.to_owned())]);
        assert_eq!(mirror.sets(), &mirrored(&[]));
        assert_eq!(
            mirror.on_bn_event(&BnEvent::Disconnected),
            vec![MirrorAction::Unsubscribe(raw.to_owned())]
        );
    }

    #[test]
    fn changed_carries_advertised_and_local_and_they_are_equal_without_extras() {
        let mut mirror = Mirror::new(*BN);
        mirror.on_bn_event(&subscribed(ATTESTATION_3));

        let actions = mirror.on_bn_event(&subscribed(BLOCK));

        let Some(MirrorAction::Changed(changed)) = actions.last() else {
            panic!("no Changed in {actions:?}");
        };
        let expected: BTreeSet<Topic> = [ATTESTATION_3, BLOCK]
            .iter()
            .map(|t| Topic::parse(t).unwrap())
            .collect();
        assert_eq!(changed.advertised, expected);
        assert_eq!(changed.local, changed.advertised);
    }

    /// The fake's subscription has to show in the watch and come back to the fake as the
    /// sidecar's own subscription, both inside one second of the fake sending it.
    #[tokio::test(flavor = "multi_thread")]
    async fn fake_bn_subscribe_is_mirrored_within_one_second() {
        let mut bn = FakeBn::start().await;
        let mut watch = mirrored_link(&bn);
        wait_connected(&mut bn).await;

        bn.subscribe(ATTESTATION_3).await;

        let (shown, seen) = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(
                watch.wait_for(|s| s == &mirrored(&[ATTESTATION_3])),
                bn.wait_for(
                    |e| matches!(e, FakeBnEvent::Subscribed { topic, .. } if topic == ATTESTATION_3)
                ),
            )
        })
        .await
        .expect("the subscription was not mirrored within a second");
        shown.unwrap();
        assert!(matches!(seen, FakeBnEvent::Subscribed { .. }));
    }

    /// The link's Disconnected has to empty the sets before the replacement fake, under a
    /// new peer id, comes up on the same port and announces a different topic.
    #[tokio::test(flavor = "multi_thread")]
    async fn fake_bn_restart_rebuilds_sets_from_reannounced_subscriptions() {
        let mut bn = FakeBn::start().await;
        let mut watch = mirrored_link(&bn);
        wait_connected(&mut bn).await;
        bn.subscribe(ATTESTATION_3).await;
        wait_sets(&mut watch, |s| s == &mirrored(&[ATTESTATION_3])).await;

        let port = bn.port();
        let http = bn.shutdown().await;
        wait_sets(&mut watch, |s| s == &SubscriptionSets::default()).await;
        let mut bn = FakeBn::start_on(port, http).await;
        wait_connected(&mut bn).await;
        bn.subscribe(BLOCK).await;

        let block = Topic::parse(BLOCK).unwrap();
        wait_sets(&mut watch, |s| s.advertised.contains(&block)).await;
        assert_eq!(*watch.borrow(), mirrored(&[BLOCK]));
    }
}
