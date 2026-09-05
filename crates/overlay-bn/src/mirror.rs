//! The mirror of the beacon node's subscriptions (§5.2): whatever topic the beacon node
//! subscribes to, the sidecar subscribes to as well, which is what makes the beacon node
//! forward that topic's validated messages to it, and the same set is what the sidecar
//! advertises to its siblings. On top of that it subscribes to every data column topic of
//! each fork digest the beacon node uses, because a beacon node publishes all columns of its
//! own proposal but custodies only some (§5.2 "All column topics, always"). Those extras are
//! local only (D06), so no sibling pushes a column to a beacon node that did not ask for it.
//! They are the one topic name the sidecar computes; a fork digest change still needs no
//! sidecar release (§3 principle 6).
//!
//! [`Mirror`] is pure: it takes the link's events and returns the actions they call for.
//! [`run`] is the shell that applies them to the link and to a `watch` of the sets.

use std::collections::{BTreeMap, BTreeSet};

use libp2p::PeerId;
use overlay_core::topic::{SubscriptionSets, Topic};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::link::{BnCommand, BnEvent};
use crate::spec::SpecSnapshot;

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

/// The beacon node's subscriptions as the link reports them, plus the extra column topics.
/// Ignores subscription events until a `Connected` names the beacon node, and after that any
/// from another peer: the sidecar has one peer, but the event carries an id, so it is checked.
#[derive(Debug)]
pub struct Mirror {
    bn: Option<PeerId>,
    /// Every topic string the beacon node is subscribed to, with its parse. One that does not
    /// parse is still mirrored to gossipsub; it only stays out of the sets.
    topics: BTreeMap<String, Option<Topic>>,
    /// `NUMBER_OF_COLUMNS` from the spec snapshot: how many column topics a digest gets.
    columns: u64,
    /// What the sidecar's own gossipsub instance is subscribed to, the beacon node's strings
    /// plus the extra columns. Kept so the next rebuild's diff against it is the actions.
    subscribed: BTreeSet<String>,
    sets: SubscriptionSets,
    /// Unparsable strings already warned about, so a beacon node that re-announces one on
    /// every reconnect does not repeat the warning.
    warned: BTreeSet<String>,
}

impl Mirror {
    /// A mirror of nothing yet, sized by `spec`'s column count, with no beacon node to mirror
    /// until the link connects.
    pub fn new(spec: &SpecSnapshot) -> Self {
        Self {
            bn: None,
            topics: BTreeMap::new(),
            columns: spec.number_of_columns,
            subscribed: BTreeSet::new(),
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
                self.bn = Some(*peer_id);
                Vec::new()
            }
            BnEvent::Subscribed { peer, topic } if Some(*peer) == self.bn => self.subscribe(topic),
            BnEvent::Unsubscribed { peer, topic } if Some(*peer) == self.bn => {
                self.unsubscribe(topic)
            }
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
        self.rederive()
    }

    fn unsubscribe(&mut self, topic: &str) -> Vec<MirrorAction> {
        if self.topics.remove(topic).is_none() {
            return Vec::new();
        }
        self.rederive()
    }

    /// Nothing survives a disconnect: the beacon node re-announces everything on reconnect.
    fn disconnected(&mut self) -> Vec<MirrorAction> {
        self.topics.clear();
        self.rederive()
    }

    /// Rebuilds everything that follows from `topics` and `columns`. The extras are every
    /// column topic of each digest the beacon node has a topic under, minus the columns it
    /// subscribes to itself; indices are `u8`, so a count past 256 yields the 256 topics that
    /// can be named. `advertised` is the mirrored set alone and `local` adds the extras
    /// (D06). The diff of the gossipsub subscriptions against the previous rebuild is the
    /// actions, which is what lets a column move between the two sets without a subscribe
    /// or unsubscribe: the sidecar was on it either way. A rebuild per event keeps `topics`
    /// the one source of truth; it walks the few hundred topics a beacon node announces.
    fn rederive(&mut self) -> Vec<MirrorAction> {
        let advertised: BTreeSet<Topic> = self.topics.values().flatten().cloned().collect();
        let digests: BTreeSet<[u8; 4]> = advertised.iter().map(Topic::fork_digest).collect();
        let columns = self.columns;
        let extra: BTreeSet<Topic> = digests
            .iter()
            .flat_map(|&digest| {
                (0..=u8::MAX)
                    .take_while(move |&i| u64::from(i) < columns)
                    .map(move |i| Topic::data_column(digest, i))
            })
            .filter(|topic| !advertised.contains(topic))
            .collect();
        let subscribed: BTreeSet<String> = self
            .topics
            .keys()
            .cloned()
            .chain(extra.iter().map(Topic::to_string))
            .collect();
        let mut actions: Vec<_> = self
            .subscribed
            .difference(&subscribed)
            .cloned()
            .map(MirrorAction::Unsubscribe)
            .collect();
        actions.extend(
            subscribed
                .difference(&self.subscribed)
                .cloned()
                .map(MirrorAction::Subscribe),
        );
        self.subscribed = subscribed;
        let sets = SubscriptionSets {
            local: advertised.union(&extra).cloned().collect(),
            advertised,
        };
        if sets != self.sets {
            self.sets = sets;
            actions.push(MirrorAction::Changed(self.sets.clone()));
        }
        actions
    }
}

/// Drives a [`Mirror`] from the link's `events` until they close or the link stops taking
/// commands: subscriptions become [`BnCommand`]s, and every change lands on `sets`, whose
/// receivers only ever want the latest value. This shell may wait on the command channel;
/// the swarm loop is on the other end of it, and it is the one that never waits.
pub fn run(
    mut events: mpsc::Receiver<BnEvent>,
    commands: mpsc::Sender<BnCommand>,
    sets: watch::Sender<SubscriptionSets>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut mirror = Mirror::new(&SpecSnapshot::MAINNET);
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
    use crate::spec::{SpecSnapshot, spec_watch};
    use crate::testutil::{FakeBn, FakeBnEvent, link_config, node_key};

    /// Long enough for a dial and a gossipsub exchange on a loaded CI box.
    const WAIT: Duration = Duration::from_secs(3);

    static BN: LazyLock<PeerId> =
        LazyLock::new(|| Keypair::generate_ed25519().public().to_peer_id());
    const ATTESTATION_3: &str = "/eth2/00000000/beacon_attestation_3/ssz_snappy";
    const BLOCK: &str = "/eth2/00000000/beacon_block/ssz_snappy";
    /// The block topic under the next fork's digest, as a transition window announces it.
    const NEXT_BLOCK: &str = "/eth2/6a95a1a9/beacon_block/ssz_snappy";

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

    /// A mirror whose link has connected to `BN`.
    fn connected() -> Mirror {
        connected_with(&SpecSnapshot::MAINNET)
    }

    /// A mirror built from `spec` whose link has connected to `BN`.
    fn connected_with(spec: &SpecSnapshot) -> Mirror {
        let mut mirror = Mirror::new(spec);
        mirror.on_bn_event(&BnEvent::Connected { peer_id: *BN });
        mirror
    }

    /// The column topic string as the spec spells it, built here on purpose without
    /// `Topic::data_column` so the tests check that constructor rather than trust it.
    fn column(digest: &str, i: u8) -> String {
        format!("/eth2/{digest}/data_column_sidecar_{i}/ssz_snappy")
    }

    fn columns(digest: &str, indices: impl IntoIterator<Item = u8>) -> BTreeSet<String> {
        indices.into_iter().map(|i| column(digest, i)).collect()
    }

    fn subscribes(actions: &[MirrorAction]) -> BTreeSet<String> {
        actions
            .iter()
            .filter_map(|a| match a {
                MirrorAction::Subscribe(topic) => Some(topic.clone()),
                _ => None,
            })
            .collect()
    }

    fn unsubscribes(actions: &[MirrorAction]) -> BTreeSet<String> {
        actions
            .iter()
            .filter_map(|a| match a {
                MirrorAction::Unsubscribe(topic) => Some(topic.clone()),
                _ => None,
            })
            .collect()
    }

    fn column_subscribes(actions: &[MirrorAction]) -> BTreeSet<String> {
        subscribes(actions)
            .into_iter()
            .filter(|t| t.contains("data_column_sidecar_"))
            .collect()
    }

    /// The sets a mirror of `topics` has under the mainnet column count: the topics
    /// themselves advertised, and every column of their digests in `local` as well.
    fn sets_of(topics: &[&str]) -> SubscriptionSets {
        let advertised: BTreeSet<Topic> = topics.iter().map(|t| Topic::parse(t).unwrap()).collect();
        let mut local = advertised.clone();
        for digest in advertised.iter().map(Topic::fork_digest) {
            local.extend((0..128).map(|i| Topic::data_column(digest, i)));
        }
        SubscriptionSets { advertised, local }
    }

    /// `actions` without the subscribes and unsubscribes of column topics, for the tests
    /// about the beacon node's own topics; the T-015 tests look at the columns.
    fn without_columns(actions: Vec<MirrorAction>) -> Vec<MirrorAction> {
        actions
            .into_iter()
            .filter(|a| match a {
                MirrorAction::Subscribe(t) | MirrorAction::Unsubscribe(t) => {
                    !t.contains("data_column_sidecar_")
                }
                MirrorAction::Changed(_) => true,
            })
            .collect()
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
        run(link.events, commands, sets);
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
        let mut mirror = connected();

        let actions = mirror.on_bn_event(&subscribed(ATTESTATION_3));

        assert_eq!(
            without_columns(actions),
            vec![
                MirrorAction::Subscribe(ATTESTATION_3.to_owned()),
                MirrorAction::Changed(sets_of(&[ATTESTATION_3])),
            ]
        );
        assert_eq!(mirror.sets(), &sets_of(&[ATTESTATION_3]));
    }

    #[test]
    fn unsubscribe_event_produces_unsubscribe_and_changed_sets() {
        let mut mirror = connected();
        mirror.on_bn_event(&subscribed(ATTESTATION_3));

        let actions = mirror.on_bn_event(&unsubscribed(ATTESTATION_3));

        assert_eq!(
            without_columns(actions),
            vec![
                MirrorAction::Unsubscribe(ATTESTATION_3.to_owned()),
                MirrorAction::Changed(sets_of(&[])),
            ]
        );
        assert_eq!(mirror.sets(), &sets_of(&[]));
    }

    #[test]
    fn duplicate_subscribe_is_idempotent_no_actions() {
        let mut mirror = connected();
        mirror.on_bn_event(&subscribed(ATTESTATION_3));

        let actions = mirror.on_bn_event(&subscribed(ATTESTATION_3));

        assert_eq!(actions, vec![]);
        assert_eq!(mirror.sets(), &sets_of(&[ATTESTATION_3]));
    }

    #[test]
    fn unsubscribe_of_unknown_topic_produces_no_actions() {
        let mut mirror = connected();

        let actions = mirror.on_bn_event(&unsubscribed(ATTESTATION_3));

        assert_eq!(actions, vec![]);
        assert_eq!(mirror.sets(), &sets_of(&[]));
    }

    #[test]
    fn disconnected_clears_both_sets_and_emits_unsubscribe_for_each_topic() {
        let mut mirror = connected();
        mirror.on_bn_event(&subscribed(ATTESTATION_3));
        mirror.on_bn_event(&subscribed(BLOCK));

        let actions = mirror.on_bn_event(&BnEvent::Disconnected);

        assert_eq!(
            without_columns(actions),
            vec![
                MirrorAction::Unsubscribe(ATTESTATION_3.to_owned()),
                MirrorAction::Unsubscribe(BLOCK.to_owned()),
                MirrorAction::Changed(sets_of(&[])),
            ]
        );
        assert_eq!(mirror.sets(), &sets_of(&[]));
    }

    /// Before the link has named the beacon node there is nobody to mirror.
    #[test]
    fn subscription_events_before_connected_are_ignored() {
        let mut mirror = Mirror::new(&SpecSnapshot::MAINNET);

        let actions = mirror.on_bn_event(&subscribed(ATTESTATION_3));

        assert_eq!(actions, vec![]);
        assert_eq!(mirror.sets(), &sets_of(&[]));
    }

    #[test]
    fn events_from_a_peer_other_than_the_bn_are_ignored() {
        let mut mirror = connected();
        let other = Keypair::generate_ed25519().public().to_peer_id();

        let actions = mirror.on_bn_event(&BnEvent::Subscribed {
            peer: other,
            topic: ATTESTATION_3.to_owned(),
        });

        assert_eq!(actions, vec![]);
        assert_eq!(mirror.sets(), &sets_of(&[]));
    }

    /// A restarted beacon node has a new peer id; its subscriptions must not be ignored.
    #[test]
    fn connected_moves_the_peer_filter_to_the_new_bn() {
        let mut mirror = connected();
        let restarted = Keypair::generate_ed25519().public().to_peer_id();
        mirror.on_bn_event(&BnEvent::Connected { peer_id: restarted });

        let actions = mirror.on_bn_event(&BnEvent::Subscribed {
            peer: restarted,
            topic: ATTESTATION_3.to_owned(),
        });

        assert_eq!(without_columns(actions).len(), 2);
        assert_eq!(mirror.sets(), &sets_of(&[ATTESTATION_3]));
    }

    #[test]
    fn unparsable_topic_is_still_mirrored() {
        let mut mirror = connected();
        let raw = "/eth2/00000000/beacon_attestation_/ssz_snappy";

        let actions = mirror.on_bn_event(&subscribed(raw));

        assert_eq!(actions, vec![MirrorAction::Subscribe(raw.to_owned())]);
        assert_eq!(mirror.sets(), &sets_of(&[]));
        assert_eq!(
            mirror.on_bn_event(&BnEvent::Disconnected),
            vec![MirrorAction::Unsubscribe(raw.to_owned())]
        );
    }

    /// A supernode subscribes to every column itself, so there is nothing extra to add.
    #[test]
    fn changed_carries_advertised_and_local_and_they_are_equal_without_extras() {
        let mut mirror = connected();
        for topic in columns("00000000", 0..128) {
            mirror.on_bn_event(&subscribed(&topic));
        }
        mirror.on_bn_event(&subscribed(ATTESTATION_3));

        let actions = mirror.on_bn_event(&subscribed(BLOCK));

        let Some(MirrorAction::Changed(changed)) = actions.last() else {
            panic!("no Changed in {actions:?}");
        };
        assert_eq!(changed.advertised, sets_of(&[ATTESTATION_3, BLOCK]).local);
        assert_eq!(changed.local, changed.advertised);
    }

    /// The count is the snapshot's the mirror was built with: eight columns here.
    #[test]
    fn first_topic_with_new_digest_subscribes_every_column_of_it() {
        let spec = SpecSnapshot {
            number_of_columns: 8,
            ..SpecSnapshot::MAINNET
        };
        let mut mirror = connected_with(&spec);

        let actions = mirror.on_bn_event(&subscribed(ATTESTATION_3));

        let mut expected = columns("00000000", 0..8);
        expected.insert(ATTESTATION_3.to_owned());
        assert_eq!(subscribes(&actions), expected);
    }

    #[test]
    fn column_count_comes_from_the_spec_snapshot_not_a_literal() {
        let sixty_four = SpecSnapshot {
            number_of_columns: 64,
            ..SpecSnapshot::MAINNET
        };
        let mut small = connected_with(&sixty_four);
        let mut mainnet = connected();

        let from_small = small.on_bn_event(&subscribed(ATTESTATION_3));
        let from_mainnet = mainnet.on_bn_event(&subscribed(ATTESTATION_3));

        assert_eq!(column_subscribes(&from_small), columns("00000000", 0..64));
        assert_eq!(
            column_subscribes(&from_mainnet),
            columns("00000000", 0..128)
        );
    }

    #[test]
    fn columns_already_mirrored_by_the_bn_are_not_subscribed_twice() {
        let mut mirror = connected();
        let column_5 = column("00000000", 5);

        let mut actions = mirror.on_bn_event(&subscribed(&column_5));
        actions.extend(mirror.on_bn_event(&subscribed(ATTESTATION_3)));

        let subscribes_of_5 = actions
            .iter()
            .filter(|a| **a == MirrorAction::Subscribe(column_5.clone()))
            .count();
        assert_eq!(subscribes_of_5, 1);
        assert_eq!(column_subscribes(&actions), columns("00000000", 0..128));
        assert_eq!(mirror.sets(), &sets_of(&[ATTESTATION_3, &column_5]));
    }

    #[test]
    fn extra_columns_are_in_local_but_not_in_advertised() {
        let mut mirror = connected();

        let actions = mirror.on_bn_event(&subscribed(ATTESTATION_3));

        let Some(MirrorAction::Changed(changed)) = actions.last() else {
            panic!("no Changed in {actions:?}");
        };
        assert_eq!(
            changed.advertised,
            BTreeSet::from([Topic::parse(ATTESTATION_3).unwrap()])
        );
        let extras: BTreeSet<String> = changed
            .local
            .difference(&changed.advertised)
            .map(Topic::to_string)
            .collect();
        assert_eq!(extras, columns("00000000", 0..128));
    }

    #[test]
    fn second_digest_adds_a_second_set_without_touching_the_first() {
        let mut mirror = connected();
        mirror.on_bn_event(&subscribed(ATTESTATION_3));

        let actions = mirror.on_bn_event(&subscribed(NEXT_BLOCK));

        let mut expected = columns("6a95a1a9", 0..128);
        expected.insert(NEXT_BLOCK.to_owned());
        assert_eq!(subscribes(&actions), expected);
        assert_eq!(unsubscribes(&actions), BTreeSet::new());
        assert_eq!(mirror.sets(), &sets_of(&[ATTESTATION_3, NEXT_BLOCK]));
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
                watch.wait_for(|s| s == &sets_of(&[ATTESTATION_3])),
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
        wait_sets(&mut watch, |s| s == &sets_of(&[ATTESTATION_3])).await;

        let port = bn.port();
        let http = bn.shutdown().await;
        wait_sets(&mut watch, |s| s == &SubscriptionSets::default()).await;
        let mut bn = FakeBn::start_on(port, http).await;
        wait_connected(&mut bn).await;
        bn.subscribe(BLOCK).await;

        let block = Topic::parse(BLOCK).unwrap();
        wait_sets(&mut watch, |s| s.advertised.contains(&block)).await;
        assert_eq!(*watch.borrow(), sets_of(&[BLOCK]));
    }
}
