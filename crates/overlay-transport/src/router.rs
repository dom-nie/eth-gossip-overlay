//! Which peers a message goes to, and how.
//!
//! Every sender works that out from its own live view, because no node is special and there is
//! nothing to ask (§3). The answer is an enum and not a list of hosts so that the send path
//! (T-032) matches on one thing however the class ends up being carried.
//!
//! v1 has one plan to make: the whole message to every live peer whose beacon node is subscribed
//! to the topic (§5.4), in hostname order and this host aside, or [`RoutePlan::Nothing`] when that
//! leaves nobody. T-072 adds the stripe a large message takes over a region, T-063 the relays a
//! small-class batch crosses a region through, and both are variants of this enum, so neither has
//! to touch what already calls it.
//!
//! `_class` and `_cfg` are the arguments those two read. v1 reads neither, so a small message and
//! a large one on the same topic get the same plan.

use overlay_core::config::Fanout;
use overlay_core::roster::{Hostname, SelfIdentity};
use overlay_core::topic::{Class, Topic};

use crate::manager::LiveView;
use crate::subs;

/// What a sender does with one message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoutePlan {
    /// The whole message to each of these hosts, in hostname order.
    Direct(Vec<Hostname>),
    /// No live peer wants it, so it goes nowhere.
    Nothing,
}

/// The plan for a message on `topic`, from the live set as it stood when `view` was taken. Pure:
/// it reads its arguments and nothing else, so the hard part of routing is a function a test can
/// ask a question of.
///
/// The recipients come off the view here rather than from [`LiveView::subscribers`], which
/// hands back borrowed names: cloning those into the plan would cost a second `Vec` on the path
/// every message takes.
pub fn route(
    topic: &Topic,
    _class: Class,
    view: &LiveView,
    self_id: &SelfIdentity,
    _cfg: &Fanout,
) -> RoutePlan {
    let targets: Vec<Hostname> = view
        .iter()
        .filter(|(hostname, _)| **hostname != self_id.hostname)
        .filter(|(_, peer)| subs::state(&peer.state).subscribed(topic))
        .map(|(hostname, _)| hostname.clone())
        .collect();
    if targets.is_empty() {
        RoutePlan::Nothing
    } else {
        RoutePlan::Direct(targets)
    }
}

#[cfg(test)]
mod tests {
    use overlay_core::config::{Fanout, SmallFanout};
    use overlay_core::roster::{Hostname, Region, SelfIdentity};
    use overlay_core::subs::PeerState;
    use overlay_core::topic::{Class, Topic};

    use super::{RoutePlan, route};
    use crate::manager::LiveView;
    use crate::testutil::{Builder, NodeKind, REGION, WAIT, peer_state, view};

    fn host(name: &str) -> Hostname {
        Hostname(name.to_owned())
    }

    fn topic(name: &str) -> Topic {
        Topic::parse(&format!("/eth2/6a95a1a9/{name}/ssz_snappy")).unwrap()
    }

    /// A fanout that relays the small class into a remote region of `min_remote_hosts` or more,
    /// through `per_region` of its hosts.
    fn relaying(min_remote_hosts: usize, per_region: usize) -> Fanout {
        Fanout {
            small: SmallFanout {
                relay_min_remote_hosts: min_remote_hosts,
                relays_per_remote_region: per_region,
                ..SmallFanout::default()
            },
            ..Fanout::default()
        }
    }

    /// A live view with each peer in the region named beside it, which is the region it declared
    /// in its HELLO and the one its second hop would fan out in (D15).
    fn view_in(connection: &quinn::Connection, peers: Vec<(&str, &str, PeerState)>) -> LiveView {
        let regions: Vec<(Hostname, Region)> = peers
            .iter()
            .map(|(name, region, _)| (host(name), Region((*region).to_owned())))
            .collect();
        let mut live = view(
            connection,
            peers
                .into_iter()
                .map(|(name, _, state)| (host(name), state))
                .collect(),
        );
        for (hostname, region) in regions {
            live.0
                .get_mut(&hostname)
                .expect("the peer this view was built from")
                .region = region;
        }
        live
    }

    /// The host doing the routing, which is in no view unless a test puts it there.
    fn me() -> SelfIdentity {
        SelfIdentity {
            hostname: host("bn-me"),
            region: Region(REGION.to_owned()),
            site: None,
        }
    }

    /// The one connection every peer in a hand-built view shares. A [`LivePeer`] holds one and a
    /// routing question never reads it, so the cluster that opened it is gone by the time the
    /// view exists.
    ///
    /// [`LivePeer`]: crate::manager::LivePeer
    async fn connection() -> quinn::Connection {
        let cluster = Builder::new(&[NodeKind::Bare, NodeKind::Bare])
            .start()
            .await;
        tokio::time::timeout(WAIT, cluster.connected_pair(0, 1))
            .await
            .unwrap()
            .0
    }

    /// The set a message goes to: every live peer whose beacon node wants the topic (§5.4). The
    /// sender works it out from its own view, with nothing coordinating the answer (§3).
    #[tokio::test(flavor = "multi_thread")]
    async fn routes_to_every_live_peer_subscribed_to_the_topic() {
        let connection = connection().await;
        let block = topic("beacon_block");
        let (first, second) = (host("bn-a"), host("bn-b"));
        let live = view(
            &connection,
            vec![
                (first.clone(), peer_state(&[(1, &block)], &[1])),
                (second.clone(), peer_state(&[(4, &block)], &[4])),
            ],
        );

        let plan = route(&block, Class::Large, &live, &me(), &Fanout::default());

        assert_eq!(plan, RoutePlan::Direct(vec![first, second]));
    }

    /// A peer whose beacon node wants other topics but not this one is not a recipient: the copy
    /// would cost the WAN a message the far end drops (§5.4).
    #[tokio::test(flavor = "multi_thread")]
    async fn excludes_peers_not_subscribed() {
        let connection = connection().await;
        let (block, attestation) = (topic("beacon_block"), topic("beacon_attestation_3"));
        let (wants_it, wants_other) = (host("bn-a"), host("bn-b"));
        let live = view(
            &connection,
            vec![
                (wants_it.clone(), peer_state(&[(1, &block)], &[1])),
                (
                    wants_other.clone(),
                    peer_state(&[(1, &attestation), (2, &block)], &[1]),
                ),
            ],
        );

        let plan = route(&block, Class::Large, &live, &me(), &Fanout::default());

        assert_eq!(plan, RoutePlan::Direct(vec![wants_it]));
    }

    /// The sender is never a recipient of its own message, whatever the view says. A host has
    /// nothing to connect to itself with, so its own name in the live set means a roster that
    /// lists it twice, and sending there would hand the message back to the beacon node it came
    /// from.
    #[tokio::test(flavor = "multi_thread")]
    async fn excludes_self_even_if_self_appears_in_view() {
        let connection = connection().await;
        let block = topic("beacon_block");
        let peer = host("bn-a");
        let live = view(
            &connection,
            vec![
                (peer.clone(), peer_state(&[(1, &block)], &[1])),
                (me().hostname, peer_state(&[(1, &block)], &[1])),
            ],
        );

        let plan = route(&block, Class::Large, &live, &me(), &Fanout::default());

        assert_eq!(plan, RoutePlan::Direct(vec![peer]));
    }

    /// Nobody to send to is its own plan and not an empty list, so the send path has one thing
    /// to match on rather than a `Direct` it has to check the length of. A live peer that wants
    /// another topic and a fleet where every sibling is down both end here (§9).
    #[tokio::test(flavor = "multi_thread")]
    async fn empty_recipient_set_is_nothing() {
        let connection = connection().await;
        let (block, attestation) = (topic("beacon_block"), topic("beacon_attestation_3"));
        let live = view(
            &connection,
            vec![(host("bn-a"), peer_state(&[(1, &attestation)], &[1]))],
        );

        let plan = route(&block, Class::Large, &live, &me(), &Fanout::default());

        assert_eq!(plan, RoutePlan::Nothing);
        assert_eq!(
            route(
                &block,
                Class::Large,
                &LiveView::default(),
                &me(),
                &Fanout::default()
            ),
            RoutePlan::Nothing
        );
    }

    /// The order is part of the answer, not an accident of how the peers connected. T-072 turns
    /// this list into a stripe by rotating it, so two origins with the same live view have to
    /// produce the same list for their chunks to deduplicate on arrival (§5.4).
    #[tokio::test(flavor = "multi_thread")]
    async fn targets_are_sorted_by_hostname() {
        let connection = connection().await;
        let block = topic("beacon_block");
        let names = ["bn-c", "bn-a", "bn-b"];
        let live = view(
            &connection,
            names
                .iter()
                .map(|name| (host(name), peer_state(&[(1, &block)], &[1])))
                .collect(),
        );

        let plan = route(&block, Class::Large, &live, &me(), &Fanout::default());

        assert_eq!(
            plan,
            RoutePlan::Direct(vec![host("bn-a"), host("bn-b"), host("bn-c")])
        );
    }

    /// A peer that has paired and announced its topic ids but has not sent a `SUBS` yet wants
    /// nothing until it says so. Its bitmap is empty, and an empty bitmap is the same answer as
    /// a beacon node that is down (§9), which is the safe way round: the alternative sends it
    /// every topic it named.
    #[tokio::test(flavor = "multi_thread")]
    async fn peer_without_any_subs_frame_yet_is_excluded() {
        let connection = connection().await;
        let block = topic("beacon_block");
        let (subscriber, silent) = (host("bn-a"), host("bn-b"));
        let live = view(
            &connection,
            vec![
                (subscriber.clone(), peer_state(&[(1, &block)], &[1])),
                (silent, peer_state(&[(1, &block)], &[])),
            ],
        );

        let plan = route(&block, Class::Large, &live, &me(), &Fanout::default());

        assert_eq!(plan, RoutePlan::Direct(vec![subscriber]));
    }

    /// §5.4: a small-class batch crosses the WAN to a few hosts of the remote region, which fan
    /// it out inside it, while the origin's own region is reached directly as ever. The three
    /// hosts of `us` are exactly `relay_min_remote_hosts`, so the region is big enough for the
    /// relay hop to be worth its copies (D36), and the two that carry it are the window
    /// `fnv1a64("bn-me") % 3` opens at (D20).
    #[tokio::test(flavor = "multi_thread")]
    async fn route_small_class_yields_in_region_direct_and_remote_relays() {
        let connection = connection().await;
        let subnet = topic("beacon_attestation_7");
        let live = view_in(
            &connection,
            vec![
                ("bn-eu-a", "eu", peer_state(&[(1, &subnet)], &[1])),
                ("bn-us-01", "us", peer_state(&[(1, &subnet)], &[1])),
                ("bn-us-02", "us", peer_state(&[(1, &subnet)], &[1])),
                ("bn-us-03", "us", peer_state(&[(1, &subnet)], &[1])),
            ],
        );

        let plan = route(&subnet, Class::Small, &live, &me(), &relaying(3, 2));

        assert_eq!(
            plan,
            RoutePlan::SmallRelayed {
                direct: vec![host("bn-eu-a")],
                relays: vec![host("bn-us-02"), host("bn-us-03")],
            }
        );
    }

    /// v1 sends both classes the same way, so the class changes nothing about the plan. T-072
    /// rewrites this test: a large message becomes a stripe over the same peers, and the two
    /// answers stop matching.
    #[tokio::test(flavor = "multi_thread")]
    async fn class_does_not_change_v1_plan() {
        let connection = connection().await;
        let block = topic("beacon_block");
        let peer = host("bn-a");
        let live = view(&connection, vec![(peer, peer_state(&[(1, &block)], &[1]))]);

        let small = route(&block, Class::Small, &live, &me(), &Fanout::default());
        let large = route(&block, Class::Large, &live, &me(), &Fanout::default());

        assert_eq!(small, RoutePlan::Direct(vec![host("bn-a")]));
        assert_eq!(small, large);
    }
}
