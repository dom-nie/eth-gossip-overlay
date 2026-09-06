//! Which peers a message goes to, and how.
//!
//! Every sender works that out from its own live view, because no node is special and there is
//! nothing to ask (§3). The answer is an enum and not a list of hosts so that the send path
//! (T-032) matches on one thing however the class ends up being carried.
//!
//! v1 has one plan to make: the whole message to every live peer whose beacon node is
//! subscribed to the topic (§5.4), in hostname order, this host aside. T-072 adds the stripe a
//! large message takes over a region and T-063 the relays a small-class batch crosses a region
//! through, both as variants of this enum, so neither has to touch what already calls it.
//!
//! The class and the fan-out settings are what those two will read. v1 reads neither: a small
//! message and a large one on the same topic get the same plan.

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
    RoutePlan::Direct(
        view.iter()
            .filter(|(hostname, _)| **hostname != self_id.hostname)
            .filter(|(_, peer)| subs::state(&peer.state).subscribed(topic))
            .map(|(hostname, _)| hostname.clone())
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use overlay_core::config::Fanout;
    use overlay_core::roster::{Hostname, Region, SelfIdentity};
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
}
