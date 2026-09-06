//! Which peers a message goes to, and how.

#[cfg(test)]
mod tests {
    use overlay_core::config::Fanout;
    use overlay_core::roster::{Hostname, Region, SelfIdentity};
    use overlay_core::topic::{Class, Topic};

    use super::{RoutePlan, route};
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
        let cluster = Builder::new(&[NodeKind::Bare, NodeKind::Bare]).start().await;
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
}
