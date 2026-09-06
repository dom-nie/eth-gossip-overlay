//! The first thing two sidecars say to each other, on the first bidirectional stream of a
//! connection.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Builder, NodeKind, WAIT};
    use crate::tls::Role;

    /// One exchange leaves both ends holding the same four facts about the other, none of which
    /// a pinned key can carry: the name the peer runs under, its site label, the release it is
    /// running and the process it is running as.
    #[tokio::test(flavor = "multi_thread")]
    async fn dialer_and_acceptor_exchange_hello_and_return_peer_info() {
        let cluster = Builder::new(&[NodeKind::Bare; 2]).start().await;
        let (lower, higher) = (cluster.hostname(0), cluster.hostname(1));
        let dialler = SelfHello {
            site: Some("rack-a".to_owned()),
            instance_id: 7,
            ..cluster.self_hello(0)
        };
        let acceptor = SelfHello {
            site: Some("rack-b".to_owned()),
            instance_id: 9,
            ..cluster.self_hello(1)
        };
        let (dialling, accepting) = cluster.connected_pair(0, 1).await;

        let (dialled, accepted) = tokio::join!(
            perform(
                dialling,
                Role::Dial,
                &dialler,
                &higher,
                Vec::new(),
                WAIT,
                &()
            ),
            perform(
                accepting,
                Role::Accept,
                &acceptor,
                &lower,
                Vec::new(),
                WAIT,
                &()
            ),
        );

        let dialled = dialled.expect("the acceptor answered");
        assert_eq!(dialled.hostname, higher);
        assert_eq!(dialled.site.as_deref(), Some("rack-b"));
        assert_eq!(dialled.software_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(dialled.instance_id, 9);

        let accepted = accepted.expect("the dialler spoke first");
        assert_eq!(accepted.hostname, lower);
        assert_eq!(accepted.site.as_deref(), Some("rack-a"));
        assert_eq!(accepted.software_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(accepted.instance_id, 7);
    }
}
