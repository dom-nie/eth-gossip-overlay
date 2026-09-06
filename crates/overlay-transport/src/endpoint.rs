//! The one QUIC endpoint a sidecar owns: what it binds and what every connection through it
//! agrees to.

use std::time::Duration;

use overlay_core::config::Overlay;
use quinn::{IdleTimeout, VarInt};

/// The parameters every overlay connection runs under, dialled or accepted. One function
/// because there is one place to change: T-076 adds the inbound stream limits, the receive
/// windows and the initial congestion window here once there is a benchmark to move them
/// against, and everything it does not set is quinn's default on purpose.
pub fn transport_config(cfg: &Overlay) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport
        .keep_alive_interval(Some(cfg.keepalive))
        .max_idle_timeout(Some(idle_timeout(cfg.idle_timeout)));
    transport
}

/// `idle_timeout_ms` as the variable-length integer QUIC carries it in. A value too large to
/// encode saturates rather than failing the bind: an operator who asks for a timeout of 146
/// million years and one who asks for 49 days want the same thing, and neither is a reason to
/// refuse to start.
fn idle_timeout(idle: Duration) -> IdleTimeout {
    IdleTimeout::try_from(idle).unwrap_or_else(|_| IdleTimeout::from(VarInt::MAX))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use arc_swap::ArcSwap;
    use ed25519_dalek::SigningKey;
    use overlay_core::config::Overlay;
    use overlay_core::identity::{FleetSeed, Seeds, derive_tls_keypair};
    use overlay_core::roster::{HostEntry, Hostname, Region, Roster};

    use super::*;
    use crate::tls::{self, PinTable};

    fn host(name: &str) -> Hostname {
        Hostname(name.to_owned())
    }

    /// A fleet of `names` and the pin table both ends of a handshake read, derived from a seed
    /// the way the sidecar derives its own. Nothing here is a stand-in: a handshake between two
    /// of these endpoints proves what a handshake between two hosts would.
    fn fleet(names: &[&str]) -> (Seeds, Arc<ArcSwap<PinTable>>) {
        let seeds = Seeds {
            current: FleetSeed::from([0x11; 32]),
            previous: None,
        };
        let roster = Roster {
            hosts: names
                .iter()
                .map(|name| HostEntry {
                    hostname: host(name),
                    region: Region("eu".to_owned()),
                    site: None,
                    addr: "127.0.0.1:7788".parse().unwrap(),
                })
                .collect(),
        };
        let pins = Arc::new(ArcSwap::from_pointee(PinTable::build(&roster, &seeds)));
        (seeds, pins)
    }

    fn own_key(seeds: &Seeds, name: &str) -> SigningKey {
        derive_tls_keypair(&seeds.current, &host(name))
    }

    fn config(listen: &str) -> Overlay {
        Overlay {
            listen: listen.parse().unwrap(),
            ..Overlay::default()
        }
    }

    fn endpoint(
        cfg: &Overlay,
        pins: &Arc<ArcSwap<PinTable>>,
        seeds: &Seeds,
        name: &str,
    ) -> quinn::Endpoint {
        bind(
            cfg,
            tls::server_config(pins.clone(), &own_key(seeds, name)).unwrap(),
        )
        .unwrap()
    }

    fn dial_config(
        pins: &Arc<ArcSwap<PinTable>>,
        seeds: &Seeds,
        from: &str,
        to: &str,
    ) -> quinn::ClientConfig {
        tls::client_config(pins.clone(), &own_key(seeds, from), &host(to)).unwrap()
    }

    /// quinn's `TransportConfig` has setters and no getters, so its `Debug` output is the only
    /// way to read a value back out. A name that is not in it is a broken test rather than
    /// anything a sidecar could do.
    fn field(transport: &quinn::TransportConfig, name: &str) -> String {
        let debug = format!("{transport:?}");
        let (_, rest) = debug
            .split_once(&format!("{name}: "))
            .expect("TransportConfig's Debug names every field it has");
        rest.split(',')
            .next()
            .expect("split always yields at least one piece")
            .to_owned()
    }

    #[test]
    fn transport_config_uses_keepalive_and_idle_from_config() {
        let cfg = Overlay {
            keepalive: Duration::from_millis(250),
            idle_timeout: Duration::from_millis(3000),
            ..Overlay::default()
        };

        let transport = transport_config(&cfg);

        assert_eq!(field(&transport, "keep_alive_interval"), "Some(250ms)");
        assert_eq!(field(&transport, "max_idle_timeout"), "Some(3000)");
    }

    /// §5.3 asks for probing that starts at 1200 and climbs, which is what quinn does when
    /// nothing sets otherwise. Nothing here does, so this pins the default: a release that
    /// moved it would take the overlay's floor with it and no other test would notice.
    #[test]
    fn mtu_discovery_starts_at_1200() {
        let transport = transport_config(&Overlay::default());

        assert_eq!(field(&transport, "initial_mtu"), "1200");
        assert!(
            field(&transport, "mtu_discovery_config").starts_with("Some("),
            "MTU discovery is off"
        );
        let upper: u16 = field(&transport, "upper_bound")
            .parse()
            .expect("the upper bound is a UDP payload size");
        assert!(upper > 1200, "discovery probes down from {upper}, not up");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn two_endpoints_on_loopback_handshake_with_pinned_keys_and_exchange_a_stream() {
        let (seeds, pins) = fleet(&["bn-a", "bn-b"]);
        let cfg = config("127.0.0.1:0");
        let acceptor = endpoint(&cfg, &pins, &seeds, "bn-a");
        let dialler = endpoint(&cfg, &pins, &seeds, "bn-b");
        let addr = acceptor.local_addr().unwrap();

        let accepted = tokio::spawn(async move {
            let connection = acceptor
                .accept()
                .await
                .expect("the endpoint is still open")
                .await
                .unwrap();
            connection
                .accept_uni()
                .await
                .unwrap()
                .read_to_end(64)
                .await
                .unwrap()
        });

        let connection = connect(
            &cfg,
            &dialler,
            addr,
            dial_config(&pins, &seeds, "bn-b", "bn-a"),
        )
        .await
        .unwrap();
        let mut stream = connection.open_uni().await.unwrap();
        stream.write_all(b"pinned").await.unwrap();
        stream.finish().unwrap();

        assert_eq!(
            tls::peer_identity(&pins.load(), &connection)
                .unwrap()
                .hostname,
            host("bn-a")
        );
        assert_eq!(accepted.await.unwrap(), b"pinned");
    }
}
