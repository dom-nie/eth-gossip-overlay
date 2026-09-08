//! The one QUIC endpoint a sidecar owns: what it binds and what every connection through it
//! agrees to.
//!
//! A sidecar accepts and dials on the same socket, because the overlay is a full mesh and the
//! lexicographically lower hostname is the one that dials (§5.3). There is no interface
//! selection anywhere: `overlay.listen` is `[::]:7788`, outbound follows the default route, and
//! `[::]` is opened dual-stack so a peer that only has this host's IPv4 address still arrives.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use overlay_core::config::Overlay;
use quinn::{IdleTimeout, VarInt};
use socket2::{Domain, Protocol, Socket, Type};

use crate::tls::PLACEHOLDER_NAME;

/// What the overlay asks the kernel for on both socket buffers, which is §5.3's floor. It is a
/// constant rather than a config key because an operator raises the ceiling in `sysctl.d`
/// (T-046), not here: a key would only let a host ask for less than the design needs.
const SOCKET_BUFFER_BYTES: usize = 8 * 1024 * 1024;

/// Bytes one connection may have in flight before it waits for acknowledgements (§5.3).
const SEND_WINDOW: u64 = 16 * 1024 * 1024;

/// Why the endpoint could not be brought up, or a peer could not be reached.
#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    /// The listen address could not be opened: something else holds the port, or no local
    /// interface has that address. The address is in the message because `overlay.listen` is
    /// the thing the operator can change.
    #[error("overlay endpoint: {addr}: {source}")]
    Bind {
        /// The address `overlay.listen` asked for.
        addr: SocketAddr,
        /// What the kernel said.
        source: std::io::Error,
    },
    /// quinn would not start the dial, so nothing left the host. A roster address this endpoint
    /// cannot reach at all, such as an IPv6 peer from an IPv4-only listen address.
    #[error("overlay endpoint: {0}")]
    Dial(#[from] quinn::ConnectError),
    /// The dial went out and no connection came back. T-023 hands this to
    /// [`crate::tls::HandshakeFailure::from_connection_error`] to learn whether the two ends
    /// disagreed about the roster or the peer simply never answered.
    #[error("overlay endpoint: {0}")]
    Connection(#[from] quinn::ConnectionError),
}

/// The sidecar's endpoint, listening on `overlay.listen` and dialling from the same socket.
/// `server` comes from [`crate::tls::server_config`] and carries the pin table, so which hosts
/// are allowed in is decided there and never here.
pub fn bind(
    cfg: &Overlay,
    mut server: quinn::ServerConfig,
) -> Result<quinn::Endpoint, EndpointError> {
    let listen = cfg.listen;
    let failed = move |source| EndpointError::Bind {
        addr: listen,
        source,
    };
    server.transport_config(Arc::new(transport_config(cfg)));
    let socket = bind_socket(listen).map_err(failed)?;
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(failed)
}

/// Dials `addr` and waits for the handshake. `client` comes from [`crate::tls::client_config`]
/// and already knows which host it expects to find there, so the name in SNI is the placeholder
/// nobody reads and there is no hostname to pass.
pub async fn connect(
    cfg: &Overlay,
    endpoint: &quinn::Endpoint,
    addr: SocketAddr,
    mut client: quinn::ClientConfig,
) -> Result<quinn::Connection, EndpointError> {
    client.transport_config(Arc::new(transport_config(cfg)));
    Ok(endpoint
        .connect_with(client, addr, PLACEHOLDER_NAME)?
        .await?)
}

/// The UDP socket quinn runs on, sized and bound before quinn sees it.
///
/// `IPV6_V6ONLY` off is what makes `[::]` dual-stack: with it on, a peer dialling this host's
/// IPv4 address is answered by nothing at all. It says nothing about an IPv4 listen address and
/// the kernel rejects it there, so it goes with the family rather than unconditionally.
///
/// The requested buffer sizes are logged beside what came back because the kernel silently caps
/// them at `net.core.rmem_max` and `net.core.wmem_max`, and on Linux reports twice what it
/// stored. An operator who sees the effective size fall short of the request is looking at a
/// host where the sysctl file from T-046 never landed.
fn bind_socket(listen: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    let socket = Socket::new(
        Domain::for_address(listen),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    if listen.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    socket.set_recv_buffer_size(SOCKET_BUFFER_BYTES)?;
    socket.set_send_buffer_size(SOCKET_BUFFER_BYTES)?;
    socket.bind(&listen.into())?;

    let (recv, send) = (socket.recv_buffer_size()?, socket.send_buffer_size()?);
    let socket = std::net::UdpSocket::from(socket);
    tracing::info!(
        listen = %socket.local_addr()?,
        requested_bytes = SOCKET_BUFFER_BYTES,
        recv_buffer_bytes = recv,
        send_buffer_bytes = send,
        "overlay endpoint bound"
    );
    Ok(socket)
}

/// The parameters every overlay connection runs under, dialled or accepted, in the one place
/// T-076 edits when it adds the inbound stream limits, the receive windows and the initial
/// congestion window.
///
/// §5.3 also asks for MTU discovery from 1200 bytes upward and for datagrams to carry the small
/// class, and quinn does both unless a transport config says otherwise. Nothing here says
/// otherwise; the tests hold quinn to it.
pub fn transport_config(cfg: &Overlay) -> quinn::TransportConfig {
    let mut cubic = quinn::congestion::CubicConfig::default();
    // §5.3: a connection carrying one block every 12 s spends every block near slow start with
    // the RFC's ~14 kB window, and the fleet's paths are ones the operator controls end to end.
    cubic.initial_window(cfg.initial_window_bytes);

    let mut transport = quinn::TransportConfig::default();
    transport
        .keep_alive_interval(Some(cfg.keepalive))
        .max_idle_timeout(Some(idle_timeout(cfg.idle_timeout)))
        .congestion_controller_factory(Arc::new(cubic))
        // §5.3: four block-equivalents (§10's 200 kB block) is the floor a stripe and the
        // batches beside it need in flight; T-033's 64 MiB process cap is what actually bounds
        // what reaches quinn, so this sits well above the floor rather than on it.
        .send_window(SEND_WINDOW);
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
    use bytes::Bytes;
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

    /// A runtime of its own, so a test can take one away and leave the other running.
    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
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

    /// The congestion window a dialled connection starts with, which is the only place
    /// `initial_window_bytes` becomes visible: quinn keeps the congestion controller out of
    /// `TransportConfig`'s `Debug`, and `stats()` reads it off the live connection instead.
    async fn initial_congestion_window(initial_window_bytes: u64) -> u64 {
        let (seeds, pins) = fleet(&["bn-a", "bn-b"]);
        let cfg = Overlay {
            initial_window_bytes,
            ..config("127.0.0.1:0")
        };
        let acceptor = endpoint(&cfg, &pins, &seeds, "bn-a");
        let dialler = endpoint(&cfg, &pins, &seeds, "bn-b");
        let addr = acceptor.local_addr().unwrap();
        tokio::spawn(async move {
            let _held = acceptor
                .accept()
                .await
                .expect("the endpoint is still open")
                .await
                .unwrap();
            std::future::pending::<()>().await;
        });

        connect(
            &cfg,
            &dialler,
            addr,
            dial_config(&pins, &seeds, "bn-b", "bn-a"),
        )
        .await
        .unwrap()
        .stats()
        .path
        .cwnd
    }

    /// §5.3's reason for the key: a connection carrying one block every 12 s never leaves slow
    /// start with the RFC's ~14 kB window, so the operator sets where it starts. Both ends of
    /// the comparison are configured values, because the assertion has to fail when nothing
    /// reads the key at all.
    #[tokio::test(flavor = "multi_thread")]
    async fn transport_config_applies_initial_window_from_config() {
        assert!(initial_congestion_window(3_000_000).await >= 3_000_000);
        assert!(initial_congestion_window(30_000).await < 3_000_000);
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

    /// Datagrams carry the small class from v2 (§5.3). quinn offers them unless a transport
    /// config sizes the receive buffer at nothing, and nothing here does, so the check is that
    /// one crosses rather than that a field holds a number: sending needs the peer to have
    /// advertised a datagram frame size during the handshake, which no assertion on this side
    /// would notice.
    #[tokio::test(flavor = "multi_thread")]
    async fn datagrams_are_enabled_and_delivered_on_loopback() {
        let (seeds, pins) = fleet(&["bn-a", "bn-b"]);
        let cfg = config("127.0.0.1:0");
        let acceptor = endpoint(&cfg, &pins, &seeds, "bn-a");
        let dialler = endpoint(&cfg, &pins, &seeds, "bn-b");
        let addr = acceptor.local_addr().unwrap();

        let received = tokio::spawn(async move {
            let connection = acceptor
                .accept()
                .await
                .expect("the endpoint is still open")
                .await
                .unwrap();
            connection.read_datagram().await.unwrap()
        });

        let connection = connect(
            &cfg,
            &dialler,
            addr,
            dial_config(&pins, &seeds, "bn-b", "bn-a"),
        )
        .await
        .unwrap();
        connection
            .send_datagram(Bytes::from_static(b"batch"))
            .unwrap();

        assert_eq!(received.await.unwrap(), Bytes::from_static(b"batch"));
    }

    /// A host that stops answering without saying goodbye. The peer runs on a runtime of its
    /// own and that runtime is dropped whole, which is the only way to reach this: an endpoint
    /// dropped on a live runtime closes its connections politely on the way out, and the
    /// dialler would be told rather than left waiting.
    #[test]
    fn silent_peer_is_closed_after_idle_timeout() {
        let (seeds, pins) = fleet(&["bn-a", "bn-b"]);
        let cfg = Overlay {
            keepalive: Duration::from_millis(50),
            idle_timeout: Duration::from_millis(200),
            ..config("127.0.0.1:0")
        };
        let peer = runtime();
        let addr = peer.block_on(async {
            let acceptor = endpoint(&cfg, &pins, &seeds, "bn-a");
            let addr = acceptor.local_addr().unwrap();
            tokio::spawn(async move {
                let _held = acceptor
                    .accept()
                    .await
                    .expect("the endpoint is still open")
                    .await
                    .unwrap();
                std::future::pending::<()>().await;
            });
            addr
        });

        let error = runtime().block_on(async {
            let dialler = endpoint(&cfg, &pins, &seeds, "bn-b");
            let connection = connect(
                &cfg,
                &dialler,
                addr,
                dial_config(&pins, &seeds, "bn-b", "bn-a"),
            )
            .await
            .unwrap();
            peer.shutdown_background();
            tokio::time::timeout(Duration::from_millis(500), connection.closed())
                .await
                .expect("the idle timeout is 200 ms")
        });

        assert!(matches!(error, quinn::ConnectionError::TimedOut), "{error}");
    }

    /// `[::]` has to answer a peer that knows only this host's IPv4 address, which is the whole
    /// reason `set_only_v6(false)` runs before the bind. Linux is where the option is needed and
    /// where the fleet runs, so the test is gated rather than written to whatever another
    /// platform happens to default to.
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread")]
    async fn dual_stack_bind_accepts_ipv4_mapped_dial() {
        let (seeds, pins) = fleet(&["bn-a", "bn-b"]);
        let acceptor = endpoint(&config("[::]:0"), &pins, &seeds, "bn-a");
        let port = acceptor.local_addr().unwrap().port();
        let cfg = config("127.0.0.1:0");
        let dialler = endpoint(&cfg, &pins, &seeds, "bn-b");

        let accepted = tokio::spawn(async move {
            acceptor
                .accept()
                .await
                .expect("the endpoint is still open")
                .await
                .unwrap()
        });

        let connection = connect(
            &cfg,
            &dialler,
            SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port)),
            dial_config(&pins, &seeds, "bn-b", "bn-a"),
        )
        .await
        .unwrap();

        assert_eq!(
            tls::peer_identity(&pins.load(), &connection)
                .unwrap()
                .hostname,
            host("bn-a")
        );
        assert_eq!(
            tls::peer_identity(&pins.load(), &accepted.await.unwrap())
                .unwrap()
                .hostname,
            host("bn-b")
        );
    }
    /// `overlay.listen` is the one thing an operator can change here, so the error names it.
    /// A bare "address already in use" leaves them guessing which of the sidecar's ports it
    /// means.
    #[tokio::test(flavor = "multi_thread")]
    async fn bind_failure_reports_address_in_error() {
        let (seeds, pins) = fleet(&["bn-a"]);
        let held = endpoint(&config("127.0.0.1:0"), &pins, &seeds, "bn-a");
        let taken = held.local_addr().unwrap();

        let error = bind(
            &Overlay {
                listen: taken,
                ..Overlay::default()
            },
            tls::server_config(pins.clone(), &own_key(&seeds, "bn-a")).unwrap(),
        )
        .unwrap_err();

        assert!(
            matches!(&error, EndpointError::Bind { addr, .. } if *addr == taken),
            "{error}"
        );
        assert!(error.to_string().contains(&taken.to_string()), "{error}");
    }
}
