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

use overlay_core::budget::STREAM_RECEIVE_WINDOW;
use overlay_core::config::Overlay;
use quinn::{IdleTimeout, VarInt};
use socket2::{Domain, Protocol, Socket, Type};

use crate::tls::PLACEHOLDER_NAME;

/// What the overlay asks the kernel for on both socket buffers, which is §5.3's floor. It is a
/// constant rather than a config key because an operator raises the ceiling in `sysctl.d`
/// (T-046), not here: a key would only let a host ask for less than the design needs.
const SOCKET_BUFFER_BYTES: usize = 8 * 1024 * 1024;

/// What a burst of small-class batches may occupy in the datagram queues (§5.3, D21). One batch
/// is one datagram and a datagram is MTU-sized, so a tick that flushes one to every host of a
/// 200-host fleet is under 300 kB; this is that with room over it.
const DATAGRAM_BUFFER_BYTES: usize = 1024 * 1024;

/// What the kernel reports back for a buffer it stored `n` bytes in: Linux doubles it, every
/// other platform returns it.
const REPORTED_BUFFER_MULTIPLE: usize = if cfg!(target_os = "linux") { 2 } else { 1 };

/// Bytes one connection may have in flight before it waits for acknowledgements (§5.3).
const SEND_WINDOW: u64 = 16 * 1024 * 1024;

/// Unidirectional streams one peer may hold open at once (DX-N3). A stripe is one stream per
/// chunk, so this is what a sibling's whole slot may occupy while the receiver reads it.
const MAX_UNI_STREAMS: u32 = 64;

/// Bidirectional streams one peer may hold open at once (DX-N3), which is T-082's repair
/// exchange and nothing else.
const MAX_BIDI_STREAMS: u32 = 4;

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
    receive_window: u64,
    mut server: quinn::ServerConfig,
) -> Result<quinn::Endpoint, EndpointError> {
    let listen = cfg.listen;
    let failed = move |source| EndpointError::Bind {
        addr: listen,
        source,
    };
    server.transport_config(Arc::new(transport_config(cfg, receive_window)));
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
    receive_window: u64,
    endpoint: &quinn::Endpoint,
    addr: SocketAddr,
    mut client: quinn::ClientConfig,
) -> Result<quinn::Connection, EndpointError> {
    client.transport_config(Arc::new(transport_config(cfg, receive_window)));
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
    warn_if_socket_buffers_capped(recv, send);
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

/// The parameters every overlay connection runs under, dialled or accepted.
///
/// `receive_window` is [`MemoryBudget::receive_window`](overlay_core::budget::MemoryBudget), the
/// share of the memory limit this connection's peer may hold. It is passed in rather than
/// derived here because the budget it comes out of is a whole-process number and this function
/// sees one connection.
///
/// §5.3 also asks for MTU discovery from 1200 bytes upward and for datagrams to carry the small
/// class, and quinn does both unless a transport config says otherwise. Nothing here says
/// otherwise; the tests hold quinn to it.
pub fn transport_config(cfg: &Overlay, receive_window: u64) -> quinn::TransportConfig {
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
        .send_window(SEND_WINDOW)
        // DX-N3: quinn would let one peer open a hundred of each and hold 1.25 MB per stream.
        .max_concurrent_uni_streams(MAX_UNI_STREAMS.into())
        .max_concurrent_bidi_streams(MAX_BIDI_STREAMS.into())
        .stream_receive_window(varint(STREAM_RECEIVE_WINDOW))
        // DX-N3: what one peer may hold across all its streams at once, which is
        // `MemoryBudget`'s remainder divided by the roster. quinn's own default is unbounded.
        .receive_window(varint(receive_window));
    transport
}

/// Warns when the kernel gave the socket less than §5.3's floor, naming the sysctl that caps it.
///
/// The report is halved on Linux, which returns twice what it stored for a socket buffer
/// (`socket(7)`, `SO_RCVBUF`). A host under the floor is one where T-046's `sysctl.d` file never
/// landed, and what it shows is datagrams dropped under a burst, which names nothing.
fn warn_if_socket_buffers_capped(recv: usize, send: usize) {
    for (reported, sysctl) in [(recv, "net.core.rmem_max"), (send, "net.core.wmem_max")] {
        let effective = reported / REPORTED_BUFFER_MULTIPLE;
        if effective < SOCKET_BUFFER_BYTES {
            tracing::warn!(
                requested_bytes = SOCKET_BUFFER_BYTES,
                effective_bytes = effective,
                sysctl,
                "the kernel capped the overlay socket buffer; raise this sysctl"
            );
        }
    }
}

/// `idle_timeout_ms` as the variable-length integer QUIC carries it in. A value too large to
/// encode saturates rather than failing the bind: an operator who asks for a timeout of 146
/// million years and one who asks for 49 days want the same thing, and neither is a reason to
/// refuse to start.
fn idle_timeout(idle: Duration) -> IdleTimeout {
    IdleTimeout::try_from(idle).unwrap_or_else(|_| IdleTimeout::from(VarInt::MAX))
}

/// A window as the variable-length integer QUIC carries it in, saturating the way
/// [`idle_timeout`] does: every value passed here is a constant or a share of the memory limit,
/// both far inside the range, and neither is worth refusing to start over.
fn varint(bytes: u64) -> VarInt {
    VarInt::from_u64(bytes).unwrap_or(VarInt::MAX)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use arc_swap::ArcSwap;
    use bytes::Bytes;
    use ed25519_dalek::SigningKey;
    use overlay_core::budget::{self, MemoryBudget, SendLaneBounds};
    use overlay_core::config::{Config, Overlay};
    use overlay_core::identity::{FleetSeed, Seeds, derive_tls_keypair};
    use overlay_core::roster::{HostEntry, Hostname, Region, Roster};

    use super::*;
    use crate::testlog::LOG;
    use crate::tls::{self, PinTable};

    /// What a two-host loopback pair gives each other inbound. Nothing here fills a window, so
    /// the floor keeps every test on one number.
    const TEST_RECEIVE_WINDOW: u64 = STREAM_RECEIVE_WINDOW;

    /// T-033's lane bounds, which are what the binary passes the budget.
    const LANES: SendLaneBounds = SendLaneBounds {
        small_frames: crate::sender::SMALL_LANE_FRAMES,
        large_bytes: crate::sender::LARGE_LANE_BYTES,
        large_bytes_max: crate::sender::LARGE_QUEUED_BYTES_MAX,
    };

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
            TEST_RECEIVE_WINDOW,
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
    /// way to read a value back out. The leading space is what tells `receive_window` from
    /// `stream_receive_window`. A name that is not in it is a broken test rather than anything a
    /// sidecar could do.
    fn field(transport: &quinn::TransportConfig, name: &str) -> String {
        let debug = format!("{transport:?}");
        let (_, rest) = debug
            .split_once(&format!(" {name}: "))
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
            TEST_RECEIVE_WINDOW,
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

    /// DX-N3's inbound bounds, which are what stops one peer from holding more of this host's
    /// memory than the budget gave it. They are constants rather than keys because an operator
    /// who lowers them starves the fleet and one who raises them breaks the budget's arithmetic.
    #[test]
    fn inbound_stream_limits_are_the_named_constants() {
        let transport = transport_config(&Overlay::default(), TEST_RECEIVE_WINDOW);

        assert_eq!(field(&transport, "max_concurrent_uni_streams"), "64");
        assert_eq!(field(&transport, "max_concurrent_bidi_streams"), "4");
        assert_eq!(
            field(&transport, "stream_receive_window"),
            STREAM_RECEIVE_WINDOW.to_string()
        );
        assert_eq!(STREAM_RECEIVE_WINDOW, 1024 * 1024);
    }

    /// DX-N3's one derived parameter. A fleet's peers share the memory the other rows leave
    /// over, so twice the roster is half the window each, and the floor is where it stops: a
    /// connection allowed less than one stream's worth would stall the stream it is carrying.
    #[test]
    fn receive_window_shrinks_with_roster_size_and_never_below_the_stream_window() {
        let window = |roster: usize| {
            let budget = MemoryBudget::compute(
                &Config::default(),
                roster,
                budget::MEMORY_MAX_DEFAULT,
                LANES,
            );
            let read = field(
                &transport_config(&Overlay::default(), budget.receive_window),
                "receive_window",
            );
            assert_eq!(read, budget.receive_window.to_string());
            budget.receive_window
        };

        assert!(
            window(20) > window(200),
            "a fleet of 200 shares the same bytes with ten times the peers"
        );
        assert!(window(200) >= STREAM_RECEIVE_WINDOW);
        assert_eq!(window(100_000), STREAM_RECEIVE_WINDOW);
    }

    /// §5.3 asks the kernel for 8 MB each way and the kernel silently gives what
    /// `net.core.rmem_max` allows, so a host where T-046's sysctl file never landed runs with a
    /// buffer a burst overruns and nothing says so. The warning names the sysctl, because that
    /// is the file the operator has to fix.
    #[test]
    fn warning_logged_when_effective_socket_buffer_below_requested() {
        let mark = LOG.len();
        warn_if_socket_buffers_capped(212_992, 212_992);
        let capped = LOG.since(mark);
        assert!(capped.contains("WARN"), "{capped}");
        assert!(capped.contains("net.core.rmem_max"), "{capped}");
        assert!(capped.contains("net.core.wmem_max"), "{capped}");
        assert!(
            capped.contains(&SOCKET_BUFFER_BYTES.to_string()),
            "{capped}"
        );

        let mark = LOG.len();
        warn_if_socket_buffers_capped(usize::MAX, usize::MAX);
        let roomy = LOG.since(mark);
        assert!(!roomy.contains("WARN"), "{roomy}");
    }

    #[test]
    fn transport_config_uses_keepalive_and_idle_from_config() {
        let cfg = Overlay {
            keepalive: Duration::from_millis(250),
            idle_timeout: Duration::from_millis(3000),
            ..Overlay::default()
        };

        let transport = transport_config(&cfg, TEST_RECEIVE_WINDOW);

        assert_eq!(field(&transport, "keep_alive_interval"), "Some(250ms)");
        assert_eq!(field(&transport, "max_idle_timeout"), "Some(3000)");
    }

    /// §5.3 asks for probing that starts at 1200 and climbs, which is what quinn does when
    /// nothing sets otherwise. Nothing here does, so this pins the default: a release that
    /// moved it would take the overlay's floor with it and no other test would notice.
    #[test]
    fn mtu_discovery_starts_at_1200() {
        let transport = transport_config(&Overlay::default(), TEST_RECEIVE_WINDOW);

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
            TEST_RECEIVE_WINDOW,
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
        let transport = transport_config(&Overlay::default(), TEST_RECEIVE_WINDOW);
        assert_eq!(
            field(&transport, "datagram_send_buffer_size"),
            DATAGRAM_BUFFER_BYTES.to_string()
        );
        assert_eq!(
            field(&transport, "datagram_receive_buffer_size"),
            format!("Some({DATAGRAM_BUFFER_BYTES})")
        );

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
            TEST_RECEIVE_WINDOW,
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
                TEST_RECEIVE_WINDOW,
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
            TEST_RECEIVE_WINDOW,
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
    /// DX-N3's cap is a queue, not a refusal: a peer with more to send than 64 streams' worth
    /// waits for one to close rather than losing anything. A striping origin opens a stream per
    /// chunk, and a slot's columns are well over the cap, so this is the ordinary case rather
    /// than an abusive one.
    ///
    /// The receiver holds its 64 without reading, which is what proves the cap binds: nothing
    /// else can arrive while they are open, and everything does once they are drained.
    #[tokio::test(flavor = "multi_thread")]
    async fn streams_beyond_the_uni_cap_queue_and_all_complete_without_stall() {
        const STREAMS: u32 = 100;
        const NOTHING_FURTHER: Duration = Duration::from_millis(50);
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
            let mut held = Vec::new();
            for _ in 0..MAX_UNI_STREAMS {
                held.push(connection.accept_uni().await.unwrap());
            }
            assert!(
                tokio::time::timeout(NOTHING_FURTHER, connection.accept_uni())
                    .await
                    .is_err(),
                "a stream past the cap arrived while the cap's worth were still open"
            );

            let mut payloads = Vec::new();
            for mut stream in held {
                payloads.push(stream.read_to_end(64).await.unwrap());
            }
            for _ in MAX_UNI_STREAMS..STREAMS {
                let mut stream = connection.accept_uni().await.unwrap();
                payloads.push(stream.read_to_end(64).await.unwrap());
            }
            payloads
        });

        let connection = connect(
            &cfg,
            TEST_RECEIVE_WINDOW,
            &dialler,
            addr,
            dial_config(&pins, &seeds, "bn-b", "bn-a"),
        )
        .await
        .unwrap();
        let sent = tokio::spawn(async move {
            for index in 0..STREAMS {
                let mut stream = connection.open_uni().await.unwrap();
                stream.write_all(&index.to_le_bytes()).await.unwrap();
                stream.finish().unwrap();
            }
            // Held open, because a connection dropped here would reset the streams still in
            // flight and the receiver would see fewer than it was sent.
            std::future::pending::<()>().await;
        });

        let mut arrived: Vec<Vec<u8>> = tokio::time::timeout(Duration::from_secs(1), received)
            .await
            .expect("every stream to complete on loopback within a second")
            .unwrap();
        sent.abort();

        arrived.sort();
        let wanted: Vec<Vec<u8>> = {
            let mut all: Vec<Vec<u8>> = (0..STREAMS).map(|i| i.to_le_bytes().to_vec()).collect();
            all.sort();
            all
        };
        assert_eq!(arrived, wanted);
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
            TEST_RECEIVE_WINDOW,
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
