//! One live connection to every other host in the roster, and the live set the router reads.
//!
//! The overlay is a full mesh, so a fleet of `n` hosts wants `n * (n - 1) / 2` connections and
//! every host wants exactly one to each of the others. The tie-break that gets there without
//! negotiating anything is [`should_dial`]: the lexicographically lower hostname dials and the
//! higher one only accepts. Both ends compare the same two strings, so neither can decide it is
//! the dialler at the same moment as the other.
//!
//! Each dialled peer gets a task of its own. A few hundred tasks that mostly sleep cost less
//! than a scheduler that has to remember whose turn it is, and roster removal becomes an abort.
//! Everything those tasks and the accept loop learn lands in one table behind one mutex, which
//! is what [`Handle::live`] snapshots for the router.
//!
//! # A connection is not a peer
//!
//! TLS 1.3 lets a dialler finish its handshake before the acceptor has judged the key it
//! presented, so `connect()` resolving is not admission: the rejection turns up later on
//! `closed()`. Nothing is added to the live set until [`Admission`] has run, and the backoff
//! resets there and nowhere else, so a peer that accepts connections and immediately rejects
//! them is retried at 30 s rather than in a tight loop.
//!
//! # Newer wins
//!
//! A second connection from a peer that already holds a live slot is admitted first and adopted
//! only on success (D15). The common cause is a peer that restarted, or whose path changed,
//! while its old connection has not yet hit the 5 s idle timeout; keeping the stale one would
//! leave the pair dark for that whole timeout. The swap and the close of the old connection
//! happen under one lock, so the peer is never at zero or two live slots.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use ed25519_dalek::SigningKey;
use overlay_core::backoff::Backoff;
use overlay_core::config::Overlay;
use overlay_core::roster::{HostEntry, Hostname, Region, Roster, SelfIdentity};
use overlay_core::topic::table::PeerTopicTable;
use quinn::VarInt;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, watch};
use tokio::task::{AbortHandle, JoinHandle, JoinSet};

use crate::endpoint::{self, EndpointError};
use crate::hello::{ControlStream, Negotiated};
use crate::tls::{self, FailureReason, HandshakeFailure, PinEntry, PinTable, Role, SeedGeneration};

/// §5.3's reconnect floor. The first retry after a peer goes away is quick because the usual
/// cause is a sidecar restart that is already finishing.
const RECONNECT_MIN: Duration = Duration::from_millis(500);

/// §5.3's reconnect ceiling. A host that has been unreachable for a while is retried twice a
/// minute, which is what keeps a fleet-wide outage from ending in a reconnect storm (§9).
const RECONNECT_MAX: Duration = Duration::from_secs(30);

/// How many refused peers the accept loop remembers having warned about. Well above the
/// largest roster this design targets, so a fleet never reaches it, and small enough that the
/// set stays a few tens of kilobytes for a host whose open port is being probed from
/// everywhere. Past the cap a refusal is still counted, and the log stays quiet rather than
/// turning a flood of packets into a flood of lines.
const WARNED_PEERS_MAX: usize = 1024;

/// Whether this host dials `peer` or waits to be dialled by it. The lexicographically lower
/// hostname dials (§5.3), so a pair reaches one connection with nothing to negotiate and no
/// window in which both ends are dialling each other. A host never dials itself.
pub fn should_dial(me: &Hostname, peer: &Hostname) -> bool {
    me < peer
}

/// Why the overlay closed a connection, as the QUIC application error code the peer reads off
/// the close frame. Every close the manager makes carries one; a close with code 0 would tell
/// the other end nothing about whether to reconnect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CloseCode {
    /// A newer connection from the same peer passed admission and took the live slot (D15).
    Superseded,
    /// The key is a fleet key but its host is not in the roster this host is running.
    NotInRoster,
    /// The peer dialled when the tie-break says this host should have dialled it.
    WrongDirection,
    /// A roster reload removed the host.
    RosterRemoved,
    /// This sidecar is going away.
    Shutdown,
    /// The peer stayed over its fan-out budget for more than 10 s (DX-N3). Sent by T-032, which
    /// owns the budget; the code lives here so every close reason is in one enum.
    RateExceeded,
    /// The peer connected and did not finish HELLO in time (T-025).
    HelloTimeout,
    /// HELLO named a host other than the one the pin table gives the peer's key (T-025).
    HostnameMismatch,
    /// The peer sent something HELLO does not allow: a frame that did not decode, one that has
    /// no business coming first, or a topic table that contradicts itself (T-025).
    ProtocolError,
}

impl CloseCode {
    /// The application error code on the wire. The numbers are part of the protocol, so they
    /// are assigned once and never reordered.
    pub fn code(self) -> VarInt {
        VarInt::from_u32(match self {
            Self::Superseded => 1,
            Self::NotInRoster => 2,
            Self::WrongDirection => 3,
            Self::RosterRemoved => 4,
            Self::Shutdown => 5,
            Self::RateExceeded => 6,
            Self::HelloTimeout => 7,
            Self::HostnameMismatch => 8,
            Self::ProtocolError => 9,
        })
    }

    /// The text that travels beside the code, for the operator reading the peer's logs rather
    /// than for the code that reconnects.
    pub fn reason(self) -> &'static [u8] {
        match self {
            Self::Superseded => b"superseded",
            Self::NotInRoster => b"not in roster",
            Self::WrongDirection => b"wrong direction",
            Self::RosterRemoved => b"roster removed",
            Self::Shutdown => b"shutdown",
            Self::RateExceeded => b"rate exceeded",
            Self::HelloTimeout => b"hello timeout",
            Self::HostnameMismatch => b"hostname mismatch",
            Self::ProtocolError => b"protocol error",
        }
    }

    fn close(self, connection: &quinn::Connection) {
        connection.close(self.code(), self.reason());
    }
}

/// A peer that has passed admission, as [`Admission`] describes it. It is not [`Clone`]: the
/// control stream and the peer's topic table exist once per connection, and
/// [`PeerEvent::Up`] is the one path they travel from admission to the task that owns them.
#[derive(Debug)]
pub struct PeerInfo {
    /// The roster host the pin table named.
    pub hostname: Hostname,
    /// The region the peer says it fans out in, which is not always the region the roster gives
    /// it (D15).
    pub region: Region,
    /// The site label, for metrics and failure-domain reporting.
    pub site: Option<String>,
    /// Random per process start, so a second connection from the same host tells a restart from
    /// a changed path (D15).
    pub instance_id: u64,
    /// The peer's `CARGO_PKG_VERSION`, for `fleet-overlayctl status` (T-042).
    pub software_version: String,
    /// What the pair agreed to operate at.
    pub negotiated: Negotiated,
    /// The connection itself.
    pub connection: quinn::Connection,
    /// The stream HELLO travelled on, which stays open as the peer's control stream (T-027).
    pub control: ControlStream,
    /// The topic ids the peer announced in its HELLO, and the table its later `TOPIC_ADD`s
    /// extend.
    pub topics: PeerTopicTable,
}

/// What the manager tells the router as connections come and go. T-033 restarts a peer's sender
/// on the [`Down`](PeerEvent::Down) and [`Up`](PeerEvent::Up) pair a supersede produces.
// `Up` carries a connection, a stream pair and a topic table and is much the larger of the two.
// Boxing it would add an allocation per connection to save nothing: the channel holds a few
// events per peer, not a stream of them.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum PeerEvent {
    /// The peer is in the live set.
    Up(PeerInfo),
    /// The peer has left it. The code is what this host closed the connection with, and `None`
    /// when the connection ended on its own: an idle timeout, a transport error or a peer that
    /// went away, which is how a dead sibling leaves the live set within about 5 s (§9).
    Down(Hostname, Option<CloseCode>),
}

/// A live peer as the router sees it.
#[derive(Clone, Debug)]
pub struct LivePeer {
    /// The region the peer declared, which is the region its second hop fans out in. A
    /// disagreement with the roster is counted and warned about, not closed (D15).
    pub region: Region,
    /// The site label from the peer's own view of itself.
    pub site: Option<String>,
    /// The connection's round-trip estimate as it stood when the snapshot was taken. It is
    /// never carried in the table: a number read when the peer was admitted would be minutes
    /// old by the time a route plan asked for it.
    pub rtt: Duration,
    /// The peer's instance id (D15).
    pub instance_id: u64,
    /// The release the peer is running.
    pub software_version: String,
    /// What the pair agreed to operate at, which every send path consults before it builds a
    /// frame.
    pub negotiated: Negotiated,
    /// The connection to send on.
    pub connection: quinn::Connection,
}

/// Who is connected right now, in hostname order. "The live set is whatever is currently
/// connected" (§5.3), so this is a snapshot and never a subscription: a peer can leave it
/// between the read and the send, and the send is what finds out.
#[derive(Clone, Debug, Default)]
pub struct LiveView(BTreeMap<Hostname, LivePeer>);

impl LiveView {
    /// The peer, if it is live.
    pub fn get(&self, peer: &Hostname) -> Option<&LivePeer> {
        self.0.get(peer)
    }

    /// How many peers are live.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether nothing is live.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Every live peer, in hostname order.
    pub fn iter(&self) -> impl Iterator<Item = (&Hostname, &LivePeer)> {
        self.0.iter()
    }

    /// Every live peer that declared `region`, in hostname order. Striping and relay selection
    /// both derive their order from the hostname, so the order is part of the answer rather
    /// than an accident of the map (T-072, D20).
    pub fn in_region(&self, region: &Region) -> Vec<(&Hostname, &LivePeer)> {
        self.0
            .iter()
            .filter(|(_, peer)| &peer.region == region)
            .collect()
    }
}

/// Counts and gauges by name until T-041's registry exists. `()` counts nothing, which is what
/// a test that is not about a metric passes.
pub trait ManagerStats: Send + Sync {
    /// `handshake_failures_total{role, reason}`: a TLS handshake or an admission that did not
    /// produce a peer, on either loop (D14).
    fn handshake_failure(&self, failure: HandshakeFailure);

    /// `peer_auth_via_previous_seed_total{peer}`: the key that admitted the peer came from the
    /// outgoing seed, so a rotation has not converged on this pair yet (DX-N2).
    fn auth_via_previous_seed(&self, peer: &Hostname);

    /// `roster_region_mismatch_total{peer}`: the peer declared a region other than the one the
    /// roster gives it, which means a stale roster on one of the two hosts (D15).
    fn roster_region_mismatch(&self, peer: &Hostname);

    /// `unknown_frame_type_total{peer}`: a frame type this release does not define, skipped on
    /// the peer's control stream (D10). A peer one release ahead is the ordinary cause.
    fn unknown_frame_type(&self, peer: &Hostname);

    /// Every dial this host starts, before the handshake. §12 has no series for it and T-041
    /// need not add one: the tie-break is only observable from the dial path, because a host
    /// that wrongly dialled a lower peer looks exactly like one whose peer dialled first.
    fn dial_started(&self, peer: &Hostname);

    /// `peers_connected{region,site}`, by the peers' declared regions.
    fn peers_connected(&self, counts: &PeerCounts);

    /// `peers_roster{region,site}`, over every roster host but this one, so the ratio of the two
    /// gauges is the overlay-health alert §12 asks for.
    fn peers_roster(&self, counts: &PeerCounts);
}

/// Peer counts by the labels `peers_connected` and `peers_roster` carry.
pub type PeerCounts = BTreeMap<(Region, Option<String>), usize>;

impl ManagerStats for () {
    fn handshake_failure(&self, _: HandshakeFailure) {}
    fn auth_via_previous_seed(&self, _: &Hostname) {}
    fn roster_region_mismatch(&self, _: &Hostname) {}
    fn unknown_frame_type(&self, _: &Hostname) {}
    fn dial_started(&self, _: &Hostname) {}
    fn peers_connected(&self, _: &PeerCounts) {}
    fn peers_roster(&self, _: &PeerCounts) {}
}

/// Why a connection did not become a peer, and what to do about it. The two are separate
/// answers: a peer that timed out and one that named the wrong hostname are counted apart, and
/// the close code is the only thing that tells the peer whether to come back.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("admission refused: {reason}")]
pub struct AdmitError {
    /// What to count under `handshake_failures_total{role, reason}`.
    pub reason: FailureReason,
    /// What to close the connection with.
    pub close: CloseCode,
}

/// What turns an authenticated connection into a peer. It runs on every new connection, in both
/// roles, before the connection reaches the live set, and it is where the supersede decision is
/// made: a second connection from a live peer is adopted only if this succeeds on it.
///
/// `pinned` is the entry the pin table yielded for the key the peer presented, which is the
/// hostname HELLO is cross-checked against (D14). [`HelloAdmission`](crate::hello::HelloAdmission) is what the
/// sidecar runs.
pub trait Admission: Send + Sync + 'static {
    /// Admits `connection`, or says what to count for refusing it.
    fn admit(
        &self,
        connection: quinn::Connection,
        role: Role,
        pinned: &PinEntry,
    ) -> impl Future<Output = Result<PeerInfo, AdmitError>> + Send;
}

impl<A: Admission> Admission for Arc<A> {
    fn admit(
        &self,
        connection: quinn::Connection,
        role: Role,
        pinned: &PinEntry,
    ) -> impl Future<Output = Result<PeerInfo, AdmitError>> + Send {
        (**self).admit(connection, role, pinned)
    }
}

/// Everything about this host the manager needs, in one argument because they are one thing:
/// what the local side of every connection is.
#[derive(Clone)]
pub struct Local {
    /// The settings the endpoint was bound with. The dial path needs them again, because both
    /// halves of a connection run under one transport configuration (T-022).
    pub cfg: Overlay,
    /// Who this host is in the roster, which is what the tie-break compares and what a peer's
    /// declared region is checked against.
    pub self_id: SelfIdentity,
    /// The pin table every handshake is judged against, replaced under the running endpoint on
    /// a roster reload (T-043).
    pub pins: Arc<ArcSwap<PinTable>>,
    /// This host's overlay key. Always from the current seed: a host accepts the outgoing seed
    /// from its peers but never presents it (DX-N2).
    pub own_key: SigningKey,
}

/// What the manager knows about one roster host.
#[derive(Debug)]
enum Slot {
    /// A dial is in flight, or a connection is being admitted.
    Connecting,
    /// The peer is in the live set.
    Live(LivePeer),
    /// Nothing is connected and the next dial is due at this instant.
    Backoff(Instant),
}

struct Shared {
    local: Local,
    endpoint: quinn::Endpoint,
    roster: watch::Receiver<Roster>,
    events: mpsc::Sender<PeerEvent>,
    stats: Arc<dyn ManagerStats>,
    peers: Mutex<HashMap<Hostname, Slot>>,
    /// Peers already warned about on the accept loop. A rejected key has no hostname, so the
    /// rate limit is keyed by the address it came from and pruned when one is admitted. By the
    /// address rather than the socket, because a peer that reconnects from a new ephemeral port
    /// is the same peer and must not earn a second line or a second entry.
    warned: Mutex<HashSet<IpAddr>>,
    stop: watch::Sender<bool>,
}

impl Shared {
    /// The table, recovering the guard from a poisoned lock rather than propagating the panic.
    /// Nothing between a lock and its release can panic, so a poisoned mutex means some other
    /// task died holding it and the table itself is whole; refusing to serve the live set after
    /// that would take the overlay down for a reason unrelated to it.
    fn peers(&self) -> MutexGuard<'_, HashMap<Hostname, Slot>> {
        self.peers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn warned(&self) -> MutexGuard<'_, HashSet<IpAddr>> {
        self.warned
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn live(&self) -> LiveView {
        LiveView(
            self.peers()
                .iter()
                .filter_map(|(hostname, slot)| match slot {
                    Slot::Live(peer) => Some((
                        hostname.clone(),
                        LivePeer {
                            rtt: peer.connection.rtt(),
                            ..peer.clone()
                        },
                    )),
                    _ => None,
                })
                .collect(),
        )
    }

    fn live_hostnames(&self) -> Vec<Hostname> {
        self.peers()
            .iter()
            .filter(|(_, slot)| matches!(slot, Slot::Live(_)))
            .map(|(hostname, _)| hostname.clone())
            .collect()
    }

    fn set_slot(&self, peer: Hostname, slot: Slot) {
        self.peers().insert(peer, slot);
    }

    /// Sends without waiting, and from inside the state lock, so a `Down` and the `Up` that
    /// supersedes it cannot be reordered by the scheduler. Waiting there would deadlock the
    /// manager against its own consumer, and a full channel means that consumer has stopped
    /// draining, at which point its view of the live set is already wrong.
    fn emit(&self, event: PeerEvent) {
        match self.events.try_send(event) {
            Ok(()) | Err(TrySendError::Closed(_)) => {}
            Err(TrySendError::Full(event)) => {
                tracing::error!(
                    ?event,
                    "peer event channel full: the router is not draining"
                );
            }
        }
    }

    /// Puts `info` in the live slot, closing whatever was there. The whole swap is one critical
    /// section and nothing in it can block: `close` only queues a frame and `try_send` never
    /// waits. So the peer goes straight from the old connection to the new one, with no window
    /// in which the table holds two of them or none, and no await another task could deadlock
    /// against.
    fn adopt(&self, info: PeerInfo) {
        {
            let mut peers = self.peers();
            let live = LivePeer {
                region: info.region.clone(),
                site: info.site.clone(),
                // Filled in by `live`, from the connection, every time it is asked for.
                rtt: Duration::ZERO,
                instance_id: info.instance_id,
                software_version: info.software_version.clone(),
                negotiated: info.negotiated,
                connection: info.connection.clone(),
            };
            if let Some(Slot::Live(old)) = peers.insert(info.hostname.clone(), Slot::Live(live)) {
                CloseCode::Superseded.close(&old.connection);
                if old.instance_id == info.instance_id {
                    tracing::info!(peer = %info.hostname, "path changed");
                } else {
                    tracing::info!(peer = %info.hostname, was = old.instance_id, now = info.instance_id, "peer restarted");
                }
                self.emit(PeerEvent::Down(
                    info.hostname.clone(),
                    Some(CloseCode::Superseded),
                ));
            }
            self.emit(PeerEvent::Up(info));
        }
        self.publish_gauges();
    }

    /// Reports `connection` gone, unless the slot has already moved on to another one, which is
    /// what a supersede leaves behind: the old connection's watcher wakes on the close this
    /// host sent and must not report a peer that is live on a newer connection.
    fn down(&self, peer: &Hostname, connection: &quinn::Connection, code: Option<CloseCode>) {
        let current = {
            let mut peers = self.peers();
            let current = matches!(
                peers.get(peer),
                Some(Slot::Live(live)) if live.connection.stable_id() == connection.stable_id()
            );
            if current {
                peers.remove(peer);
                self.emit(PeerEvent::Down(peer.clone(), code));
            }
            current
        };
        if current {
            self.publish_gauges();
        }
    }

    /// Drops whatever the manager holds for `peer` and closes a live connection with `code`.
    fn close_peer(&self, peer: &Hostname, code: CloseCode) {
        {
            let mut peers = self.peers();
            if let Some(Slot::Live(live)) = peers.remove(peer) {
                code.close(&live.connection);
                self.emit(PeerEvent::Down(peer.clone(), Some(code)));
            }
        }
        self.publish_gauges();
    }

    fn publish_gauges(&self) {
        let mut in_roster = PeerCounts::new();
        {
            let roster = self.roster.borrow();
            for host in roster.others(&self.local.self_id.hostname) {
                *in_roster
                    .entry((host.region.clone(), host.site.clone()))
                    .or_default() += 1;
            }
        }
        let mut connected = PeerCounts::new();
        for slot in self.peers().values() {
            if let Slot::Live(peer) = slot {
                *connected
                    .entry((peer.region.clone(), peer.site.clone()))
                    .or_default() += 1;
            }
        }
        self.stats.peers_roster(&in_roster);
        self.stats.peers_connected(&connected);
    }

    /// The peer's roster entry as it stands now, which is what a declared region is compared
    /// against and what a dial reads an address from.
    fn roster_entry(&self, peer: &Hostname) -> Option<HostEntry> {
        self.roster.borrow().get(peer).cloned()
    }

    /// Records that the peer's key came from the outgoing seed, so an operator can watch a
    /// rotation converge before removing the previous seed file (DX-N2).
    fn note_seed(&self, pinned: &PinEntry) {
        if pinned.seed == SeedGeneration::Previous {
            self.stats.auth_via_previous_seed(&pinned.hostname);
        }
    }

    /// Once per admission, which is once per backoff cycle: a peer only reaches admission again
    /// after its connection was lost and redialled.
    fn check_region(&self, info: &PeerInfo, entry: &HostEntry) {
        if info.region != entry.region {
            self.stats.roster_region_mismatch(&info.hostname);
            tracing::warn!(
                peer = %info.hostname,
                declared = %info.region,
                roster = %entry.region,
                "peer declares a region the roster does not give it"
            );
        }
    }

    /// What a connection that ended has to say about admission. Only an admitted connection
    /// reaches here, on either loop; a handshake that never produced one is counted where it
    /// failed. An orderly close says nothing, which is what
    /// [`HandshakeFailure::from_connection_error`] answers `None` to, and a peer that was
    /// admitted and then went quiet is a sibling going down (§9) rather than a handshake
    /// problem, so its timeout is not counted either. Every other ending is, because a dial
    /// that resolved before the acceptor judged its key is rejected here and nowhere else.
    ///
    /// Answers whether the ending was counted, which is also what tells the dial loop that its
    /// pairing was refused rather than lost.
    fn count_close(&self, role: Role, error: &quinn::ConnectionError) -> bool {
        let counted = HandshakeFailure::from_connection_error(role, error)
            .filter(|failure| failure.reason != FailureReason::Timeout);
        if let Some(failure) = counted {
            self.stats.handshake_failure(failure);
        }
        counted.is_some()
    }

    fn warn_once(&self, remote: SocketAddr, reason: FailureReason) {
        if first_refusal(&mut self.warned(), remote.ip()) {
            tracing::warn!(%remote, %reason, "refusing an incoming connection");
        }
    }

    /// Counts and warns for an inbound connection this host will not take, and closes it with a
    /// code so the peer knows whether to come back.
    fn refuse(
        &self,
        remote: SocketAddr,
        connection: &quinn::Connection,
        reason: FailureReason,
        code: CloseCode,
    ) {
        self.stats.handshake_failure(HandshakeFailure {
            role: Role::Accept,
            reason,
        });
        self.warn_once(remote, reason);
        code.close(connection);
    }
}

/// Whether a refusal from `peer` is the first the accept loop has seen, and so the one that
/// gets a line. The set only ever grows from packets nobody has authenticated, so it stops at
/// [`WARNED_PEERS_MAX`]: past that every refusal is counted and none is logged.
fn first_refusal(warned: &mut HashSet<IpAddr>, peer: IpAddr) -> bool {
    warned.len() < WARNED_PEERS_MAX && warned.insert(peer)
}

/// The connection manager: the accept loop, one task per dialled peer, and the table they share.
pub struct ConnectionManager;

impl ConnectionManager {
    /// Starts accepting on `endpoint` and dialling every roster host this one should dial.
    /// `stats` stands in for T-041's registry, which does not exist yet.
    pub fn spawn<A: Admission>(
        local: Local,
        endpoint: quinn::Endpoint,
        roster: watch::Receiver<Roster>,
        admission: A,
        events: mpsc::Sender<PeerEvent>,
        stats: Arc<dyn ManagerStats>,
    ) -> Handle {
        let (stop, _) = watch::channel(false);
        let shared = Arc::new(Shared {
            local,
            endpoint,
            roster,
            events,
            stats,
            peers: Mutex::new(HashMap::new()),
            warned: Mutex::new(HashSet::new()),
            stop,
        });
        let admission = Arc::new(admission);
        shared.publish_gauges();
        Handle {
            accept: tokio::spawn(accept_loop(shared.clone(), admission.clone())),
            supervisor: tokio::spawn(supervise(shared.clone(), admission)),
            shared,
        }
    }
}

/// What the rest of the sidecar holds the manager by. Dropping it leaves the tasks running;
/// [`shutdown`](Self::shutdown) is how a sidecar stops cleanly.
pub struct Handle {
    shared: Arc<Shared>,
    accept: JoinHandle<()>,
    supervisor: JoinHandle<()>,
}

impl Handle {
    /// Who is connected right now.
    pub fn live(&self) -> LiveView {
        self.shared.live()
    }

    /// When the next dial to `peer` is due, for a peer that is neither live nor being dialled.
    /// A peer with no answer here is either connected, in flight, or not one this host dials.
    pub fn retry_at(&self, peer: &Hostname) -> Option<Instant> {
        match self.shared.peers().get(peer) {
            Some(Slot::Backoff(at)) => Some(*at),
            _ => None,
        }
    }

    /// Closes every live connection with [`CloseCode::Shutdown`], stops the loops and waits for
    /// them, then closes the endpoint. It returns only once nothing of the manager's is still
    /// holding the socket, which is what lets a replacement bind the same port.
    pub async fn shutdown(self) {
        for peer in self.shared.live_hostnames() {
            self.shared.close_peer(&peer, CloseCode::Shutdown);
        }
        let _ = self.shared.stop.send(true);
        let _ = self.supervisor.await;
        let _ = self.accept.await;
        self.shared
            .endpoint
            .close(CloseCode::Shutdown.code(), CloseCode::Shutdown.reason());
        self.shared.endpoint.wait_idle().await;
    }
}

/// Accepts inbound connections and hands each to a task of its own, so one slow handshake does
/// not hold up the next peer.
async fn accept_loop<A: Admission>(shared: Arc<Shared>, admission: Arc<A>) {
    let mut stop = shared.stop.subscribe();
    let mut handshakes = JoinSet::new();
    loop {
        tokio::select! {
            _ = stop.wait_for(|stop| *stop) => break,
            incoming = shared.endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                handshakes.spawn(accept_one(shared.clone(), admission.clone(), incoming));
                while handshakes.try_join_next().is_some() {}
            }
        }
    }
    handshakes.shutdown().await;
}

/// One inbound connection, from the handshake to the close.
async fn accept_one<A: Admission>(
    shared: Arc<Shared>,
    admission: Arc<A>,
    incoming: quinn::Incoming,
) {
    let remote = incoming.remote_address();
    let connection = match incoming.await {
        Ok(connection) => connection,
        Err(error) => {
            if let Some(failure) = HandshakeFailure::from_connection_error(Role::Accept, &error) {
                shared.stats.handshake_failure(failure);
                shared.warn_once(remote, failure.reason);
            }
            return;
        }
    };
    // T-021: no pin entry is an admission decision, not a missing convenience. Either the peer
    // presented nothing pinnable or its key left the table since the handshake, which is what a
    // roster reload landing mid-connection looks like.
    let Some(pinned) = tls::peer_identity(&shared.local.pins.load(), &connection) else {
        shared.refuse(
            remote,
            &connection,
            FailureReason::UnknownKey,
            CloseCode::NotInRoster,
        );
        return;
    };
    shared.note_seed(&pinned);
    let Some(entry) = shared.roster_entry(&pinned.hostname) else {
        shared.warn_once(remote, FailureReason::Hostname);
        CloseCode::NotInRoster.close(&connection);
        return;
    };
    // The peer is meant to be the one that waits. Both ends run the same comparison, so this is
    // a roster that disagrees about a hostname rather than a peer misbehaving.
    if !should_dial(&pinned.hostname, &shared.local.self_id.hostname) {
        tracing::debug!(peer = %pinned.hostname, "closing a connection this host should have dialled");
        CloseCode::WrongDirection.close(&connection);
        return;
    }
    let info = match admission
        .admit(connection.clone(), Role::Accept, &pinned)
        .await
    {
        Ok(info) => info,
        Err(error) => {
            shared.refuse(remote, &connection, error.reason, error.close);
            return;
        }
    };
    shared.warned().remove(&remote.ip());
    shared.check_region(&info, &entry);
    shared.adopt(info);

    let error = connection.closed().await;
    shared.count_close(Role::Accept, &error);
    shared.down(&pinned.hostname, &connection, None);
}

/// Keeps one connection to `peer` up, redialling with jittered backoff whenever it is not.
async fn dial_loop<A: Admission>(peer: Hostname, shared: Arc<Shared>, admission: Arc<A>) {
    let mut backoff = Backoff::new(RECONNECT_MIN, RECONNECT_MAX);
    // "Once per backoff cycle" (D14): one warn line for a peer that cannot be reached, however
    // many attempts that takes, cleared when the peer is admitted again. The counter still
    // counts every attempt, so the rate is visible without the log repeating it.
    let mut warned = false;
    loop {
        let Some(entry) = shared.roster_entry(&peer) else {
            // The reload that removed the host also aborts this task; leaving early only saves
            // a dial to an address that is no longer in the roster.
            return;
        };
        match dial_once(&peer, &entry, &shared, &admission).await {
            Ok(connection) => {
                // Admission, not the QUIC connect. The two come apart when the acceptor judges
                // the key after the dial has already resolved: admission passes, the peer
                // reaches the live set, and the refusal turns up on `closed()`. That was never
                // a pairing, so the reset is undone rather than left to redial at the floor for
                // as long as the peer keeps refusing.
                let unproven = backoff.clone();
                backoff.reset();
                warned = false;
                let error = connection.closed().await;
                if shared.count_close(Role::Dial, &error) {
                    backoff = unproven;
                }
                shared.down(&peer, &connection, None);
            }
            Err(failure) => {
                if let Some(failure) = failure {
                    shared.stats.handshake_failure(failure);
                    if !warned {
                        warned = true;
                        tracing::warn!(
                            peer = %peer,
                            remote = %entry.addr,
                            reason = %failure.reason,
                            "cannot pair with a roster host"
                        );
                    }
                }
            }
        }
        // Built at the call site: `ThreadRng` is not `Send` and this task crosses an await.
        let delay = backoff.next_delay(&mut rand::rng());
        shared.set_slot(peer.clone(), Slot::Backoff(Instant::now() + delay));
        tokio::time::sleep(delay).await;
    }
}

/// One dial, through admission and into the live set. The error is what to count, and `None`
/// when there is nothing to count for it.
async fn dial_once<A: Admission>(
    peer: &Hostname,
    entry: &HostEntry,
    shared: &Shared,
    admission: &A,
) -> Result<quinn::Connection, Option<HandshakeFailure>> {
    shared.set_slot(peer.clone(), Slot::Connecting);
    shared.stats.dial_started(peer);
    let client = tls::client_config(shared.local.pins.clone(), &shared.local.own_key, peer)
        .map_err(|error| {
            tracing::error!(peer = %peer, %error, "cannot build a client configuration");
            None
        })?;
    let connection = endpoint::connect(&shared.local.cfg, &shared.endpoint, entry.addr, client)
        .await
        .map_err(|error| match &error {
            EndpointError::Connection(closed) => {
                HandshakeFailure::from_connection_error(Role::Dial, closed)
            }
            _ => {
                tracing::debug!(peer = %peer, %error, "dial did not leave the host");
                None
            }
        })?;
    // The dialler's verifier already proved the key is this host's, so the lookup is for which
    // seed derived it. A miss means the table changed under the handshake.
    let pinned = tls::peer_identity(&shared.local.pins.load(), &connection).ok_or(Some(
        HandshakeFailure {
            role: Role::Dial,
            reason: FailureReason::KeyMismatch,
        },
    ))?;
    shared.note_seed(&pinned);
    let info = admission
        .admit(connection.clone(), Role::Dial, &pinned)
        .await
        .map_err(|error| {
            error.close.close(&connection);
            Some(HandshakeFailure {
                role: Role::Dial,
                reason: error.reason,
            })
        })?;
    shared.check_region(&info, entry);
    shared.adopt(info);
    Ok(connection)
}

/// Starts a dial task for every peer this host should dial and abandons the ones the roster no
/// longer has. A reload never touches a peer whose entry did not change, which is what keeps
/// SIGHUP from dropping connections (§5.3); a changed address takes effect at the next dial,
/// because the task reads it from the roster on every attempt.
async fn supervise<A: Admission>(shared: Arc<Shared>, admission: Arc<A>) {
    let mut roster = shared.roster.clone();
    let mut stop = shared.stop.subscribe();
    let mut dials: HashMap<Hostname, AbortHandle> = HashMap::new();
    let mut tasks = JoinSet::new();
    loop {
        let current = roster.borrow_and_update().clone();
        reconcile(&shared, &admission, &current, &mut dials, &mut tasks);
        tokio::select! {
            _ = stop.wait_for(|stop| *stop) => break,
            changed = roster.changed() => if changed.is_err() { break },
        }
    }
    tasks.shutdown().await;
}

fn reconcile<A: Admission>(
    shared: &Arc<Shared>,
    admission: &Arc<A>,
    roster: &Roster,
    dials: &mut HashMap<Hostname, AbortHandle>,
    tasks: &mut JoinSet<()>,
) {
    let me = &shared.local.self_id.hostname;
    let wanted: HashSet<Hostname> = roster
        .others(me)
        .filter(|host| should_dial(me, &host.hostname))
        .map(|host| host.hostname.clone())
        .collect();
    for peer in &wanted {
        if !dials.contains_key(peer) {
            let task = tasks.spawn(dial_loop(peer.clone(), shared.clone(), admission.clone()));
            dials.insert(peer.clone(), task);
        }
    }
    dials.retain(|peer, task| {
        let keep = wanted.contains(peer);
        if !keep {
            task.abort();
            shared.close_peer(peer, CloseCode::RosterRemoved);
        }
        keep
    });
    // A host that dialled this one has no task to abort, so its slot is closed here instead.
    let known: HashSet<&Hostname> = roster.hosts.iter().map(|host| &host.hostname).collect();
    for peer in shared.live_hostnames() {
        if !known.contains(&peer) {
            shared.close_peer(&peer, CloseCode::RosterRemoved);
        }
    }
    shared.publish_gauges();
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::testlog::LOG;
    use crate::testutil::{Builder, NodeKind, REGION, TestCluster, WAIT, eventually};

    fn host(name: &str) -> Hostname {
        Hostname(name.to_owned())
    }

    /// The tie-break that keeps a pair at one connection without negotiating anything: the
    /// lower hostname dials, the higher one only accepts. Both ends run the same comparison
    /// on the same two strings, so they cannot disagree.
    #[test]
    fn should_dial_is_true_only_for_higher_hostnames() {
        assert!(should_dial(&host("bn-a"), &host("bn-b")));
        assert!(!should_dial(&host("bn-b"), &host("bn-a")));
        assert!(!should_dial(&host("bn-a"), &host("bn-a")));
    }

    /// The whole mesh from three hosts' points of view: three connections, each host holding
    /// one to each of the other two. A second `Up` for a peer already up would mean the
    /// tie-break let both ends dial, which is what the set catches.
    #[tokio::test(flavor = "multi_thread")]
    async fn three_hosts_form_exactly_three_connections() {
        let mut cluster = TestCluster::start(3).await;

        for node in 0..3 {
            let mut up = BTreeSet::new();
            while up.len() < 2 {
                match cluster.next_event(node).await {
                    PeerEvent::Up(peer) => {
                        assert!(up.insert(peer.hostname.clone()), "{peer:?} came up twice");
                    }
                    event => panic!("node {node} reported {event:?}"),
                }
            }
        }

        for node in 0..3 {
            let live = cluster.live(node);
            assert_eq!(live.len(), 2);
            assert!(!live.is_empty());
            assert_eq!(live.iter().count(), 2);
            for (peer, live) in live.iter() {
                assert!(
                    live.rtt > Duration::ZERO,
                    "{peer} has no round-trip estimate"
                );
            }
        }
    }

    /// The tie-break has to hold on the wire and not only in [`should_dial`]: the higher
    /// hostname of a pair never starts a dial, however long it waits to be dialled.
    #[tokio::test(flavor = "multi_thread")]
    async fn higher_host_never_dials() {
        let mut cluster = TestCluster::start(2).await;
        let (lower, higher) = (cluster.hostname(0), cluster.hostname(1));

        for node in 0..2 {
            assert!(matches!(cluster.next_event(node).await, PeerEvent::Up(_)));
        }

        assert_eq!(cluster.stats(1).dials(&lower), 0);
        assert!(cluster.stats(0).dials(&higher) >= 1);
    }

    /// A host that dies leaves the live set on the keepalive timeout, with nothing said and
    /// no reload involved (§9). Its runtime is shut down rather than its endpoint dropped,
    /// because an endpoint dropped on a live runtime closes its connections politely on the
    /// way out and the peer would be told rather than left waiting.
    #[tokio::test(flavor = "multi_thread")]
    async fn peer_removed_from_live_after_idle_timeout_when_it_vanishes() {
        let mut cluster = Builder::new(&[NodeKind::Manager, NodeKind::Vanishing])
            .start()
            .await;
        let peer = cluster.hostname(1);
        assert!(matches!(cluster.next_event(0).await, PeerEvent::Up(up) if up.hostname == peer));

        cluster.vanish(1);

        assert!(matches!(cluster.next_event(0).await, PeerEvent::Down(down, None) if down == peer));
        assert!(cluster.live(0).is_empty());
    }

    /// A sidecar restart: the peer goes away and comes back on the same address, and the dial
    /// task pairs with it again on its own. `Down` first, so T-033 can throw away whatever the
    /// old connection was still carrying before the new one arrives.
    #[tokio::test(flavor = "multi_thread")]
    async fn peer_reconnects_after_restart() {
        let mut cluster = TestCluster::start(2).await;
        let peer = cluster.hostname(1);
        assert!(matches!(cluster.next_event(0).await, PeerEvent::Up(up) if up.hostname == peer));

        cluster.restart(1).await;

        assert!(matches!(cluster.next_event(0).await, PeerEvent::Down(down, _) if down == peer));
        assert!(matches!(cluster.next_event(0).await, PeerEvent::Up(up) if up.hostname == peer));
        assert_eq!(cluster.live(0).len(), 1);
    }

    /// A reload with a bigger roster dials the new host and leaves the old connection alone:
    /// the same connection afterwards, not a fresh one that happens to be up again (§5.3).
    #[tokio::test(flavor = "multi_thread")]
    async fn roster_reload_adds_a_peer_without_dropping_existing_connections() {
        let mut cluster = Builder::new(&[NodeKind::Manager; 3])
            .roster(&[0, 1])
            .start()
            .await;
        let (first, added) = (cluster.hostname(1), cluster.hostname(2));
        assert!(matches!(cluster.next_event(0).await, PeerEvent::Up(up) if up.hostname == first));
        let before = cluster.live(0).get(&first).unwrap().connection.stable_id();

        cluster.set_roster(&[0, 1, 2]);

        assert!(matches!(cluster.next_event(0).await, PeerEvent::Up(up) if up.hostname == added));
        let after = cluster.live(0).get(&first).unwrap().connection.stable_id();
        assert_eq!(
            before, after,
            "the reload replaced a connection it did not have to"
        );
        assert_eq!(cluster.live(0).len(), 2);
    }

    /// A reload that drops a host closes it, and says why: the peer reads `RosterRemoved` off
    /// the close frame and knows not to come back rather than retrying into a refusal.
    #[tokio::test(flavor = "multi_thread")]
    async fn roster_reload_removes_a_peer_and_closes_it_with_roster_removed() {
        let mut cluster = TestCluster::start(2).await;
        let peer = cluster.hostname(1);
        assert!(matches!(cluster.next_event(0).await, PeerEvent::Up(up) if up.hostname == peer));

        cluster.set_roster(&[0]);

        let event = cluster.next_event(0).await;
        assert!(
            matches!(&event, PeerEvent::Down(down, Some(CloseCode::RosterRemoved)) if *down == peer),
            "{event:?}"
        );
        assert!(cluster.live(0).is_empty());
    }

    /// A key the fleet seed derives for a name the roster does not have, which is what a host
    /// expelled from the roster still holds. The acceptor's verifier refuses it inside the
    /// handshake, so no connection ever reaches the manager and the refusal shows up only in
    /// the counter.
    #[tokio::test(flavor = "multi_thread")]
    async fn incoming_connection_with_a_key_absent_from_the_pin_table_never_reaches_the_manager() {
        let mark = LOG.len();
        let mut cluster = Builder::new(&[NodeKind::Sink, NodeKind::Manager])
            .start()
            .await;

        let refused = cluster
            .dial_as(&Hostname("bn-expelled".to_owned()), 0, 1)
            .await;

        eventually("the acceptor counts the refused key", || {
            cluster
                .stats(1)
                .handshake_failures(Role::Accept, FailureReason::UnknownKey)
                == 1
        })
        .await;
        drop(refused);
        assert!(cluster.try_next_event(1).await.is_none());
        assert!(cluster.live(1).is_empty());
        // A rejected key has no hostname, so the warn names the address it came from.
        assert_eq!(
            LOG.since(mark)
                .lines()
                .filter(|line| line.contains("refusing an incoming connection")
                    && line.contains(&cluster.addr(0).to_string()))
                .count(),
            1
        );
    }

    /// Newer wins, once it has passed admission (D15). A peer that restarted or moved is live
    /// on its new connection straight away instead of waiting out the old one's idle timeout,
    /// and the old connection is told what happened to it.
    #[tokio::test(flavor = "multi_thread")]
    async fn second_connection_from_same_peer_supersedes_the_first_after_admission() {
        let mark = LOG.len();
        let mut cluster = Builder::new(&[NodeKind::Sink, NodeKind::Manager])
            .start()
            .await;
        let peer = cluster.hostname(0);
        let first = cluster.dial_with_hello(0, 1, &cluster.self_hello(0)).await;
        let PeerEvent::Up(before) = cluster.next_event(1).await else {
            panic!("the first connection did not come up")
        };

        let _second = cluster.dial_with_hello(0, 1, &cluster.self_hello(0)).await;

        let down = cluster.next_event(1).await;
        assert!(
            matches!(&down, PeerEvent::Down(host, Some(CloseCode::Superseded)) if *host == peer),
            "{down:?}"
        );
        let PeerEvent::Up(after) = cluster.next_event(1).await else {
            panic!("the second connection did not come up")
        };
        assert_ne!(before.connection.stable_id(), after.connection.stable_id());
        assert_eq!(
            cluster.live(1).get(&peer).unwrap().connection.stable_id(),
            after.connection.stable_id()
        );

        let closed = tokio::time::timeout(WAIT, first.connection.closed())
            .await
            .unwrap();
        assert!(
            matches!(&closed, quinn::ConnectionError::ApplicationClosed(frame)
                if frame.error_code == CloseCode::Superseded.code()),
            "{closed:?}"
        );
        // Both connections come from one process and carry its instance id, so what changed is
        // the path and the line has to say so (D15).
        assert!(
            LOG.since(mark)
                .lines()
                .any(|line| line.contains("path changed") && line.contains(&peer.0)),
            "no supersede line for {peer}"
        );
    }

    /// A peer as an admission that skips HELLO would report it. The control stream is opened
    /// rather than exchanged on: [`PeerInfo`] owns one, and a test about the manager has no use
    /// for what travels on it.
    async fn admitted(pinned: &PinEntry, region: &str, connection: quinn::Connection) -> PeerInfo {
        let control = ControlStream::open(&connection, Role::Dial).await.unwrap();
        PeerInfo {
            hostname: pinned.hostname.clone(),
            region: Region(region.to_owned()),
            site: None,
            instance_id: 0,
            software_version: "test".to_owned(),
            negotiated: Negotiated {
                minor: 0,
                features: 0,
                peer_max_frame_bytes: 0,
                peer_max_batch_entries: 0,
            },
            connection,
            control,
            topics: PeerTopicTable::new(),
        }
    }

    /// Admits the first connection it is offered and refuses every one after it, standing in
    /// for the HELLO that does not check out once T-025 lands.
    #[derive(Default)]
    struct AdmitOnce {
        seen: Mutex<usize>,
    }

    impl Admission for AdmitOnce {
        fn admit(
            &self,
            connection: quinn::Connection,
            _role: Role,
            pinned: &PinEntry,
        ) -> impl Future<Output = Result<PeerInfo, AdmitError>> + Send {
            let first = {
                let mut seen = self.seen.lock().unwrap();
                *seen += 1;
                *seen == 1
            };
            let pinned = pinned.clone();
            async move {
                if first {
                    Ok(admitted(&pinned, REGION, connection).await)
                } else {
                    Err(AdmitError {
                        reason: FailureReason::Hostname,
                        close: CloseCode::HostnameMismatch,
                    })
                }
            }
        }
    }

    /// The other half of D15: a newcomer that cannot pass admission takes nothing. The peer
    /// keeps the connection it had, because dropping a working one for a suspect one is how a
    /// pair goes dark.
    #[tokio::test(flavor = "multi_thread")]
    async fn second_connection_failing_admission_leaves_the_first_live() {
        let mut cluster = Builder::new(&[NodeKind::Sink, NodeKind::Manager])
            .start_with(AdmitOnce::default())
            .await;
        let host = cluster.hostname(0);
        let _first = cluster.dial(0, 1).await.unwrap();
        let PeerEvent::Up(before) = cluster.next_event(1).await else {
            panic!("the first connection did not come up")
        };

        let _second = cluster.dial(0, 1).await.unwrap();

        assert!(cluster.try_next_event(1).await.is_none());
        assert_eq!(
            cluster.live(1).get(&host).unwrap().connection.stable_id(),
            before.connection.stable_id()
        );
        assert_eq!(
            cluster
                .stats(1)
                .handshake_failures(Role::Accept, FailureReason::Hostname),
            1
        );
    }

    /// Admits everything and puts the peer in a region of its own choosing.
    struct DeclaresRegion(&'static str);

    impl Admission for DeclaresRegion {
        fn admit(
            &self,
            connection: quinn::Connection,
            _role: Role,
            pinned: &PinEntry,
        ) -> impl Future<Output = Result<PeerInfo, AdmitError>> + Send {
            let (pinned, region) = (pinned.clone(), self.0);
            async move { Ok(admitted(&pinned, region, connection).await) }
        }
    }

    /// The region a peer declares is the region its second hop fans out in, so it is the one
    /// the live view records even when the roster disagrees. The disagreement means a stale
    /// roster on one of the two hosts, which is worth a counter and a line, not a close (D15).
    #[tokio::test(flavor = "multi_thread")]
    async fn declared_region_differing_from_roster_is_recorded_counted_and_not_closed() {
        let mut cluster = Builder::new(&[NodeKind::Sink, NodeKind::Manager])
            .start_with(DeclaresRegion("us"))
            .await;
        let host = cluster.hostname(0);
        let connection = cluster.dial(0, 1).await.unwrap();

        let PeerEvent::Up(up) = cluster.next_event(1).await else {
            panic!("the connection did not come up")
        };

        assert_eq!(up.region, Region("us".to_owned()));
        let live = cluster.live(1);
        assert_eq!(live.in_region(&Region("us".to_owned())).len(), 1);
        assert!(live.in_region(&Region(REGION.to_owned())).is_empty());
        assert_eq!(cluster.stats(1).region_mismatches(&host), 1);
        assert_eq!(connection.close_reason(), None);
    }

    /// Striping and relay selection both derive their order from the hostname (T-072, D20), so
    /// the order the live view comes back in is part of the answer and not an accident of how
    /// the peers happened to connect.
    #[tokio::test(flavor = "multi_thread")]
    async fn live_view_in_region_is_sorted_by_hostname() {
        let mut cluster = TestCluster::start(4).await;
        let expected: Vec<Hostname> = (1..4).map(|node| cluster.hostname(node)).collect();
        for _ in 0..3 {
            assert!(matches!(cluster.next_event(0).await, PeerEvent::Up(_)));
        }

        let live = cluster.live(0);
        let ordered: Vec<Hostname> = live
            .in_region(&Region(REGION.to_owned()))
            .into_iter()
            .map(|(hostname, _)| hostname.clone())
            .collect();

        assert_eq!(ordered, expected);
    }

    /// A roster host presenting a key the seed does not derive for it, which is what a
    /// mistyped address or an impostor looks like from the dial side. Every attempt is counted
    /// so the rate can be alerted on, and one line is logged for the whole backoff cycle so a
    /// fleet-wide misconfiguration does not fill the journal (D14).
    #[tokio::test(flavor = "multi_thread")]
    async fn handshake_failure_warn_is_logged_once_per_backoff_cycle_while_the_counter_counts_every_attempt()
     {
        let mark = LOG.len();
        let cluster = Builder::new(&[NodeKind::Manager, NodeKind::WrongKey])
            .start()
            .await;
        let peer = cluster.hostname(1);

        eventually("three refused dials", || {
            cluster
                .stats(0)
                .handshake_failures(Role::Dial, FailureReason::KeyMismatch)
                >= 3
        })
        .await;

        let warned = LOG
            .since(mark)
            .lines()
            .filter(|line| {
                line.contains("cannot pair with a roster host") && line.contains(&peer.0)
            })
            .count();
        assert_eq!(warned, 1);
    }

    /// A dial that resolved before the acceptor judged its key is not a pairing, so the
    /// backoff it reset has to go back where it was. Otherwise a host that every peer has
    /// dropped from its roster is redialled at the floor for as long as it keeps being
    /// dropped, which is the tight loop the reset exists to avoid.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_dial_refused_after_it_resolves_does_not_reset_the_backoff() {
        let cluster = Builder::new(&[NodeKind::Manager, NodeKind::RefusesEveryone])
            .start()
            .await;
        let peer = cluster.hostname(1);

        eventually("the backoff to grow past its floor", || {
            cluster
                .retry_at(0, &peer)
                .is_some_and(|at| at > Instant::now() + RECONNECT_MIN)
        })
        .await;

        assert!(
            cluster
                .stats(0)
                .handshake_failures(Role::Dial, FailureReason::KeyMismatch)
                >= 2
        );
    }

    /// The application error codes are protocol: a peer reads the number off the close frame,
    /// so renumbering them would leave two versions of a fleet disagreeing about why a
    /// connection went away.
    #[test]
    fn close_codes_and_their_reasons_are_fixed() {
        let wire = [
            CloseCode::Superseded,
            CloseCode::NotInRoster,
            CloseCode::WrongDirection,
            CloseCode::RosterRemoved,
            CloseCode::Shutdown,
            CloseCode::RateExceeded,
            CloseCode::HelloTimeout,
            CloseCode::HostnameMismatch,
            CloseCode::ProtocolError,
        ]
        .map(|code| {
            (
                code.code().into_inner(),
                str::from_utf8(code.reason()).unwrap().to_owned(),
            )
        });

        assert_eq!(
            wire.map(|(code, reason)| (code, reason)),
            [
                (1, "superseded".to_owned()),
                (2, "not in roster".to_owned()),
                (3, "wrong direction".to_owned()),
                (4, "roster removed".to_owned()),
                (5, "shutdown".to_owned()),
                (6, "rate exceeded".to_owned()),
                (7, "hello timeout".to_owned()),
                (8, "hostname mismatch".to_owned()),
                (9, "protocol error".to_owned()),
            ]
        );
    }

    /// The other side of a removal: a host that dialled this one has no dial task to abandon,
    /// so its slot is the only thing the reload can act on. Without that pass an expelled host
    /// would keep its way in until it disconnected of its own accord.
    #[tokio::test(flavor = "multi_thread")]
    async fn roster_reload_closes_a_removed_host_that_dialled_this_one() {
        let mut cluster = TestCluster::start(2).await;
        let dialler = cluster.hostname(0);
        assert!(matches!(cluster.next_event(1).await, PeerEvent::Up(up) if up.hostname == dialler));

        cluster.set_roster(&[1]);

        let event = cluster.next_event(1).await;
        assert!(
            matches!(&event, PeerEvent::Down(down, Some(CloseCode::RosterRemoved))
                if *down == dialler),
            "{event:?}"
        );
        assert!(cluster.live(1).is_empty());
    }

    /// The two gauges §12 compares for overlay health: how many peers the roster has and how
    /// many of them are up, both under the labels the alert groups by.
    #[tokio::test(flavor = "multi_thread")]
    async fn gauges_report_the_roster_and_the_peers_connected_to_it() {
        let mut cluster = TestCluster::start(3).await;
        for _ in 0..2 {
            assert!(matches!(cluster.next_event(0).await, PeerEvent::Up(_)));
        }
        let group = (Region(REGION.to_owned()), None);

        eventually("both peers to reach the connected gauge", || {
            cluster.stats(0).connected_gauge().get(&group) == Some(&2)
        })
        .await;

        assert_eq!(cluster.stats(0).roster_gauge().get(&group), Some(&2));
    }

    /// A host a rotation has not restarted yet still holds the outgoing seed's key, and it
    /// pairs as itself. The counter is how an operator watches a fleet converge before removing
    /// the previous seed file (DX-N2).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_peer_admitted_on_the_previous_seed_is_counted() {
        let mut cluster = Builder::new(&[NodeKind::Manager, NodeKind::PreviousSeedKey])
            .start()
            .await;
        let peer = cluster.hostname(1);

        assert!(matches!(cluster.next_event(0).await, PeerEvent::Up(up) if up.hostname == peer));

        assert_eq!(cluster.stats(0).previous_seed(&peer), 1);
        assert_eq!(cluster.stats(0).previous_seed(&cluster.hostname(0)), 0);
    }

    /// The accept loop takes its rate-limit keys from whoever sends a packet, so the set they
    /// go in needs a ceiling. Past it a refusal is still counted; only the log suppression
    /// stops, and it stops by staying quiet rather than by logging every packet.
    #[test]
    fn the_warn_set_stops_growing_at_its_cap() {
        let mut warned = HashSet::new();
        let peer = |n: u32| IpAddr::V4(Ipv4Addr::from_bits(n));

        let lines = (0..WARNED_PEERS_MAX as u32 * 2)
            .filter(|n| first_refusal(&mut warned, peer(*n)))
            .count();

        assert_eq!(lines, WARNED_PEERS_MAX);
        assert_eq!(warned.len(), WARNED_PEERS_MAX);
        assert!(!first_refusal(&mut warned, peer(0)), "one peer, one line");
    }
}
