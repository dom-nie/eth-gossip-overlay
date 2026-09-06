//! The first thing two sidecars say to each other, on the first bidirectional stream of a
//! connection.
//!
//! The TLS handshake proved which key the peer holds and the pin table said whose key it is
//! (T-021). HELLO carries what a key cannot: the name the peer believes it runs under, the region
//! it fans out in, the protocol minor and feature bits it speaks, the limits it will accept, the
//! release it is running, the process it is running as, and its whole topic table. A connection
//! is not a peer until that exchange has finished, and the stream it happened on stays open
//! afterwards as the peer's control stream, which is where `SUBS` and `TOPIC_ADD` travel (T-027).
//!
//! # Version skew
//!
//! | Difference | What happens |
//! |---|---|
//! | The protocol major | The ALPN does not match, the TLS handshake fails, and a peer on another major never reaches this module. |
//! | The protocol minor | The pair operates at the lower of the two. |
//! | A feature bit one end has never heard of | It is zero on that end, so the `AND` clears it and neither side uses it. |
//!
//! There is no version equality check anywhere. A fleet is upgraded host by host, and a pair that
//! refused to talk until both ends matched exactly would turn every rolling upgrade into an
//! outage (D29).

use std::fmt;
use std::future::Future;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use overlay_core::protocol::{
    MAX_BATCH_ENTRIES, MAX_FRAME_BYTES, PROTOCOL_MINOR, SUPPORTED_FEATURES,
};
use overlay_core::roster::{Hostname, Region, SelfIdentity};
use overlay_core::topic::table::{Announcer, OwnTopicTable, PeerTopicTable, TopicId};
use overlay_core::wire::{Frame, Hello, Read, write_frame};

use crate::manager::{Admission, AdmitError, CloseCode, ManagerStats, PeerInfo};
use crate::tls::{FailureReason, HandshakeFailure, PinEntry, Role};

/// How long a connection has to finish HELLO. It covers a peer that completes a TLS handshake and
/// then says nothing, which no QUIC timeout catches: the connection is healthy and idle.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(3);

/// A random number drawn once per process start. Two connections carrying the same id come from
/// one sidecar, so a supersede (D15) can tell a peer that restarted from one whose path changed.
pub struct InstanceId;

impl InstanceId {
    /// This process's id, the same for every connection it ever makes.
    pub fn this_process() -> u64 {
        static ID: OnceLock<u64> = OnceLock::new();
        *ID.get_or_init(rand::random)
    }
}

/// What this host puts in every HELLO it sends. Built once at startup, because none of it changes
/// while the process runs: the protocol numbers and the limits are this release's, and the rest
/// is who this host is.
#[derive(Clone, Debug)]
pub struct SelfHello {
    /// This host's roster name, which every peer checks against the key it pinned.
    pub hostname: Hostname,
    /// The region this host fans out in.
    pub region: Region,
    /// The site label, if the roster gives this host one.
    pub site: Option<String>,
    /// This process's [`InstanceId`].
    pub instance_id: u64,
}

impl SelfHello {
    /// What `self_id` (T-003) says about this host, plus the id of the process reading it.
    pub fn new(self_id: &SelfIdentity) -> Self {
        Self {
            hostname: self_id.hostname.clone(),
            region: self_id.region.clone(),
            site: self_id.site.clone(),
            instance_id: InstanceId::this_process(),
        }
    }

    /// The frame, with `topics` as the sender's whole table. An absent site travels as the empty
    /// string, because the layout has no way to say "no site" and a label nobody set reads the
    /// same either way.
    fn frame(&self, topics: Vec<(TopicId, String)>) -> Frame {
        Frame::Hello(Hello {
            minor: PROTOCOL_MINOR,
            features: SUPPORTED_FEATURES,
            max_frame_bytes: MAX_FRAME_BYTES,
            max_batch_entries: MAX_BATCH_ENTRIES,
            instance_id: self.instance_id,
            hostname: self.hostname.0.clone(),
            region: self.region.0.clone(),
            site: self.site.clone().unwrap_or_default(),
            software_version: env!("CARGO_PKG_VERSION").to_owned(),
            topics: topics
                .into_iter()
                .map(|(id, topic)| (id.get(), topic))
                .collect(),
        })
    }
}

/// What a pair agreed to operate at, which every sender consults before it builds a frame: never
/// a frame type, a flag or a behaviour the peer did not advertise, and never above the limits the
/// peer named. Both ends compute the same answer from the same two HELLOs, so neither has to be
/// told what the other decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Negotiated {
    /// The lower of the two minors.
    pub minor: u16,
    /// The bits both ends advertised.
    pub features: u64,
    /// The largest frame the peer accepts on a stream.
    pub peer_max_frame_bytes: u32,
    /// The most entries the peer accepts in one `BATCH`.
    pub peer_max_batch_entries: u16,
}

impl Negotiated {
    /// Whether the pair may use the behaviour behind `feature`, from
    /// [`overlay_core::protocol::features`].
    pub fn allows(&self, feature: u64) -> bool {
        self.features & feature == feature
    }

    fn of(hello: &Hello) -> Self {
        Self {
            // clippy sees that this release's minor is 0 and offers to drop the `min`. The rule
            // is the pair operating at the lower of the two, and the release that raises the
            // constant must not have to remember that it was written out.
            #[allow(clippy::unnecessary_min_or_max)]
            minor: PROTOCOL_MINOR.min(hello.minor),
            features: SUPPORTED_FEATURES & hello.features,
            peer_max_frame_bytes: hello.max_frame_bytes,
            peer_max_batch_entries: hello.max_batch_entries,
        }
    }
}

/// The stream HELLO travelled on, handed to the peer's task afterwards. It is the one stream both
/// ends keep open for the life of the connection, so `SUBS` and `TOPIC_ADD` never have to open
/// one and never race with the frame they follow.
#[derive(Debug)]
pub struct ControlStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl ControlStream {
    /// The dialler opens the stream, the acceptor takes the one it is offered. Whoever opened the
    /// connection knows which it is, so nothing has to be detected here.
    pub(crate) async fn open(
        connection: &quinn::Connection,
        role: Role,
    ) -> Result<Self, quinn::ConnectionError> {
        let (send, recv) = match role {
            Role::Dial => connection.open_bi().await?,
            Role::Accept => connection.accept_bi().await?,
        };
        Ok(Self { send, recv })
    }

    /// Sends one frame with its length prefix.
    pub async fn write_frame(&mut self, frame: &Frame) -> std::io::Result<()> {
        write_frame(&mut self.send, frame).await
    }

    /// Reads one frame, refusing a length prefix past what this host advertised in its own HELLO.
    pub async fn read_frame(&mut self) -> Result<Read, overlay_core::wire::ReadError> {
        overlay_core::wire::read_frame(&mut self.recv, MAX_FRAME_BYTES).await
    }
}

/// Why a connection did not get through HELLO.
#[derive(Debug, thiserror::Error)]
pub enum HelloError {
    /// The peer did not finish the exchange in time. Usually a peer that connected and then said
    /// nothing, which the QUIC idle timeout never notices because the connection is healthy.
    #[error("the peer did not finish HELLO within {0:?}")]
    Timeout(Duration),
    /// The name in HELLO is not the name the pin table gives the key the peer presented. A bug in
    /// one of the two rosters, or an attempt to be someone else.
    #[error("HELLO from the host pinned as {pinned} names {declared}")]
    HostnameMismatch {
        /// Whose key it is, according to the pin table.
        pinned: Hostname,
        /// The name HELLO claimed.
        declared: String,
    },
    /// The peer is not speaking this protocol: a frame that did not decode, a frame that has no
    /// business coming before HELLO, a topic table that contradicts itself, or a stream that
    /// ended mid-exchange. The text is for the operator; all of it counts and closes the same.
    #[error("HELLO could not be read: {0}")]
    Decode(String),
    /// The connection went away during the exchange.
    #[error("the connection closed during HELLO: {0}")]
    Closed(quinn::ConnectionError),
}

impl HelloError {
    /// What the manager counts this as and what it closes the connection with. A close code is
    /// the only thing that tells the peer whether coming back is worth its while, so a failure
    /// that is not the peer's fault must not read as one that is.
    pub fn refusal(&self, role: Role) -> AdmitError {
        match self {
            Self::Timeout(_) => AdmitError {
                reason: FailureReason::Timeout,
                close: CloseCode::HelloTimeout,
            },
            Self::HostnameMismatch { .. } => AdmitError {
                reason: FailureReason::Hostname,
                close: CloseCode::HostnameMismatch,
            },
            Self::Decode(_) => AdmitError {
                reason: FailureReason::Decode,
                close: CloseCode::ProtocolError,
            },
            // The connection is already gone, so the code goes nowhere and only the count
            // matters. quinn knows why it ended, and a rejected key ending a dial mid-HELLO is
            // the same rejection T-023 counts when it arrives a moment later on `closed()`.
            Self::Closed(error) => AdmitError {
                reason: HandshakeFailure::from_connection_error(role, error)
                    .map_or(FailureReason::Timeout, |failure| failure.reason),
                close: CloseCode::HelloTimeout,
            },
        }
    }
}

/// Runs the exchange and turns what came back into a peer.
///
/// `pinned` is the hostname the pin table yielded for the key this connection was made with, and
/// HELLO's own hostname has to equal it. `own_topics` is the sender's whole topic table as
/// [`Announcer::hello_snapshot`] handed it over, which is the only place it may come from: the
/// entries sent and the watermark recorded have to be one read of the table (D12).
///
/// The stream is returned rather than read from here. The peer's task owns it from now on.
pub async fn perform(
    connection: quinn::Connection,
    role: Role,
    self_hello: &SelfHello,
    pinned: &Hostname,
    own_topics: Vec<(TopicId, String)>,
    timeout: Duration,
    stats: &dyn ManagerStats,
) -> Result<PeerInfo, HelloError> {
    let exchange = exchange(&connection, role, self_hello, pinned, own_topics, stats);
    let (hello, control) = tokio::time::timeout(timeout, exchange)
        .await
        .map_err(|_| HelloError::Timeout(timeout))??;

    let mut topics = PeerTopicTable::new();
    topics
        .apply_snapshot(
            hello
                .topics
                .iter()
                .map(|(id, topic)| (TopicId::new(*id), topic)),
        )
        .map_err(|error| HelloError::Decode(error.to_string()))?;

    let negotiated = Negotiated::of(&hello);
    Ok(PeerInfo {
        hostname: pinned.clone(),
        // Declared, not looked up: the region a peer names is the one its second hop fans out
        // in, and T-023 is where a disagreement with the roster is counted (D15).
        region: Region(hello.region),
        site: Some(hello.site).filter(|site| !site.is_empty()),
        instance_id: hello.instance_id,
        software_version: hello.software_version,
        negotiated,
        connection,
        control,
        topics,
    })
}

/// The frames themselves: the dialler opens the stream and sends first, the acceptor answers.
/// One side has to go first for the stream to exist at all, and the side that opened the
/// connection is the obvious one.
///
/// The acceptor checks the name before it answers, so a host claiming to be someone else is told
/// nothing about this one, not even which topics it carries.
async fn exchange(
    connection: &quinn::Connection,
    role: Role,
    self_hello: &SelfHello,
    pinned: &Hostname,
    own_topics: Vec<(TopicId, String)>,
    stats: &dyn ManagerStats,
) -> Result<(Hello, ControlStream), HelloError> {
    let mut control = ControlStream::open(connection, role)
        .await
        .map_err(HelloError::Closed)?;
    let ours = self_hello.frame(own_topics);

    if role == Role::Dial {
        send(&mut control, &ours, connection).await?;
    }
    let theirs = read_hello(&mut control, connection, pinned, stats).await?;
    if theirs.hostname != pinned.0 {
        return Err(HelloError::HostnameMismatch {
            pinned: pinned.clone(),
            declared: theirs.hostname,
        });
    }
    if role == Role::Accept {
        send(&mut control, &ours, connection).await?;
    }
    Ok((theirs, control))
}

/// The peer's HELLO, skipping the frame types this release has never heard of. A newer peer may
/// send one before anything else and still be understood, which is what keeps the skip rule (D10)
/// true of the control stream too; the timeout is what bounds a peer that sends nothing else.
async fn read_hello(
    control: &mut ControlStream,
    connection: &quinn::Connection,
    peer: &Hostname,
    stats: &dyn ManagerStats,
) -> Result<Hello, HelloError> {
    loop {
        match control.read_frame().await {
            Ok(Read::Frame(Frame::Hello(hello))) => return Ok(hello),
            Ok(Read::Frame(other)) => {
                return Err(HelloError::Decode(format!(
                    "{:?} arrived before HELLO",
                    other.frame_type()
                )));
            }
            Ok(Read::Unknown(_)) => stats.unknown_frame_type(peer),
            Err(error) => return Err(stream_failed(connection, &error)),
        }
    }
}

async fn send(
    control: &mut ControlStream,
    frame: &Frame,
    connection: &quinn::Connection,
) -> Result<(), HelloError> {
    control
        .write_frame(frame)
        .await
        .map_err(|error| stream_failed(connection, &error))
}

/// A stream that failed is a connection that went away, or a peer that reset a stream it is
/// supposed to keep open for the life of the connection. quinn is asked which, because the first
/// is nobody's fault and the second is the peer not speaking this protocol.
fn stream_failed(connection: &quinn::Connection, error: &dyn fmt::Display) -> HelloError {
    match connection.close_reason() {
        Some(reason) => HelloError::Closed(reason),
        None => HelloError::Decode(format!("control stream: {error}")),
    }
}

/// This host's topic table and the record of what each peer has been told, behind one lock
/// because a HELLO snapshot has to take both in one read (D12). The mirror interns into the same
/// table from its own task (T-026).
#[derive(Debug, Default)]
pub struct OwnTopics {
    /// The ids this host assigns.
    pub table: OwnTopicTable,
    /// What each peer has been told of them.
    pub announcer: Announcer,
}

/// Admission by HELLO: a connection becomes a peer only once the exchange has finished and the
/// name checks out. It is the manager's only [`Admission`] in production.
pub struct HelloAdmission {
    self_hello: SelfHello,
    topics: Arc<Mutex<OwnTopics>>,
    stats: Arc<dyn ManagerStats>,
    timeout: Duration,
}

impl HelloAdmission {
    /// Sends `self_hello` and whatever `topics` holds at the moment each connection arrives.
    pub fn new(
        self_hello: SelfHello,
        topics: Arc<Mutex<OwnTopics>>,
        stats: Arc<dyn ManagerStats>,
    ) -> Self {
        Self {
            self_hello,
            topics,
            stats,
            timeout: HELLO_TIMEOUT,
        }
    }
}

impl Admission for HelloAdmission {
    fn admit(
        &self,
        connection: quinn::Connection,
        role: Role,
        pinned: &PinEntry,
    ) -> impl Future<Output = Result<PeerInfo, AdmitError>> + Send {
        let snapshot = {
            let mut topics = self
                .topics
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let OwnTopics { table, announcer } = &mut *topics;
            announcer.hello_snapshot(&pinned.hostname, table)
        };
        let hostname = pinned.hostname.clone();
        let self_hello = self.self_hello.clone();
        let stats = self.stats.clone();
        let timeout = self.timeout;
        async move {
            perform(
                connection,
                role,
                &self_hello,
                &hostname,
                snapshot,
                timeout,
                stats.as_ref(),
            )
            .await
            .map_err(|error| error.refusal(role))
        }
    }
}

#[cfg(test)]
mod tests {
    use overlay_core::topic::Topic;

    use super::*;
    use crate::manager::PeerEvent;
    use crate::testutil::{Builder, CountingStats, NodeKind, REGION, TestCluster, WAIT};

    /// A fork digest, as a topic string carries one.
    const DIGEST: [u8; 4] = [0x6a, 0x95, 0xa1, 0xa9];

    /// The next `Up` for `peer` on node `index`, stepping over the events its other peers cause.
    async fn next_up<A: Admission>(
        cluster: &mut TestCluster<A>,
        index: usize,
        peer: &Hostname,
    ) -> PeerInfo {
        loop {
            if let PeerEvent::Up(up) = cluster.next_event(index).await
                && up.hostname == *peer
            {
                return up;
            }
        }
    }

    /// One length-prefixed frame's worth of bytes, whatever they are, as the codec would put on
    /// a stream.
    async fn write_raw(send: &mut quinn::SendStream, body: &[u8]) {
        let mut out = (body.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(body);
        send.write_all(&out).await.unwrap();
    }

    /// A HELLO as a peer would send it, which a test then changes one field of to be the peer
    /// this release has to cope with.
    fn peer_hello(hostname: &Hostname) -> Hello {
        Hello {
            minor: PROTOCOL_MINOR,
            features: SUPPORTED_FEATURES,
            max_frame_bytes: MAX_FRAME_BYTES,
            max_batch_entries: MAX_BATCH_ENTRIES,
            instance_id: 1,
            hostname: hostname.0.clone(),
            region: REGION.to_owned(),
            site: String::new(),
            software_version: "1.2.3".to_owned(),
            topics: Vec::new(),
        }
    }

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

    /// A peer's ids arrive before anything can travel on them, which is the whole reason the
    /// table is in HELLO (D12). What the announcer handed over is what the peer ends up holding,
    /// entry for entry.
    #[tokio::test(flavor = "multi_thread")]
    async fn topic_snapshot_from_hello_populates_peer_topic_table() {
        let cluster = Builder::new(&[NodeKind::Bare; 2]).start().await;
        let (lower, higher) = (cluster.hostname(0), cluster.hostname(1));
        let mut own = OwnTopics::default();
        let topics: Vec<Topic> = (0..3)
            .map(|index| Topic::data_column(DIGEST, index))
            .collect();
        let ids: Vec<TopicId> = topics
            .iter()
            .map(|topic| own.table.intern(topic).unwrap().0)
            .collect();
        let snapshot = own.announcer.hello_snapshot(&higher, &own.table);
        let (announcing, silent) = (cluster.self_hello(0), cluster.self_hello(1));
        let (dialling, accepting) = cluster.connected_pair(0, 1).await;

        let (dialled, accepted) = tokio::join!(
            perform(
                dialling,
                Role::Dial,
                &announcing,
                &higher,
                snapshot,
                WAIT,
                &()
            ),
            perform(
                accepting,
                Role::Accept,
                &silent,
                &lower,
                Vec::new(),
                WAIT,
                &()
            ),
        );

        let accepted = accepted.unwrap();
        for (id, topic) in ids.iter().zip(&topics) {
            assert_eq!(accepted.topics.resolve(*id), Some(topic));
        }
        assert!(
            dialled.unwrap().topics.resolve(ids[0]).is_none(),
            "the acceptor announced no topics and the dialler recorded some anyway"
        );
    }

    /// The pin table already proved whose key this is, so a HELLO naming anyone else is either a
    /// roster that disagrees with itself or a host trying to be another one. Either way the
    /// connection goes, and the close code says which of the manager's refusals it was.
    #[tokio::test(flavor = "multi_thread")]
    async fn hostname_in_hello_not_matching_pinned_identity_closes_with_hostname_mismatch() {
        let cluster = Builder::new(&[NodeKind::Bare; 2]).start().await;
        let lower = cluster.hostname(0);
        let acceptor = cluster.self_hello(1);
        let (dialling, accepting) = cluster.connected_pair(0, 1).await;
        let (mut send, _recv) = dialling.open_bi().await.unwrap();
        let impostor = Hello {
            hostname: "bn-someone-else".to_owned(),
            ..peer_hello(&lower)
        };
        write_frame(&mut send, &Frame::Hello(impostor))
            .await
            .unwrap();

        let refused = perform(
            accepting,
            Role::Accept,
            &acceptor,
            &lower,
            Vec::new(),
            WAIT,
            &(),
        )
        .await
        .expect_err("the name in HELLO is not the name the key is pinned to");

        assert!(
            matches!(&refused, HelloError::HostnameMismatch { pinned, declared }
                if *pinned == lower && declared == "bn-someone-else"),
            "{refused:?}"
        );
        assert_eq!(
            refused.refusal(Role::Accept),
            AdmitError {
                reason: FailureReason::Hostname,
                close: CloseCode::HostnameMismatch,
            }
        );
    }

    /// A peer's region is where its own second hop fans out, so the peer is the authority on it
    /// and a roster that disagrees is a stale file, not an intruder. The region is recorded as
    /// declared and the connection stays up; T-023 is what counts the disagreement (D15).
    #[tokio::test(flavor = "multi_thread")]
    async fn region_in_hello_differing_from_roster_is_returned_as_declared_and_does_not_close() {
        let cluster = Builder::new(&[NodeKind::Bare; 2]).start().await;
        let lower = cluster.hostname(0);
        let acceptor = cluster.self_hello(1);
        let (dialling, accepting) = cluster.connected_pair(0, 1).await;
        let (mut send, _recv) = dialling.open_bi().await.unwrap();
        let elsewhere = Hello {
            region: "us".to_owned(),
            ..peer_hello(&lower)
        };
        write_frame(&mut send, &Frame::Hello(elsewhere))
            .await
            .unwrap();

        let peer = perform(
            accepting,
            Role::Accept,
            &acceptor,
            &lower,
            Vec::new(),
            WAIT,
            &(),
        )
        .await
        .unwrap();

        assert_eq!(peer.region, Region("us".to_owned()));
        assert_ne!(peer.region, Region(REGION.to_owned()));
        assert!(peer.connection.close_reason().is_none());
        assert!(dialling.close_reason().is_none());
    }

    /// A peer several releases ahead pairs with this one instead of refusing it: the minor drops
    /// to the lower of the two and the bits this release has never heard of are gone after the
    /// AND, so nothing here can be told to use them (D29).
    #[tokio::test(flavor = "multi_thread")]
    async fn negotiated_minor_is_the_minimum_and_features_the_intersection() {
        use overlay_core::protocol::features;

        let cluster = Builder::new(&[NodeKind::Bare; 2]).start().await;
        let lower = cluster.hostname(0);
        let acceptor = cluster.self_hello(1);
        let (dialling, accepting) = cluster.connected_pair(0, 1).await;
        let (mut send, _recv) = dialling.open_bi().await.unwrap();
        let ahead = Hello {
            minor: 7,
            features: features::DATAGRAM_BATCHES | features::STRIPING | features::REPAIR,
            ..peer_hello(&lower)
        };
        write_frame(&mut send, &Frame::Hello(ahead)).await.unwrap();

        let peer = perform(
            accepting,
            Role::Accept,
            &acceptor,
            &lower,
            Vec::new(),
            WAIT,
            &(),
        )
        .await
        .unwrap();

        // The literals rather than the constants: this release advertises minor 0 and no
        // features, and a test that reads the answer out of the same constants it is checking
        // would still pass if the negotiation stopped happening.
        assert_eq!(peer.negotiated.minor, 0);
        assert_eq!(peer.negotiated.features, 0);
        assert!(!peer.negotiated.allows(features::STRIPING));
        assert!(!peer.negotiated.allows(features::DATAGRAM_BATCHES));
        assert!(!peer.negotiated.allows(features::REPAIR));
    }

    /// The limits in [`Negotiated`] are the peer's own, not this host's and not the smaller of
    /// the two: they are what a sender is held to when it builds a frame for that peer.
    #[tokio::test(flavor = "multi_thread")]
    async fn peer_limits_are_recorded_in_negotiated() {
        let cluster = Builder::new(&[NodeKind::Bare; 2]).start().await;
        let lower = cluster.hostname(0);
        let acceptor = cluster.self_hello(1);
        let (dialling, accepting) = cluster.connected_pair(0, 1).await;
        let (mut send, _recv) = dialling.open_bi().await.unwrap();
        let modest = Hello {
            max_frame_bytes: 65_536,
            max_batch_entries: 32,
            ..peer_hello(&lower)
        };
        write_frame(&mut send, &Frame::Hello(modest)).await.unwrap();

        let peer = perform(
            accepting,
            Role::Accept,
            &acceptor,
            &lower,
            Vec::new(),
            WAIT,
            &(),
        )
        .await
        .unwrap();

        assert_eq!(peer.negotiated.peer_max_frame_bytes, 65_536);
        assert_eq!(peer.negotiated.peer_max_batch_entries, 32);
        assert!(peer.negotiated.peer_max_frame_bytes < MAX_FRAME_BYTES);
        assert!(peer.negotiated.peer_max_batch_entries < MAX_BATCH_ENTRIES);
    }

    /// A peer that finishes the TLS handshake and then says nothing holds a connection that QUIC
    /// itself is happy with: it is idle, not broken. The timeout is the only thing that ends it,
    /// and it counts as a timeout rather than as a peer that is not in the roster.
    #[tokio::test(flavor = "multi_thread")]
    async fn acceptor_times_out_when_dialer_never_sends() {
        let cluster = Builder::new(&[NodeKind::Bare; 2]).start().await;
        let lower = cluster.hostname(0);
        let acceptor = cluster.self_hello(1);
        let (_dialling, accepting) = cluster.connected_pair(0, 1).await;

        let refused = perform(
            accepting,
            Role::Accept,
            &acceptor,
            &lower,
            Vec::new(),
            Duration::from_millis(100),
            &(),
        )
        .await
        .expect_err("the dialler opened nothing and sent nothing");

        assert!(matches!(refused, HelloError::Timeout(_)), "{refused:?}");
        assert_eq!(
            refused.refusal(Role::Accept),
            AdmitError {
                reason: FailureReason::Timeout,
                close: CloseCode::HelloTimeout,
            }
        );
    }

    /// A peer sending something that is not a frame is refused, and refused the same way every
    /// time: no panic on a length that promises more than arrived, and a decode failure counted
    /// under its own reason rather than as an unknown host.
    #[tokio::test(flavor = "multi_thread")]
    async fn garbage_on_first_stream_is_decode_error_not_panic() {
        let cluster = Builder::new(&[NodeKind::Bare; 2]).start().await;
        let lower = cluster.hostname(0);
        let acceptor = cluster.self_hello(1);
        let (dialling, accepting) = cluster.connected_pair(0, 1).await;
        let (mut send, _recv) = dialling.open_bi().await.unwrap();
        // A CHUNK header that stops in the middle of its message id.
        write_raw(&mut send, &[5, 0, 0xab, 0xcd, 0xef]).await;

        let refused = perform(
            accepting,
            Role::Accept,
            &acceptor,
            &lower,
            Vec::new(),
            WAIT,
            &(),
        )
        .await
        .expect_err("those bytes are not a frame");

        assert!(matches!(refused, HelloError::Decode(_)), "{refused:?}");
        assert_eq!(
            refused.refusal(Role::Accept),
            AdmitError {
                reason: FailureReason::Decode,
                close: CloseCode::ProtocolError,
            }
        );
    }

    /// The skip rule (D10) holds on the control stream too, including before HELLO: a release
    /// that adds a frame type can send it first and still pair with this one. The counter is
    /// what tells an operator it is happening.
    #[tokio::test(flavor = "multi_thread")]
    async fn unknown_frame_type_before_hello_is_skipped_and_counted() {
        let cluster = Builder::new(&[NodeKind::Bare; 2]).start().await;
        let lower = cluster.hostname(0);
        let acceptor = cluster.self_hello(1);
        let stats = CountingStats::default();
        let (dialling, accepting) = cluster.connected_pair(0, 1).await;
        let (mut send, _recv) = dialling.open_bi().await.unwrap();
        // Type 200 with a body nothing here can read, then the HELLO behind it.
        write_raw(&mut send, &[200, 0, 1, 2, 3]).await;
        write_frame(&mut send, &Frame::Hello(peer_hello(&lower)))
            .await
            .unwrap();

        let peer = perform(
            accepting,
            Role::Accept,
            &acceptor,
            &lower,
            Vec::new(),
            WAIT,
            &stats,
        )
        .await
        .unwrap();

        assert_eq!(peer.hostname, lower);
        assert_eq!(stats.unknown_frame_types(&lower), 1);
    }

    /// A connection is not a peer (T-023): the manager holds an authenticated connection back
    /// until HELLO has been through, so nothing downstream is ever told about a peer whose name
    /// has not been checked.
    #[tokio::test(flavor = "multi_thread")]
    async fn manager_announces_up_only_after_successful_hello() {
        let mut cluster = Builder::new(&[NodeKind::Bare, NodeKind::Manager])
            .start()
            .await;
        let (peer, manager) = (cluster.hostname(0), cluster.hostname(1));
        let dialler = cluster.self_hello(0);
        let connection = cluster.dial(0, 1).await.unwrap();

        assert!(cluster.try_next_event(1).await.is_none());
        assert!(cluster.live(1).is_empty());

        let _dialled = perform(
            connection,
            Role::Dial,
            &dialler,
            &manager,
            Vec::new(),
            WAIT,
            &(),
        )
        .await
        .unwrap();

        let event = cluster.next_event(1).await;
        assert!(
            matches!(&event, PeerEvent::Up(up) if up.hostname == peer),
            "{event:?}"
        );
        assert_eq!(cluster.live(1).len(), 1);
    }

    /// The id is what tells a restarted peer from one whose path changed (D15), so it has to be
    /// the same on every connection a process makes and different after it comes back.
    #[tokio::test(flavor = "multi_thread")]
    async fn instance_id_is_one_per_process_and_changes_on_restart() {
        assert_eq!(InstanceId::this_process(), InstanceId::this_process());
        let mut cluster = TestCluster::start(3).await;
        let dialler = cluster.hostname(0);

        let at_one = next_up(&mut cluster, 1, &dialler).await;
        let at_two = next_up(&mut cluster, 2, &dialler).await;
        assert_eq!(at_one.instance_id, at_two.instance_id);

        cluster.restart(0).await;

        let after = next_up(&mut cluster, 1, &dialler).await;
        assert_ne!(after.instance_id, at_one.instance_id);
    }
}
