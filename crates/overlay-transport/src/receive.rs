//! What a peer sends this host, on its way into the beacon node.
//!
//! One task per live peer reads both carriers. It accepts unidirectional streams and reads the
//! frames off each, and it reads the peer's datagrams, which is where the small class arrives
//! (§5.3). A whole message is a `CHUNK` with `k = 1, m = 0`; any other chunk is one piece of a
//! striped message, which this host offers to the rest of its region and hands to the
//! [`Reassembler`] the message is put back together in. A `BATCH` feeds each entry
//! through the same path on either carrier, because an entry names its own topic and an id this
//! host cannot resolve costs that entry alone (D21).
//!
//! The two carriers differ in what a frame this release cannot read costs. A stream has a `u32`
//! length prefix, so an unknown frame type is stepped over and reading goes on; a datagram is
//! one frame and nothing else, so an unknown type there drops the datagram (D10).
//!
//! # The order every payload is checked in
//!
//! | Step | What a miss costs (§12) |
//! |---|---|
//! | resolve the topic id through the sender's own table (D13) | `unknown_topic_id_total{peer}`, this entry only |
//! | classify by topic kind and payload length (D02) | nothing; the class labels the counters below |
//! | gate on the mirror's advertised set (DX-N1) | `unwanted_topic_total{peer}` |
//! | compute the message id and check the snappy branch (D03) | `invalid_payload_total{peer}` and a warn once per connection |
//! | insert into the seen cache, site 2 of 3 (D08) | `duplicates_dropped_total{source="overlay"}` |
//! | queue it for publish (DX-N4) | `first_seen_total{source="overlay"}` on the way in |
//!
//! A message reassembled from chunks takes the last three of those steps in the same order, at
//! its own site (D08 site 3 of 3), with the id already computed by the reassembler as part of
//! deciding the message is the one its chunks claimed.
//!
//! `messages_total` and `bytes_total` count everything that resolved to a topic, whether or not
//! it is published, so the two ends of a connection agree on what crossed it.
//!
//! # Nothing here waits for the beacon node
//!
//! The only awaits are accepting a stream, reading a frame and reading a datagram. Publishing
//! is a push into T-017's bounded queue and returns whether or not anything is draining it
//! (DX-N4), so a wedged beacon node costs queue drops and never a stalled stream. Every read is
//! bounded twice: by [`MAX_FRAME_BYTES`] before a body is allocated, and by
//! [`STREAM_READ_TIMEOUT`], after which the stream is closed and the rest of the connection
//! carries on.
//!
//! # One hop, and the one thing that gets a second
//!
//! A message from the overlay is published locally and goes no further (§3 principle 1): only
//! what the beacon node hands this host enters the overlay, through [`crate::fanout`], which
//! this module holds nothing of. That is what keeps duplicates bounded by the number of beacon
//! nodes that received a message from public gossip (§5.5).
//!
//! There are two exceptions, both handed to the receiver rather than reached for, and both
//! through [`Relaying`]: a `BATCH` carrying `RELAY` from a peer in another region, which asks
//! this host to fan it out inside its own (D11, D20), and a `CHUNK` arriving without
//! `FORWARDED`, which this host passes to the rest of its region the moment it lands (D19).
//! Both are metered the same way: the bytes are charged to the peer's fan-out budget, and a peer
//! that asks for more of it than its share closes (DX-N3).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use overlay_core::budget::{Charge, FanoutBudget, FanoutKind};
use overlay_core::config::LargeClass;
use overlay_core::custody::SharedCustody;
use overlay_core::events::{self, FirstArrival};
use overlay_core::header::Header;
use overlay_core::msgid::{self, Branch, MessageId};
use overlay_core::protocol::{MAX_FRAME_BYTES, features};
use overlay_core::pubqueue::{PublishItem, PublishSink};
use overlay_core::reassemble::{Outcome, Reason, Reassembler};
use overlay_core::recent::SharedRecentLarge;
use overlay_core::repair::Outcome as RepairOutcome;
use overlay_core::roster::{Hostname, Region, SelfIdentity};
use overlay_core::rs::{self, Params};
use overlay_core::seen::SharedSeenCache;
use overlay_core::subs::PeerState;
use overlay_core::time::Clock;
use overlay_core::topic::table::TopicId;
use overlay_core::topic::{Class, SubscriptionSets, Topic};
use overlay_core::wire::{
    self, BatchEntry, BatchFlags, Chunk, ChunkFlags, Frame, Read, RepairReq, RepairResp,
};
use quinn::VarInt;
use tokio::io::AsyncRead;
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

use crate::batching::{BatchHandle, Small};
use crate::fanout::{Direction, PeerLabels, TrafficStats};
use crate::hello::OwnTopics;
use crate::manager::{CloseCode, LivePeer, LiveSource, ManagerStats, PeerInfo};
use crate::subs;

/// How long one frame may take to arrive once its stream has started (DX-N3). A peer that opens
/// a stream and stops writing holds a slot in the receive window until this fires; T-076 takes
/// the constant over when it tunes the transport.
pub const STREAM_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// What a stalled stream is stopped with. The peer learns nothing from the number, so it is the
/// unremarkable zero; the connection's own codes are [`CloseCode`](crate::manager::CloseCode).
const STALLED_STREAM_CODE: u32 = 0;

/// Repair exchanges one peer may have running at once (D24).
///
/// The same number as the connection's own `max_concurrent_bidi_streams` (DX-N3), so a peer that
/// honours the parameters it was given never reaches this and one that ignores them is held to
/// the same count here, where the work is.
pub const MAX_REPAIR_STREAMS_PER_PEER: usize = crate::endpoint::MAX_BIDI_STREAMS as usize;

/// Where the receive path counts. Every method is about one peer's traffic, so `source="overlay"`
/// is implied on the two counters that carry it rather than passed: T-041 binds
/// [`first_seen`](Self::first_seen) and [`duplicate`](Self::duplicate) under that label, the way
/// T-016's stats are bound under `source="bn"`. `()` counts nothing.
pub trait ReceiveStats: ManagerStats + TrafficStats {
    /// `unknown_topic_id_total{peer}`: an id the peer has not announced. Only this entry is
    /// dropped; the stream and the connection carry on (D12).
    fn unknown_topic_id(&self, peer: &Hostname);

    /// `unwanted_topic_total{peer}`: a topic outside this host's advertised set, which the
    /// beacon node never asked for (DX-N1).
    fn unwanted_topic(&self, peer: &Hostname);

    /// `invalid_payload_total{peer}`: the payload took the invalid snappy branch, declared more
    /// than the maximum, or came under an id that is not the one it hashes to (D03).
    fn invalid_payload(&self, peer: &Hostname);

    /// `first_seen_total{class, source="overlay"}`: the overlay reached this host before the
    /// beacon node did, which is the win rate the canary is judged on (§12).
    fn first_seen(&self, class: Class);

    /// `duplicates_dropped_total{class, source="overlay"}`: the seen cache already held the id.
    fn duplicate(&self, class: Class);

    /// `fanout_suppressed_total{peer, kind}`: the peer asked for more second-hop work than its
    /// budget covers, so it was delivered locally and fanned out nowhere (DX-N3). §12 alerts on
    /// any non-zero value.
    fn fanout_suppressed(&self, peer: &Hostname, kind: FanoutKind);

    /// `relayed_batches_total`: one `RELAY` batch fanned out inside this host's region. A batch
    /// holding nothing this host had not already seen re-fans nothing and is not counted (D20).
    fn relayed_batch(&self);

    /// `relay_same_region_total{peer}`: a peer in this host's own region asked for a re-fan.
    /// No sender does that, so it is the peer breaking the protocol; the entries are delivered
    /// locally and forwarded nowhere (D20).
    fn relay_same_region(&self, peer: &Hostname);

    /// `chunks_received_total`: one chunk of a striped message read off a peer, whether it is
    /// one this host was assigned or the in-region copy of somebody else's (§12). The flags and
    /// the header are what a test reads to tell the two hops apart.
    fn chunk_received(&self, peer: &Hostname, flags: ChunkFlags, chunk: &Chunk);

    /// `parity_used_total`: a message that needed a parity chunk to come back, which means a
    /// host was down or a chunk was lost on the way (§5.4 step 4).
    fn parity_used(&self);

    /// `reconstruct_seconds{class}`: how long a message took from its first chunk to the moment
    /// it was queued for the beacon node.
    fn reconstructed(&self, class: Class, took: Duration);

    /// `repair_requests_total{outcome}`: one repair request and what it came to, `gave_up`
    /// included, which is the one that stands for a request nobody was left to send (§12, D24).
    fn repair_request(&self, outcome: RepairOutcome);
}

impl ReceiveStats for () {
    fn unknown_topic_id(&self, _: &Hostname) {}
    fn unwanted_topic(&self, _: &Hostname) {}
    fn invalid_payload(&self, _: &Hostname) {}
    fn first_seen(&self, _: Class) {}
    fn duplicate(&self, _: Class) {}
    fn fanout_suppressed(&self, _: &Hostname, _: FanoutKind) {}
    fn relayed_batch(&self) {}
    fn relay_same_region(&self, _: &Hostname) {}
    fn chunk_received(&self, _: &Hostname, _: ChunkFlags, _: &Chunk) {}
    fn parity_used(&self) {}
    fn reconstructed(&self, _: Class, _: Duration) {}
    fn repair_request(&self, _: RepairOutcome) {}
}

/// What a payload's arrival owes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Delivery {
    /// This host's own: published if its beacon node wants the topic, dropped if not (DX-N1).
    Local,
    /// The same, and what was new to the seen cache is owed to this host's region as well,
    /// because a `RELAY` batch carried it (D20).
    Relayed,
}

/// What every peer's receiver shares: the caches, the queue and the hooks that belong to the
/// host rather than to one connection.
#[derive(Clone)]
pub struct Deps {
    /// The seen cache all three insert sites share (D08).
    pub seen: SharedSeenCache,
    /// Where a message this host reassembled is kept so a peer can repair it from here (§5.6).
    /// The beacon node link (T-016) holds the other handle to the same store.
    pub recent: SharedRecentLarge,
    /// What the beacon node's columns are owed and which have arrived (§6.4, T-083). Every
    /// recent-store insert that decoded a header tells it what it saw; the repair task reads it.
    pub custody: SharedCustody,
    /// T-017's publish queue, behind the trait that keeps `overlay-transport` clear of libp2p.
    pub publish: Arc<dyn PublishSink>,
    /// What the mirror says the beacon node is subscribed to, which is the gate (DX-N1).
    pub sets: watch::Receiver<SubscriptionSets>,
    /// Where a chunk that is not a whole message goes: the chunks are collected here, the
    /// forwarded bitmap and the completed set D19 reads live here, and this is what answers with
    /// the message once k of them have arrived.
    pub reassembler: Arc<Reassembler>,
    /// Where every counter above lands.
    pub stats: Arc<dyn ReceiveStats>,
    /// Who this host is, which the event log names as the host that saw the message.
    pub node: Arc<SelfIdentity>,
    /// The clock the arrival time in that event is read from.
    pub clock: Arc<dyn Clock>,
    /// The budget each peer gets a copy of. A bucket that starts full is what a peer that
    /// connects an hour later would have anyway, since a refill saturates at the capacity.
    pub budget: FanoutBudget,
    /// The split every host of the fleet cuts a large message into, which is how a repair
    /// answer rebuilds the chunks a peer is asking for from the payload the recent store kept
    /// (§5.6). The same file on every host, so the chunks come out the same as the origin's.
    pub large: LargeClass,
    /// What the two second hops are made with.
    pub relaying: Relaying,
}

/// The second hop, as the receive path is handed it: what this host needs to fan a `RELAY`
/// batch out inside its own region (D20) and to pass a chunk on to it (D19), and nothing more.
/// Nothing else here can send, which is what makes one hop structural for everything but these
/// two.
#[derive(Clone)]
pub struct Relaying {
    /// The live set, read once per batch or chunk for the in-region subscribers of its topic.
    pub live: LiveSource,
    /// This host's own topic ids, which a re-fanned entry or a forwarded chunk travels under: a
    /// frame is named by whoever sends it, and this host is the sender of the second hop (D13).
    pub topics: Arc<Mutex<OwnTopics>>,
    /// The batcher the entries are re-coalesced through, so each in-region subscriber gets one
    /// batch holding only what it asked for (D21). Chunks do not pass through it: a chunk is
    /// large class and travels on a stream of its own (§5.4).
    pub batches: BatchHandle,
}

/// One peer's receiver. Dropping it stops the task: everything it holds belongs to a connection,
/// and a connection that is gone has nothing left to read.
pub struct PeerReceiver {
    ctx: Arc<Ctx>,
    connection: quinn::Connection,
    task: JoinHandle<()>,
}

impl PeerReceiver {
    /// Starts reading `peer`'s streams. One of these per live peer, started from
    /// [`PeerEvent::Up`](crate::manager::PeerEvent::Up) and dropped on its `Down`.
    pub fn spawn(peer: &PeerInfo, deps: Deps) -> Self {
        let ctx = Arc::new(Ctx {
            peer: peer.hostname.clone(),
            region: peer.region.clone(),
            site: peer.site.clone(),
            state: peer.state.clone(),
            budget: Mutex::new(deps.budget.clone()),
            deps,
            warned_invalid: AtomicBool::new(false),
        });
        Self {
            task: tokio::spawn(read_peer(peer.connection.clone(), ctx.clone())),
            connection: peer.connection.clone(),
            ctx,
        }
    }

    /// Charges this peer's fan-out budget for `bytes` of second-hop work, counting a refusal
    /// and closing the connection when the peer has been over budget for too long (DX-N3). The
    /// datagram loop charges `kind = Relay` for every `RELAY` batch; T-073 charges `Chunk`.
    pub fn charge(&self, kind: FanoutKind, bytes: usize, now: Instant) -> Charge {
        let charge = self.ctx.charge(kind, bytes, now);
        if charge == Charge::CloseRateExceeded {
            close_rate_exceeded(&self.ctx.peer, kind, &self.connection);
        }
        charge
    }
}

/// Ends a connection whose peer has been over its fan-out budget for longer than
/// [`SUSTAINED_VIOLATION`](overlay_core::budget::SUSTAINED_VIOLATION). The peer comes back
/// through the ordinary reconnect backoff, which is what makes this a pause and not a
/// punishment (DX-N3).
fn close_rate_exceeded(peer: &Hostname, kind: FanoutKind, connection: &quinn::Connection) {
    tracing::warn!(
        %peer,
        kind = kind.as_str(),
        "closing a peer that has been over its fan-out budget for too long"
    );
    CloseCode::RateExceeded.close(connection);
}

impl Drop for PeerReceiver {
    // mutants::skip: a receiver is only ever dropped for a connection that has already gone,
    // where the task ends on its own as soon as the accept fails, so no test in this suite can
    // tell the abort from its absence. It is here for a handle dropped while its connection is
    // still up, which would otherwise leave a task reading a peer nothing owns any more.
    #[cfg_attr(test, mutants::skip)]
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Where the chunks a `REPAIR_RESP` carried go (T-082).
///
/// It is the peer's own receiver context, built from the live view rather than handed over by a
/// [`PeerEvent::Up`](crate::manager::PeerEvent::Up), so a repaired chunk takes the same
/// [`Reassembler::on_chunk`], the same completion and the same publish queue as one that arrived
/// on that peer's stream. There is deliberately no second ingest path: what completion owes,
/// from the seen cache to the `first_arrival` event, is owed the same whether the last chunk was
/// asked for or not.
pub struct RepairSink(Ctx);

impl RepairSink {
    /// Where to put what `peer` answers a repair request with. One per attempt, so the peer's
    /// one line about a payload that did not check out stays one line.
    pub fn new(deps: &Deps, peer: &Hostname, live: &LivePeer) -> Self {
        Self(Ctx {
            peer: peer.clone(),
            region: live.region.clone(),
            site: live.site.clone(),
            state: live.state.clone(),
            budget: Mutex::new(deps.budget.clone()),
            deps: deps.clone(),
            warned_invalid: AtomicBool::new(false),
        })
    }

    /// One repaired chunk, answering whether it was the one that put the message back together.
    ///
    /// The responder set `FORWARDED` and the reassembler honours it, so nothing repaired is
    /// passed on to a region that has already been offered the message (D11, D19). The
    /// fan-out budget is never charged for the same reason: there is no second hop to charge.
    pub fn take(&self, chunk: Chunk) -> bool {
        self.0.chunk(ChunkFlags::FORWARDED, chunk).completed
    }
}

/// One peer, as everything reading its streams sees it.
struct Ctx {
    peer: Hostname,
    region: Region,
    site: Option<String>,
    /// The peer's own topic ids, kept up to date by the control stream reader (T-027).
    state: Arc<Mutex<PeerState>>,
    /// What this peer may make this host fan out (DX-N3), one bucket per connection.
    budget: Mutex<FanoutBudget>,
    deps: Deps,
    /// Whether this connection has already had its line about a payload that did not check out.
    /// A peer sending a stream of them costs one line, and a reconnect gets a fresh one.
    warned_invalid: AtomicBool,
}

/// Both carriers of one peer, in one task. They end together, because both end when the
/// connection does, and neither can hold the other up: a stream is read by a task of its own
/// and a datagram is one frame that is already whole when [`read_datagram`] answers.
///
/// [`read_datagram`]: quinn::Connection::read_datagram
async fn read_peer(connection: quinn::Connection, ctx: Arc<Ctx>) {
    tokio::join!(
        accept(connection.clone(), ctx.clone()),
        accept_repair(connection.clone(), ctx.clone()),
        datagrams(connection, ctx)
    );
}

/// This peer's datagrams, which is where the small class arrives (§5.3). Each one is exactly one
/// frame with no length prefix (D10), so there is nothing to resynchronise and a datagram that
/// does not decode costs only itself.
///
/// Reading never waits for the beacon node: [`Ctx::deliver`] ends in a `try_send` into the
/// publish queue (DX-N4), so a queue nothing is draining costs queue drops and the loop keeps
/// taking datagrams off the connection.
async fn datagrams(connection: quinn::Connection, ctx: Arc<Ctx>) {
    loop {
        match connection.read_datagram().await {
            Ok(datagram) => {
                if let After::Close(kind) = ctx.datagram(datagram) {
                    close_rate_exceeded(&ctx.peer, kind, &connection);
                    return;
                }
            }
            Err(error) => {
                tracing::debug!(peer = %ctx.peer, %error, "peer sends no more datagrams");
                return;
            }
        }
    }
}

/// Accepts this peer's streams, each read by a task of its own so one stalled stream holds up
/// nothing. Finished ones are reaped on the next accept; the peer may have at most
/// `max_concurrent_uni_streams` open at once (DX-N3), so the set is bounded by that.
async fn accept(connection: quinn::Connection, ctx: Arc<Ctx>) {
    let mut streams = JoinSet::new();
    loop {
        match connection.accept_uni().await {
            Ok(stream) => {
                streams.spawn(read_stream(stream, ctx.clone(), connection.clone()));
            }
            Err(error) => {
                tracing::debug!(peer = %ctx.peer, %error, "peer opens no more streams");
                return;
            }
        }
        while streams.try_join_next().is_some() {}
    }
}

/// Accepts this peer's bidirectional streams, which after the control stream carry repair
/// requests and nothing else (§7). Built like [`accept`] above it: one task per stream, finished
/// ones reaped on the next accept, so a request that is slow to answer holds nothing up.
///
/// The control stream is not one of these. It was accepted during HELLO, before this task
/// existed, and stays open for the life of the connection (T-025).
///
/// A peer past [`MAX_REPAIR_STREAMS_PER_PEER`] has its stream dropped, which resets it and lets
/// the requester move on to another candidate rather than wait out its attempt.
async fn accept_repair(connection: quinn::Connection, ctx: Arc<Ctx>) {
    let mut streams = JoinSet::new();
    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                while streams.try_join_next().is_some() {}
                if streams.len() >= MAX_REPAIR_STREAMS_PER_PEER {
                    tracing::debug!(peer = %ctx.peer, "peer is over its repair stream budget");
                    continue;
                }
                streams.spawn(serve_repair(send, recv, ctx.clone()));
            }
            Err(error) => {
                tracing::debug!(peer = %ctx.peer, %error, "peer opens no more repair streams");
                return;
            }
        }
    }
}

/// One repair exchange, from the request the peer wrote to the answer this host finishes the
/// stream with (§5.6).
///
/// The read wears [`STREAM_READ_TIMEOUT`] like every other data-stream read, so a peer that
/// opens a stream and says nothing costs a slot for two seconds and no longer. What is written
/// back is decided synchronously by [`Ctx::repair`], which is what keeps the recent store's lock
/// and the topic table's lock off this function's `await`s.
async fn serve_repair(mut send: quinn::SendStream, mut recv: quinn::RecvStream, ctx: Arc<Ctx>) {
    let read = tokio::time::timeout(
        STREAM_READ_TIMEOUT,
        wire::read_frame(&mut recv, MAX_FRAME_BYTES),
    )
    .await;
    let request = match read {
        Ok(Ok(Read::Frame(Frame::RepairReq(request)))) => request,
        other => {
            tracing::debug!(peer = %ctx.peer, "a repair stream carried {other:?}");
            return;
        }
    };
    for frame in ctx.repair(&request) {
        if wire::write_frame(&mut send, &frame).await.is_err() {
            return;
        }
    }
    let _ = send.finish();
}

/// Why a stream stopped being read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamEnd {
    /// It ended, or the peer sent something that did not decode.
    Ended,
    /// A frame did not arrive within [`STREAM_READ_TIMEOUT`].
    Timeout,
    /// The peer has been asking for more second-hop work than its budget covers for longer than
    /// the connection is given (DX-N3).
    RateExceeded(FanoutKind),
}

/// What one chunk's arrival came to: whether the connection carries on, and whether that chunk
/// was the one that put its message back together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Arrival {
    after: After,
    completed: bool,
}

impl Arrival {
    /// An arrival that ends nothing, for the chunks that never reach the reassembler.
    fn carry(completed: bool) -> Self {
        Self {
            after: After::Carry,
            completed,
        }
    }
}

/// Whether the connection a frame arrived on carries on. A peer that has been over its fan-out
/// budget for too long is the one thing on this path that ends it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum After {
    /// Keep reading.
    Carry,
    /// Close with [`CloseCode::RateExceeded`], naming the second hop the peer asked for too
    /// much of.
    Close(FanoutKind),
}

/// One stream from the peer's first byte to whatever ends it, and the one place a stalled
/// stream is given up on.
async fn read_stream(mut stream: quinn::RecvStream, ctx: Arc<Ctx>, connection: quinn::Connection) {
    match read_frames(&mut stream, &ctx).await {
        StreamEnd::Timeout => {
            tracing::debug!(peer = %ctx.peer, "closing a stream that stalled mid-frame");
            let _ = stream.stop(VarInt::from_u32(STALLED_STREAM_CODE));
        }
        StreamEnd::RateExceeded(kind) => close_rate_exceeded(&ctx.peer, kind, &connection),
        // A stream that ended has nothing left to stop, and the peer that finished it knows.
        StreamEnd::Ended => {}
    }
}

/// Reads frames until the stream ends or stalls. An unknown frame type is skipped and reading
/// continues, which is what lets a peer one release ahead send frames this one has never heard
/// of (D10).
async fn read_frames<R: AsyncRead + Unpin>(stream: &mut R, ctx: &Ctx) -> StreamEnd {
    loop {
        // A host the fleet harness has throttled reads no further until it has paid for what it
        // already delivered (T-051 scenario 14). Nothing throttles a host outside that test, and
        // the hook is compiled out of every build that does not carry the test surface.
        #[cfg(any(test, feature = "test-util"))]
        crate::testutil::throttle::wait(&ctx.deps.node.hostname).await;
        let read = tokio::time::timeout(
            STREAM_READ_TIMEOUT,
            wire::read_frame(stream, MAX_FRAME_BYTES),
        )
        .await;
        match read {
            Err(_) => return StreamEnd::Timeout,
            Ok(Ok(Read::Frame(frame))) => {
                if let After::Close(kind) = ctx.frame(frame) {
                    return StreamEnd::RateExceeded(kind);
                }
            }
            Ok(Ok(Read::Unknown(frame_type))) => {
                tracing::debug!(peer = %ctx.peer, frame_type, "frame type from a newer peer");
                ctx.deps.stats.unknown_frame_type(&ctx.peer);
            }
            Ok(Err(error)) => {
                tracing::debug!(peer = %ctx.peer, %error, "stream ended");
                return StreamEnd::Ended;
            }
        }
    }
}

impl Ctx {
    /// Sends one frame down the path its carrier and shape call for, and answers whether the
    /// connection carries on.
    fn frame(&self, frame: Frame) -> After {
        // Off the socket and decoded, which is the earliest the arrival time can be read here;
        // everything below it, the id above all, costs time this host should not be charged
        // with in the fleet-spread query.
        let arrived = self.deps.clock.wall();
        match frame {
            Frame::Chunk { chunk, .. } if chunk.is_whole() => {
                let _ = self.deliver(
                    chunk.topic_id,
                    chunk.data,
                    Some(chunk.msg_id),
                    arrived,
                    Delivery::Local,
                );
                After::Carry
            }
            Frame::Chunk { flags, chunk } => self.chunk(flags, chunk).after,
            Frame::Batch { flags, entries } => self.batch(flags, entries, arrived),
            other => {
                tracing::debug!(
                    peer = %self.peer,
                    frame = ?other.frame_type(),
                    "frame that does not belong on a data stream"
                );
                After::Carry
            }
        }
    }

    /// One chunk of a striped message: offered to the rest of the region, collected, and, on the
    /// chunk that makes `k` of them, published as the message it was cut from.
    ///
    /// Cut-through (§5.4 step 3): the forward is the first thing that happens to a chunk this
    /// host owes its region, before anything is decoded from it, because the whole point of
    /// striping is that a host passes a piece on the moment it arrives rather than after it has
    /// the message. [`Reassembler::on_chunk`] answers what the region is owed before it looks at
    /// what it holds, and the completion below runs once the forward has been issued.
    ///
    /// What the region is owed is that answer and not this function's: a chunk that arrived with
    /// `FORWARDED` is the second hop and there is no third, and an index some other origin's copy
    /// already carried has been forwarded once (D11, D19).
    fn chunk(&self, flags: ChunkFlags, chunk: Chunk) -> Arrival {
        self.deps.stats.chunk_received(&self.peer, flags, &chunk);
        let Some(topic) = self.topic(chunk.topic_id) else {
            self.deps.stats.unknown_topic_id(&self.peer);
            return Arrival::carry(false);
        };
        let class = Class::of(topic.kind(), chunk.total_len as usize);
        self.deps
            .stats
            .chunk_bytes(Direction::In, class, self.labels(), chunk.data.len());
        // Forward only what this host does not hold (D19). A message in the seen cache reached
        // it whole, or from its own beacon node, and its region was offered the message then;
        // the chunks still arriving are the stripe finishing and there is nothing owed for them.
        if self.deps.seen.contains(&chunk.msg_id) {
            self.deps.stats.duplicate(class);
            return Arrival::carry(false);
        }
        let now = self.deps.clock.now();
        let outcome = self.deps.reassembler.on_chunk(
            &chunk,
            &topic,
            &self.peer,
            flags.contains(ChunkFlags::FORWARDED),
            now,
        );
        let after = match outcome.forward() {
            false => After::Carry,
            true => match self.charge(FanoutKind::Chunk, chunk.data.len(), now) {
                Charge::Allowed => {
                    self.forward(&topic, &chunk);
                    After::Carry
                }
                Charge::Suppressed => After::Carry,
                Charge::CloseRateExceeded => After::Close(FanoutKind::Chunk),
            },
        };
        Arrival {
            after,
            completed: self.reassembled(&topic, class, outcome, now),
        }
    }

    /// What a chunk's arrival came to once the region has been offered it, answering whether
    /// that chunk was the one that put the message back together (T-082 counts that).
    ///
    /// A message that came back goes through the same three steps a whole one does, in the same
    /// order: the advertised gate (DX-N1), the seen cache (D08, site 3 of 3) and the publish
    /// queue (DX-N4). `reconstruct_seconds` is read from the first chunk's arrival and
    /// `parity_used_total` says a host or a chunk was lost on the way (§12).
    ///
    /// A payload the beacon node would refuse is counted against the origin rather than the peer
    /// that happened to send the last chunk, because the origin is who cut it up (D03).
    fn reassembled(&self, topic: &Topic, class: Class, outcome: Outcome, now: Instant) -> bool {
        match outcome {
            Outcome::Completed {
                msg_id,
                payload,
                used_parity,
                first_chunk_at,
                origin,
                ..
            } => {
                let took = now.saturating_duration_since(first_chunk_at);
                // When the first chunk came off the socket, which is when this host heard of the
                // message: the wall clock reading now, less how long the rest of it took.
                let arrived = self.deps.clock.wall() - took;
                if self.publish_reassembled(topic, class, msg_id, payload, &origin, arrived, now) {
                    if used_parity {
                        self.deps.stats.parity_used();
                    }
                    self.deps.stats.reconstructed(class, took);
                }
                true
            }
            Outcome::Rejected {
                reason: Reason::InvalidPayload,
                origin,
            } => {
                self.deps.stats.invalid_payload(&origin);
                self.warn_invalid(topic, "the reassembled payload is not one its id names");
                false
            }
            Outcome::Rejected { reason, origin } => {
                tracing::debug!(%origin, ?reason, "dropping a chunk this host cannot use");
                false
            }
            Outcome::Stored { .. } | Outcome::Duplicate { .. } | Outcome::LateAfterCompletion => {
                false
            }
            Outcome::HeaderConflict => {
                tracing::debug!(peer = %self.peer, "a chunk header that contradicts the first");
                false
            }
        }
    }

    /// Gate, remember and queue one reassembled message, answering whether it reached the queue.
    ///
    /// This is the third of D08's three seen-cache insert sites, and the insert is immediately
    /// before the enqueue with no other insert on this path. First-seen accounting belongs with
    /// the insert and not with the enqueue: "first seen" means the cache did not already hold
    /// the id, so a fourth insert site would owe `first_seen_total` and the `first_arrival`
    /// event as well, the way [`deliver`](Self::deliver) and T-016's inbound path do.
    ///
    /// `origin` is the host that cut the message up rather than whoever sent the last chunk,
    /// and `arrived` is when the first chunk landed, so the fleet-spread query compares the
    /// moment each host heard of the message. `now` is when the message came back, which is
    /// what the recent store ages it from.
    #[expect(
        clippy::too_many_arguments,
        reason = "one message and the four readings that describe it: what it is, who cut it \
                  up, when this host heard of it, and when it came back. Each has its own \
                  type, so a call site cannot mix two up"
    )]
    fn publish_reassembled(
        &self,
        topic: &Topic,
        class: Class,
        id: MessageId,
        payload: Bytes,
        origin: &Hostname,
        arrived: SystemTime,
        now: Instant,
    ) -> bool {
        if !self.deps.sets.borrow().advertised.contains(topic) {
            self.deps.stats.unwanted_topic(&self.peer);
            return false;
        }
        if !self.deps.seen.insert(id) {
            self.deps.stats.duplicate(class);
            return false;
        }
        self.deps.stats.first_seen(class);
        self.deps.publish.enqueue(PublishItem {
            topic: topic.clone(),
            id,
            payload: payload.clone(),
            class,
        });
        // Insert site 2 of 3 for the recent store (§5.6); T-016's inbound path and T-032's whole
        // delivery are the others. A reassembled message is always large class, and the peers
        // that sent its chunks are the ones that may still be missing some of them. The
        // reassembler checked this payload against its id when it completed, so the
        // decompression cannot fail on anything it accepted (T-074).
        let ssz = msgid::decompressed(&payload, wire::MAX_PAYLOAD_BYTES);
        let header = self.remember(id, topic, payload, ssz.as_deref(), class, now);
        events::emit_first_arrival(&FirstArrival {
            id,
            class,
            topic,
            node: &self.deps.node,
            at: arrived,
            source: events::Source::Overlay { origin },
            header,
        });
        true
    }

    /// Hands one chunk to every live in-region peer subscribed to `topic`, with `FORWARDED` set
    /// and the sender left out: it has the chunk, and sending it back would be the third hop the
    /// bit exists to prevent (D11, D19).
    ///
    /// A peer that advertised no `STRIPING` is left out too. It was sent the whole message by
    /// the origin instead, because the stripe pool is the subscribers that can read one
    /// (D29, `router::striped`), so a chunk would be a frame it would drop.
    ///
    /// The chunk goes out under this host's own id for the topic, since a frame is named by
    /// whoever sends it (D13), and only to a peer that has had the `TOPIC_ADD` binding it
    /// (MD-04). A forwarding host is a stripe target and a stripe runs over subscribers (D18),
    /// so it holds an id already; the intern is what keeps that true if the pool ever widens.
    fn forward(&self, topic: &Topic, chunk: &Chunk) {
        let Some(topic_id) = self.own_id(topic) else {
            self.deps.stats.unannounced_topic();
            return;
        };
        let frame = wire::encode_stream(&Frame::Chunk {
            flags: ChunkFlags::FORWARDED,
            chunk: Chunk {
                topic_id: topic_id.get(),
                ..chunk.clone()
            },
        });
        // The lane's own clock, which is the runtime's: the age bound the drain task holds a
        // frame to is read from that one and not from the injected clock this path reads.
        let now = Instant::now();
        let view = self.deps.relaying.live.live();
        // One lock for the whole region rather than one per peer, the way `refan` takes it.
        let own = crate::hello::lock(&self.deps.relaying.topics);
        for (hostname, peer) in view.in_region(&self.deps.node.region) {
            let wanted = *hostname != self.deps.node.hostname
                && *hostname != self.peer
                && peer.negotiated.allows(features::STRIPING)
                && own.announcer.told(hostname, topic_id)
                && subs::state(&peer.state).subscribed(topic);
            if !wanted {
                continue;
            }
            if peer.sender.push(Class::Large, frame.clone(), now).is_err() {
                tracing::debug!(peer = %hostname, "peer has no sender to queue the chunk on");
                continue;
            }
            self.deps.stats.chunk_sent();
            self.deps.stats.chunk_bytes(
                Direction::Out,
                Class::Large,
                PeerLabels {
                    hostname,
                    region: &peer.region,
                    site: peer.site.as_deref(),
                },
                chunk.data.len(),
            );
        }
    }

    /// What to write back to a peer that asked for chunks of a message (§5.6, D24).
    ///
    /// The payload is what the recent store kept whole, and the chunks are cut from it again
    /// here rather than held as chunks: every host runs the same `classes.large` and
    /// [`Params::for_len`] is a function of the payload's length, so what comes out is what the
    /// origin sent. A requester whose split disagrees reads a header that contradicts the chunks
    /// it already holds and drops it, which is [`Outcome::HeaderConflict`] doing its job.
    ///
    /// Each chunk goes as its own `CHUNK` frame because a `REPAIR_RESP` body carries no flags
    /// byte and `FORWARDED` is the point: the requester must not pass a repaired chunk on to a
    /// region that has already been offered the message (D11, D19). The `REPAIR_RESP` after them
    /// is the trailer that says the answer is complete, and carries no chunks of its own.
    ///
    /// Everything the peer is not owed is [`RepairResp::NotFound`], which is what makes it move
    /// on to the next candidate rather than wait: a message this host does not hold, a request
    /// for more indices than the message has data chunks, and a topic this host cannot name to
    /// this peer yet (MD-04).
    fn repair(&self, request: &RepairReq) -> Vec<Frame> {
        let not_found = || vec![Frame::RepairResp(RepairResp::NotFound)];
        let Some(msg_id) = self.asked_for(request) else {
            return not_found();
        };
        let Some((topic, payload)) = self.deps.recent.get(&msg_id) else {
            return not_found();
        };
        let Ok(split) = Params::for_len(
            payload.len(),
            self.deps.large.chunk_bytes,
            self.deps.large.parity_ratio,
        ) else {
            return not_found();
        };
        let missing: Vec<u16> = match request {
            RepairReq::Missing { missing, .. } => missing.clone(),
            // A peer that asked by identity holds none of the column, so it is owed every data
            // chunk of it; parity would only cost bytes it has no shortfall to make up (D24).
            RepairReq::Column { .. } => (0..split.k).collect(),
        };
        if missing.len() > usize::from(split.k) {
            tracing::debug!(
                peer = %self.peer,
                asked = missing.len(),
                k = split.k,
                "a repair request for more indices than the message has data chunks"
            );
            return not_found();
        }
        let Some(topic_id) = self.told_id(&topic) else {
            return not_found();
        };
        let chunks = rs::encode(&payload, split);
        let mut answer: Vec<Frame> = missing
            .iter()
            .filter_map(|index| Some((*index, chunks.get(usize::from(*index))?)))
            .map(|(index, data)| Frame::Chunk {
                flags: ChunkFlags::FORWARDED,
                chunk: Chunk {
                    msg_id,
                    topic_id: topic_id.get(),
                    k: split.k,
                    m: split.m,
                    index,
                    total_len: split.total_len,
                    data: data.clone(),
                },
            })
            .collect();
        answer.push(Frame::RepairResp(RepairResp::Chunks(Vec::new())));
        answer
    }

    /// Which message a request is about: the one it names, or the one the recent store files
    /// under the column it names (T-081's index, T-083). A column nothing has indexed is one
    /// this host cannot answer for, whatever else it holds.
    fn asked_for(&self, request: &RepairReq) -> Option<MessageId> {
        match request {
            RepairReq::Missing { msg_id, .. } => Some(*msg_id),
            RepairReq::Column { block_root, index } => {
                self.deps.recent.get_by_column(*block_root, *index)
            }
        }
    }

    /// The id this host names `topic` by, once this peer has had the `TOPIC_ADD` that binds it
    /// (MD-04). A peer that has not been told cannot resolve the id, so there is nothing worth
    /// answering with until the announcement has crossed its control stream.
    fn told_id(&self, topic: &Topic) -> Option<TopicId> {
        let id = self.own_id(topic)?;
        crate::hello::lock(&self.deps.relaying.topics)
            .announcer
            .told(&self.peer, id)
            .then_some(id)
    }

    /// One datagram, which carries one `BATCH` or nothing this release will act on. Anything
    /// else is dropped whole and counted `unknown_frame_type_total{peer}`: a type from a newer
    /// release, and a type that belongs on a stream, are the same thing here, since a datagram
    /// has no length prefix to skip a frame by (D10).
    fn datagram(&self, datagram: Bytes) -> After {
        let arrived = self.deps.clock.wall();
        match wire::decode_datagram(datagram) {
            Ok(Frame::Batch { flags, entries }) => return self.batch(flags, entries, arrived),
            Ok(other) => {
                tracing::debug!(
                    peer = %self.peer,
                    frame = ?other.frame_type(),
                    "frame that does not belong in a datagram"
                );
                self.deps.stats.unknown_frame_type(&self.peer);
            }
            Err(wire::DecodeError::UnknownType(frame_type)) => {
                tracing::debug!(peer = %self.peer, frame_type, "datagram from a newer peer");
                self.deps.stats.unknown_frame_type(&self.peer);
            }
            Err(error) => {
                tracing::debug!(peer = %self.peer, %error, "datagram that does not decode");
            }
        }
        After::Carry
    }

    /// One `BATCH`, from either carrier. Without `RELAY` the entries are this host's alone.
    ///
    /// With it, the sender is asking this host to fan the batch out inside its own region, and
    /// three things decide whether it does. The sender has to be in another region: a
    /// same-region `RELAY` is a peer breaking the protocol, and honouring it would be the
    /// hundredfold re-forwarding the bit exists to prevent (D20). The bytes have to fit the
    /// peer's fan-out budget, or the batch is delivered here and fanned out nowhere (DX-N3).
    /// And an entry is only re-fanned if it was new to this host's seen cache: one it already
    /// held reached its region from another relay or from the origin, and has been fanned
    /// already.
    fn batch(&self, flags: BatchFlags, entries: Vec<BatchEntry>, arrived: SystemTime) -> After {
        if !flags.contains(BatchFlags::RELAY) {
            self.deliver_all(entries, arrived);
            return After::Carry;
        }
        if self.region == self.deps.node.region {
            self.deps.stats.relay_same_region(&self.peer);
            tracing::debug!(peer = %self.peer, "a peer in this region asked for a re-fan");
            self.deliver_all(entries, arrived);
            return After::Carry;
        }
        let bytes = entries.iter().map(|entry| entry.payload.len()).sum();
        let charge = self.charge(FanoutKind::Relay, bytes, self.deps.clock.now());
        if charge != Charge::Allowed {
            self.deliver_all(entries, arrived);
            return match charge {
                Charge::CloseRateExceeded => After::Close(FanoutKind::Relay),
                _ => After::Carry,
            };
        }
        let new: Vec<(Topic, Bytes)> = entries
            .into_iter()
            .filter_map(|entry| {
                self.deliver(
                    entry.topic_id,
                    entry.payload,
                    None,
                    arrived,
                    Delivery::Relayed,
                )
            })
            .collect();
        self.refan(new);
        After::Carry
    }

    /// Every entry of a batch this host keeps to itself.
    fn deliver_all(&self, entries: Vec<BatchEntry>, arrived: SystemTime) {
        for entry in entries {
            let _ = self.deliver(
                entry.topic_id,
                entry.payload,
                None,
                arrived,
                Delivery::Local,
            );
        }
    }

    /// Hands what was new to this host's own batcher, once per in-region subscriber of each
    /// entry's topic, so every one of them gets a single batch of what it asked for and nothing
    /// else (D21). The batches go out with `RELAY` clear: this is the second hop and there is
    /// no third.
    ///
    /// Every payload here came out of a `BATCH` entry, so it already fits the `u16` length one
    /// carries and [`Batcher::push`](overlay_core::batch::Batcher::push)'s precondition holds
    /// without a second check. An entry goes out only under an id the peer has already been
    /// told: the intern below binds one at once, and a frame naming a binding the peer has not
    /// had is one it drops and counts as `unknown_topic_id_total` (MD-04). The entries in that
    /// window are lost, which is what the small class has public gossip for.
    ///
    /// `relayed_batches_total` counts a batch that arrives here with something new in it, and
    /// not one that reached a peer: a batch that correctly re-fanned nothing is D20 working and
    /// is deliberately not counted, so counting the pushes as well would make it look the same
    /// as one whose every entry was dropped. What was dropped is `unannounced_topic_total`.
    fn refan(&self, new: Vec<(Topic, Bytes)>) {
        if new.is_empty() {
            return;
        }
        self.deps.stats.relayed_batch();
        let relaying = &self.deps.relaying;
        let view = relaying.live.live();
        for (topic, payload) in new {
            let Some(topic_id) = self.own_id(&topic) else {
                self.deps.stats.unannounced_topic();
                continue;
            };
            // One lock for the whole region rather than one per peer. Nothing under it takes
            // the topics lock, so the order this nests in is the only one there is.
            let own = crate::hello::lock(&relaying.topics);
            for (hostname, peer) in view.in_region(&self.deps.node.region) {
                let wanted = *hostname != self.deps.node.hostname
                    && own.announcer.told(hostname, topic_id)
                    && subs::state(&peer.state).subscribed(&topic);
                let Some(max_bytes) = wanted
                    .then(|| crate::fanout::datagram_limit(&self.deps.node.hostname, peer))
                    .flatten()
                else {
                    continue;
                };
                let _ = relaying.batches.push(Small {
                    dest: hostname.clone(),
                    topic_id,
                    payload: payload.clone(),
                    max_bytes,
                    relay: false,
                    sender: peer.sender.clone(),
                });
            }
        }
    }

    /// The id this host names `topic` by on the wire, interning one if it has none (MD-04). A
    /// relay carries topics its own beacon node never subscribed to, and `route` leaves a
    /// relayed region out of the origin's direct plan, so an entry this host cannot name is one
    /// its whole region loses.
    ///
    /// Only a topic whose fork digest this host already knows is interned. `Topic::parse`
    /// accepts any of ~2^32 digests and the fan-out budget is denominated in bytes, so without
    /// the bound a peer could make this host allocate an unbounded id space at no cost to
    /// itself; with it the reachable set is the couple of hundred topics a digest has.
    ///
    /// The digest is checked between the two lock takes rather than inside one: the announce
    /// loop reads the mirror and then takes this lock, and taking them the other way round here
    /// would be the one ordering that can deadlock.
    fn own_id(&self, topic: &Topic) -> Option<TopicId> {
        if let Some(id) = crate::hello::lock(&self.deps.relaying.topics)
            .table
            .get(topic)
        {
            return Some(id);
        }
        if !self.knows_digest(topic) {
            tracing::debug!(%topic, peer = %self.peer, "a fork digest this host does not know");
            return None;
        }
        crate::hello::lock(&self.deps.relaying.topics)
            .intern(topic)
            .inspect_err(|error| tracing::error!(%topic, %error, "no id left to carry a topic"))
            .ok()
    }

    /// Whether `topic`'s fork digest is one this host's own beacon node is subscribed under.
    fn knows_digest(&self, topic: &Topic) -> bool {
        self.deps
            .sets
            .borrow()
            .local
            .iter()
            .any(|known| known.fork_digest() == topic.fork_digest())
    }

    /// Charges this peer's fan-out budget for `bytes` of second-hop work and counts a refusal
    /// (DX-N3). Closing is the caller's: whoever is reading the connection is who has it.
    ///
    /// The lock guard is recovered from a poisoned lock: nothing between the lock and its
    /// release can panic, so the bucket is whole, and refusing to charge afterwards would let a
    /// peer past the one bound that stops it.
    fn charge(&self, kind: FanoutKind, bytes: usize, now: Instant) -> Charge {
        let charge = self
            .budget
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .charge(kind, bytes, now);
        if charge != Charge::Allowed {
            self.deps.stats.fanout_suppressed(&self.peer, kind);
        }
        charge
    }

    /// One payload, from a whole message or from a batch entry. `header_id` is the id the frame
    /// claimed for it, which only a chunk header carries, and `arrived` is when the frame that
    /// carried it came off the socket. The answer is the entry a relay owes its own region,
    /// which is only ever `Some` for [`Delivery::Relayed`].
    fn deliver(
        &self,
        topic_id: u16,
        payload: Bytes,
        header_id: Option<MessageId>,
        arrived: SystemTime,
        delivery: Delivery,
    ) -> Option<(Topic, Bytes)> {
        let Some(topic) = self.topic(topic_id) else {
            self.deps.stats.unknown_topic_id(&self.peer);
            return None;
        };
        let class = Class::of(topic.kind(), payload.len());
        self.deps
            .stats
            .message(Direction::In, class, self.labels(), payload.len());
        #[cfg(any(test, feature = "test-util"))]
        crate::testutil::throttle::charge(&self.deps.node.hostname, payload.len());
        // A relay carries on past the gate: what it publishes is its own beacon node's business
        // (DX-N1), what it re-fans is its region's, and it need not want a thing in the batch.
        let wanted = self.deps.sets.borrow().advertised.contains(&topic);
        if !wanted {
            self.deps.stats.unwanted_topic(&self.peer);
            if delivery == Delivery::Local {
                return None;
            }
        }
        // One decompression for both the id and, below, the payload's header (T-006, T-083).
        let (computed, ssz) =
            msgid::compute_with_bytes(&topic.to_string(), &payload, wire::MAX_PAYLOAD_BYTES);
        let refused = match (computed.branch, header_id) {
            (Branch::Valid, Some(claimed)) if claimed != computed.id => {
                Some("the id does not match the payload")
            }
            (Branch::Valid, _) => None,
            (Branch::Invalid, _) => Some("the payload does not decompress"),
            (Branch::TooLarge, _) => Some("the payload declares more than the maximum"),
        };
        if let Some(refused) = refused {
            self.deps.stats.invalid_payload(&self.peer);
            self.warn_invalid(&topic, refused);
            return None;
        }
        // Insert site 2 of 3 (D08), immediately before the enqueue. There is no second insert
        // anywhere in this file, and a message dropped below is one this host is already
        // holding for the seen cache's TTL.
        if !self.deps.seen.insert(computed.id) {
            self.deps.stats.duplicate(class);
            return None;
        }
        let owed = match delivery {
            Delivery::Relayed => Some((topic.clone(), payload.clone())),
            Delivery::Local => None,
        };
        if wanted {
            self.deps.stats.first_seen(class);
            // The beacon node first, and everything the sidecar wants to know about the message
            // after it: the SSZ decode below is milliseconds on a block, and nothing it produces
            // is owed to the node.
            self.deps.publish.enqueue(PublishItem {
                topic: topic.clone(),
                id: computed.id,
                payload: payload.clone(),
                class,
            });
            // Insert site 3 of 3 for the recent store (§5.6), and the one T-081 left open: a
            // message that arrived whole is one this host holds, and column repair asks
            // in-region peers by round trip whatever they sent it (D23).
            let now = self.deps.clock.now();
            let header = self.remember(computed.id, &topic, payload, ssz.as_deref(), class, now);
            events::emit_first_arrival(&FirstArrival {
                id: computed.id,
                class,
                topic: &topic,
                node: &self.deps.node,
                at: arrived,
                source: events::Source::Overlay { origin: &self.peer },
                header,
            });
        }
        owed
    }

    /// Keeps a large payload for repair and tells the custody tracker what its header said
    /// (§5.6, §6.4). Small-class messages are never repaired, so they are never decoded either.
    ///
    /// The decode runs here, outside the recent store's lock and after whatever the caller owed
    /// the beacon node, because it is the one place in the sidecar that reads a consensus object
    /// and a block costs milliseconds (T-083).
    fn remember(
        &self,
        id: MessageId,
        topic: &Topic,
        payload: Bytes,
        ssz: Option<&[u8]>,
        class: Class,
        now: Instant,
    ) -> Option<Header> {
        if class != Class::Large {
            return None;
        }
        let header = self
            .deps
            .recent
            .insert(id, topic.clone(), payload, ssz, now)?;
        self.deps.custody.observe(header, now);
        Some(header)
    }

    /// One line per connection about payloads the beacon node would refuse. A peer sending a
    /// stream of them costs one line, and its next connection gets a fresh one (D03).
    fn warn_invalid(&self, topic: &Topic, refused: &str) {
        if !self.warned_invalid.swap(true, Ordering::Relaxed) {
            tracing::warn!(peer = %self.peer, %topic, "dropping a payload: {refused}");
        }
    }

    /// The topic the peer means by `id`, read against the peer's own table and nobody else's
    /// (D13). The lock is held for the lookup and the clone, never across the hashing below.
    fn topic(&self, id: u16) -> Option<Topic> {
        subs::state(&self.state)
            .table
            .resolve(TopicId::new(id))
            .cloned()
    }

    fn labels(&self) -> PeerLabels<'_> {
        PeerLabels {
            hostname: &self.peer,
            region: &self.region,
            site: self.site.as_deref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testlog::LOG;
    use crate::testutil::{
        Builder, CountingStats, NodeKind, PUBLISHED_MAX, PublishSpy, SETTLE, TestCluster, WAIT,
        eventually, subscriptions, topic,
    };
    use bytes::BytesMut;
    use overlay_core::budget::SUSTAINED_VIOLATION;
    use overlay_core::config;
    use overlay_core::reassemble::{MAX_IN_FLIGHT, ReassembleConfig};
    use overlay_core::recent::{RECENT_MAX_BYTES, RECENT_TTL, RecentLarge};
    use overlay_core::rs::Params;
    use overlay_core::seen::SeenCache;
    use overlay_core::time::{FakeClock, SystemClock};
    use overlay_core::topic::UNKNOWN_LARGE_THRESHOLD_BYTES;
    use overlay_core::wire::{BatchEntry, BatchFlags, RepairReq, RepairResp, encode_datagram};
    use tokio::io::AsyncWriteExt;

    /// The gossipsub wire form of `data`: snappy-compressed, which is what a payload has to be
    /// for its id to come out of the valid branch (D03).
    fn payload(data: &[u8]) -> Vec<u8> {
        snap::raw::Encoder::new().compress_vec(data).unwrap()
    }

    /// A node with a sidecar and a peer of the test's own, which announced `announced` in its
    /// HELLO and writes what the test tells it to. The node with the sidecar is the higher
    /// hostname, so it dials nobody and every connection it has is the one made here.
    async fn peer_of(
        sets: SubscriptionSets,
        announced: &[(u16, &Topic)],
    ) -> (TestCluster, PeerInfo) {
        peer_of_with(sets, announced, |builder| builder).await
    }

    /// The same with a clock the test drives, for the one assertion about how long something
    /// took.
    async fn peer_of_clocked(
        sets: SubscriptionSets,
        announced: &[(u16, &Topic)],
        clock: Arc<dyn Clock>,
    ) -> (TestCluster, PeerInfo) {
        peer_of_with(sets, announced, |builder| builder.clock(clock)).await
    }

    /// The same with a publish queue of `published_max` entries, for the one test about a beacon
    /// node that has stopped draining.
    async fn peer_of_queueing(
        sets: SubscriptionSets,
        announced: &[(u16, &Topic)],
        published_max: usize,
    ) -> (TestCluster, PeerInfo) {
        dialled(
            Builder::new(&[NodeKind::Bare, NodeKind::Manager]),
            sets,
            announced,
            published_max,
        )
        .await
    }

    /// The same with `with` applied to the builder first.
    async fn peer_of_with(
        sets: SubscriptionSets,
        announced: &[(u16, &Topic)],
        with: impl FnOnce(Builder) -> Builder,
    ) -> (TestCluster, PeerInfo) {
        dialled(
            with(Builder::new(&[NodeKind::Bare, NodeKind::Manager])),
            sets,
            announced,
            PUBLISHED_MAX,
        )
        .await
    }

    /// Starts the cluster `builder` describes and dials its sidecar from the test's own peer.
    async fn dialled(
        builder: Builder,
        sets: SubscriptionSets,
        announced: &[(u16, &Topic)],
        published_max: usize,
    ) -> (TestCluster, PeerInfo) {
        let mut cluster = builder.start().await;
        cluster.start_sidecar_with(1, sets, published_max);
        let announced = announced
            .iter()
            .map(|(id, topic)| (TopicId::new(*id), topic.to_string()))
            .collect();
        let peer = cluster
            .dial_announcing(0, 1, &cluster.self_hello(0), announced)
            .await;
        (cluster, peer)
    }

    /// Sends one body as the whole of a datagram, which is how a `BATCH` travels (§7). No
    /// length prefix: the datagram is the frame (D10), so a body here is a frame on the wire.
    fn datagram(peer: &PeerInfo, body: Bytes) {
        peer.connection.send_datagram(body).unwrap();
    }

    /// A batch of `entries`, as the carrier a batch belongs on carries it.
    fn batch(entries: Vec<BatchEntry>) -> Bytes {
        encode_datagram(&Frame::Batch {
            flags: BatchFlags::NONE,
            entries,
        })
    }

    /// One entry of a batch.
    fn entry(topic_id: u16, payload: &[u8]) -> BatchEntry {
        BatchEntry {
            topic_id,
            payload: Bytes::copy_from_slice(payload),
        }
    }

    /// Writes each body on one stream, with the `u32` length prefix a stream carries. Bodies and
    /// not frames, so a test can put a type byte on the wire that no [`Frame`] variant has.
    async fn send(peer: &PeerInfo, bodies: &[Bytes]) {
        let mut stream = peer.connection.open_uni().await.unwrap();
        for body in bodies {
            let mut out = BytesMut::new();
            out.extend_from_slice(&(body.len() as u32).to_le_bytes());
            out.extend_from_slice(body);
            stream.write_all(&out).await.unwrap();
        }
        stream.finish().unwrap();
    }

    /// A whole message as a peer's sender would write it, under the id the payload hashes to
    /// on `topic`.
    fn whole(topic_id: u16, topic: &Topic, payload: &[u8]) -> Bytes {
        let id = msgid::compute(&topic.to_string(), payload, wire::MAX_PAYLOAD_BYTES).id;
        encode_datagram(&Frame::whole_message(
            id,
            topic_id,
            Bytes::copy_from_slice(payload),
        ))
    }

    /// A batch keys on its destination and nothing else, so one datagram carries entries for
    /// every topic the destination wants and each names its own id (D21). The receiver resolves
    /// them one at a time and publishes each on the topic its id resolved to.
    #[tokio::test(flavor = "multi_thread")]
    async fn entries_for_two_topics_in_one_datagram_are_each_published_on_their_own_topic() {
        let first = topic("beacon_attestation_1");
        let second = topic("beacon_attestation_2");
        let one = payload(b"an attestation on the first subnet");
        let two = payload(b"an attestation on the second subnet");
        let (cluster, peer) = peer_of(
            subscriptions(&[&first, &second], &[]),
            &[(1, &first), (2, &second)],
        )
        .await;

        datagram(&peer, batch(vec![entry(1, &one), entry(2, &two)]));

        eventually("both entries to be queued", || {
            cluster.published(1).len() == 2
        })
        .await;
        let published = cluster.published(1);
        assert_eq!(published[0].topic, first);
        assert_eq!(published[0].payload, one);
        assert_eq!(published[1].topic, second);
        assert_eq!(published[1].payload, two);
    }

    /// The same rule on the carrier the small class really travels on: an id this host cannot
    /// resolve costs that entry, and the entries around it in the datagram are published (D21).
    #[tokio::test(flavor = "multi_thread")]
    async fn entry_with_unknown_topic_id_is_dropped_and_the_rest_of_the_batch_is_published() {
        let subnet = topic("beacon_attestation_7");
        let wanted = payload(b"the entry under an id this host holds");
        let (cluster, peer) = peer_of(subscriptions(&[&subnet], &[]), &[(3, &subnet)]).await;

        datagram(
            &peer,
            batch(vec![
                entry(31, b"an id nobody announced"),
                entry(3, &wanted),
                entry(32, b"another one"),
            ]),
        );

        eventually("the readable entry to be queued", || {
            cluster.published(1).len() == 1
        })
        .await;
        assert_eq!(cluster.published(1)[0].payload, wanted);
        assert_eq!(cluster.stats(1).unknown_topic_ids(&cluster.hostname(0)), 2);
    }

    /// A sidecar publishes only what its own beacon node asked for, whatever a sibling sends it
    /// (DX-N1). The entry is counted as traffic that crossed the connection and then dropped, so
    /// both ends agree on what was sent and only one of them publishes it.
    #[tokio::test(flavor = "multi_thread")]
    async fn entry_for_a_topic_outside_the_advertised_set_is_counted_and_not_enqueued() {
        let wanted = topic("beacon_attestation_7");
        let column = topic("data_column_sidecar_37");
        let unwanted = payload(b"a column this beacon node does not custody");
        let (cluster, peer) = peer_of(
            subscriptions(&[&wanted], &[&column]),
            &[(3, &wanted), (4, &column)],
        )
        .await;

        datagram(&peer, batch(vec![entry(4, &unwanted)]));

        let sender = cluster.hostname(0);
        eventually("the entry to be refused", || {
            cluster.stats(1).unwanted_topics(&sender) == 1
        })
        .await;
        tokio::time::sleep(SETTLE).await;
        assert!(cluster.published(1).is_empty());
        assert!(cluster.seen(1).is_empty());
        assert_eq!(cluster.stats(1).messages(Direction::In, &sender), 1);
    }

    /// A datagram has no length prefix, so there is no way to step over a frame this release
    /// cannot read: the whole datagram goes, whatever is behind the type byte (D10). The
    /// connection carries on, and the next datagram is delivered as if the first had not been
    /// there.
    #[tokio::test(flavor = "multi_thread")]
    async fn datagram_with_unknown_frame_type_is_dropped_whole_and_counted() {
        let subnet = topic("beacon_attestation_7");
        let wanted = payload(b"the datagram after the one from the future");
        let (cluster, peer) = peer_of(subscriptions(&[&subnet], &[]), &[(3, &subnet)]).await;
        let readable = payload(b"the entry hidden behind the unknown type");
        let mut from_the_future = BytesMut::from(&[200u8, 0][..]);
        from_the_future.extend_from_slice(&batch(vec![entry(3, &readable)]));

        datagram(&peer, from_the_future.freeze());
        datagram(&peer, batch(vec![entry(3, &wanted)]));

        eventually("the datagram after it to be queued", || {
            cluster.published(1).len() == 1
        })
        .await;
        tokio::time::sleep(SETTLE).await;
        assert_eq!(cluster.published(1).len(), 1);
        assert_eq!(cluster.published(1)[0].payload, wanted);
        assert_eq!(
            cluster.stats(1).unknown_frame_types(&cluster.hostname(0)),
            1
        );
    }

    /// The seen cache is asked per payload and not per frame (D08), so a batch that carries the
    /// same attestation twice, which two origins reaching one relay will produce from T-063 on,
    /// costs the beacon node one publish.
    #[tokio::test(flavor = "multi_thread")]
    async fn datagram_receive_path_deduplicates_per_payload() {
        let subnet = topic("beacon_attestation_7");
        let twice = payload(b"one attestation, two entries");
        let (cluster, peer) = peer_of(subscriptions(&[&subnet], &[]), &[(3, &subnet)]).await;

        datagram(&peer, batch(vec![entry(3, &twice), entry(3, &twice)]));

        eventually("the first entry to be queued", || {
            cluster.published(1).len() == 1
        })
        .await;
        tokio::time::sleep(SETTLE).await;
        assert_eq!(cluster.published(1).len(), 1);
        assert_eq!(cluster.stats(1).duplicates(Class::Small), 1);
    }

    /// `messages_total` counts payloads, not frames (§12). A batch is a saving on the wire and
    /// not a message of its own, so an operator reading the counter sees the attestations that
    /// crossed the connection rather than the datagrams they were packed into.
    #[tokio::test(flavor = "multi_thread")]
    async fn metrics_count_payloads_not_batches() {
        let subnet = topic("beacon_attestation_7");
        let payloads = [
            payload(b"the first attestation"),
            payload(b"the second attestation"),
            payload(b"the third attestation"),
        ];
        let (cluster, peer) = peer_of(subscriptions(&[&subnet], &[]), &[(3, &subnet)]).await;

        datagram(&peer, batch(payloads.iter().map(|p| entry(3, p)).collect()));

        let sender = cluster.hostname(0);
        eventually("all three to be queued", || cluster.published(1).len() == 3).await;
        assert_eq!(cluster.stats(1).messages(Direction::In, &sender), 3);
        assert_eq!(
            cluster.stats(1).bytes(Direction::In, &sender),
            payloads.iter().map(|p| p.len() as u64).sum::<u64>()
        );
    }

    /// Nothing on this path waits for the beacon node (DX-N4). A queue with nothing draining it
    /// costs queue drops, and the datagram loop keeps taking datagrams off the connection while
    /// it fills, so a wedged beacon node on one host never stalls the socket it shares with the
    /// stream acceptor.
    #[tokio::test(flavor = "multi_thread")]
    async fn receive_loop_keeps_draining_when_the_publish_queue_is_full() {
        let subnet = topic("beacon_attestation_7");
        let queue = 4;
        let (cluster, peer) =
            peer_of_queueing(subscriptions(&[&subnet], &[]), &[(3, &subnet)], queue).await;
        let attestations: Vec<Vec<u8>> = (0..12)
            .map(|n| payload(format!("attestation {n}").as_bytes()))
            .collect();

        for chunk in attestations.chunks(4) {
            datagram(&peer, batch(chunk.iter().map(|p| entry(3, p)).collect()));
        }

        eventually("the queue to start dropping", || {
            cluster.publish_drops(1) > 0
        })
        .await;
        eventually("every entry to be read off the connection", || {
            cluster.publish_drops(1) == (attestations.len() - queue) as u64
        })
        .await;

        let after = payload(b"a whole message on a stream once the queue is full");
        send(&peer, &[whole(3, &subnet, &after)]).await;

        eventually("the stream acceptor to deliver as well", || {
            cluster.published(1).last().map(|item| item.payload.clone())
                == Some(after.clone().into())
        })
        .await;
    }

    /// A fanout that relays into a remote region of `min_remote_hosts` or more, through
    /// `per_region` of its hosts.
    fn relaying(min_remote_hosts: usize, per_region: usize) -> config::Fanout {
        config::Fanout {
            small: config::SmallFanout {
                relay_min_remote_hosts: min_remote_hosts,
                relays_per_remote_region: per_region,
                ..config::SmallFanout::default()
            },
            ..config::Fanout::default()
        }
    }

    /// A relay in `eu` with one in-region subscriber beside it, and a peer of the test's own in
    /// `us` to send `RELAY` batches from. Node 1 is the relay, node 2 the host it fans out to,
    /// and node 0 is the lowest hostname and so the one that dials.
    fn relay_cluster() -> Builder {
        Builder::new(&[NodeKind::Bare, NodeKind::Manager, NodeKind::Manager])
            .regions(&["us", "eu", "eu"])
    }

    /// That cluster started, with the peer of the test's own dialled and its topic announced.
    async fn relay_of(subnet: &Topic, builder: Builder) -> (TestCluster, PeerInfo) {
        let mut cluster = builder.start().await;
        for node in [1, 2] {
            cluster.start_sidecar(node, subscriptions(&[subnet], &[]));
        }
        eventually("the two siblings to pair and subscribe", || {
            cluster.live(1).subscribers(subnet).len() == 1
        })
        .await;
        let peer = cluster
            .dial_announcing(
                0,
                1,
                &cluster.self_hello(0),
                vec![(TopicId::new(3), subnet.to_string())],
            )
            .await;
        (cluster, peer)
    }

    /// A batch asking its destination to fan it out inside its own region (D11).
    fn relay_batch(entries: Vec<BatchEntry>) -> Bytes {
        encode_datagram(&Frame::Batch {
            flags: BatchFlags::RELAY,
            entries,
        })
    }

    /// The id a payload on `topic` hashes to, which is what the seen cache holds.
    fn id_of(topic: &Topic, payload: &[u8]) -> MessageId {
        msgid::compute(&topic.to_string(), payload, wire::MAX_PAYLOAD_BYTES).id
    }

    /// D20: a relay re-fans only what was new to its own seen cache. An entry it already held
    /// reached its region from another relay or from the origin and has been spread once
    /// already, and spreading it again would cost the region a copy per relay.
    #[tokio::test(flavor = "multi_thread")]
    async fn relay_refans_only_entries_new_to_its_seen_cache() {
        let subnet = topic("beacon_attestation_7");
        let held = payload(b"an attestation the relay is already holding");
        let fresh = payload(b"an attestation the relay has not seen");
        let (cluster, peer) = relay_of(&subnet, relay_cluster()).await;
        assert!(cluster.seen(1).insert(id_of(&subnet, &held)));

        datagram(&peer, relay_batch(vec![entry(3, &held), entry(3, &fresh)]));

        eventually("the in-region subscriber to be given the new entry", || {
            cluster.published(2).len() == 1
        })
        .await;
        tokio::time::sleep(SETTLE).await;
        assert_eq!(cluster.published(2)[0].payload, fresh);
        assert_eq!(cluster.published(2).len(), 1);
        assert_eq!(cluster.stats(1).relayed_batches(), 1);

        datagram(&peer, relay_batch(vec![entry(3, &held)]));

        tokio::time::sleep(SETTLE).await;
        assert_eq!(cluster.published(2).len(), 1, "nothing new was re-fanned");
        assert_eq!(cluster.stats(1).relayed_batches(), 1);
    }

    /// MD-04: a relay carries topics its own beacon node never asked for. It has no id of its
    /// own for one, so it interns one and announces it; until the peer has been told, the entry
    /// is held back rather than sent under an id the peer would drop and count against D12's
    /// alarm. Every batch here is a fresh attestation, which is what a real subnet delivers
    /// while the announcement crosses the control stream.
    #[tokio::test(flavor = "multi_thread")]
    async fn relay_carries_a_topic_its_beacon_node_never_subscribed_to() {
        let subnet = topic("beacon_attestation_7");
        let its_own = topic("beacon_attestation_2");
        let mut cluster = relay_cluster().start().await;
        cluster.start_sidecar(1, subscriptions(&[&its_own], &[]));
        cluster.start_sidecar(2, subscriptions(&[&subnet], &[]));
        eventually("the two siblings to pair", || cluster.live(1).len() == 1).await;
        let peer = cluster
            .dial_announcing(
                0,
                1,
                &cluster.self_hello(0),
                vec![(TopicId::new(3), subnet.to_string())],
            )
            .await;

        let mut sent = 0;
        eventually("the region behind the relay to be given one", || {
            sent += 1;
            datagram(
                &peer,
                relay_batch(vec![entry(
                    3,
                    &payload(format!("one of many {sent}").as_bytes()),
                )]),
            );
            !cluster.published(2).is_empty()
        })
        .await;

        assert!(
            cluster.published(1).is_empty(),
            "the relay wants none of it"
        );
        assert_eq!(
            cluster.stats(2).unknown_topic_ids(&cluster.hostname(1)),
            0,
            "an entry went out under an id the peer had not been told"
        );
    }

    /// MD-04's bound: a relay interns only a topic whose fork digest it already knows, because
    /// `Topic::parse` takes any of ~2^32 of them and the fan-out budget counts bytes, so a peer
    /// naming digests would be writing into this host's id space for free. An entry it will not
    /// name goes nowhere and is counted, which is the difference between a batch this host
    /// dropped and a batch that correctly held nothing new.
    #[tokio::test(flavor = "multi_thread")]
    async fn relay_entry_on_an_unknown_fork_digest_is_counted_and_not_refanned() {
        let subnet = topic("beacon_attestation_7");
        let foreign = Topic::parse("/eth2/deadbeef/beacon_attestation_7/ssz_snappy").unwrap();
        let payload = payload(b"an attestation from a fork this host has never heard of");
        let mut cluster = relay_cluster().start().await;
        for node in [1, 2] {
            cluster.start_sidecar(node, subscriptions(&[&subnet], &[]));
        }
        eventually("the two siblings to pair and subscribe", || {
            cluster.live(1).subscribers(&subnet).len() == 1
        })
        .await;
        let peer = cluster
            .dial_announcing(
                0,
                1,
                &cluster.self_hello(0),
                vec![
                    (TopicId::new(3), subnet.to_string()),
                    (TopicId::new(4), foreign.to_string()),
                ],
            )
            .await;

        datagram(&peer, relay_batch(vec![entry(4, &payload)]));

        eventually("the entry to be counted", || {
            cluster.stats(1).unannounced_topics() == 1
        })
        .await;
        tokio::time::sleep(SETTLE).await;
        assert_eq!(cluster.stats(1).relayed_batches(), 1, "the batch arrived");
        assert!(cluster.published(2).is_empty());
    }

    /// The arithmetic MD-04 is about: a region's subscribers to one attestation subnet are a
    /// minority of its live hosts, and the relay window is drawn from all of them, so a relay
    /// that wants nothing on the topic is the ordinary case rather than the odd one. Here every
    /// relay is such a host, and the twelve subscribers behind them are each offered the
    /// attestation once.
    #[tokio::test(flavor = "multi_thread")]
    async fn remote_region_where_subscribers_are_a_minority_still_all_publish_once() {
        let subnet = topic("beacon_attestation_7");
        let its_own = topic("beacon_attestation_2");
        let region: Vec<&str> = std::iter::once("eu")
            .chain(std::iter::repeat_n("us", 20))
            .collect();
        let mut cluster = Builder::new(&[NodeKind::Manager; 21])
            .regions(&region)
            .start()
            .await;
        let pool: Vec<Hostname> = (1..21).map(|node| cluster.hostname(node)).collect();
        let relays = overlay_core::relay::select(&cluster.hostname(0), &pool, 3);
        // The subscribers are twelve of the seventeen hosts the window missed, so every relay
        // is a host that wants nothing on the subnet and the old skip lost the whole region.
        let subscribers: Vec<usize> = (1..21)
            .filter(|node| !relays.contains(&cluster.hostname(*node)))
            .take(12)
            .collect();
        cluster.start_sidecar(0, subscriptions(&[&subnet], &[]));
        for node in 1..21 {
            let wanted = match subscribers.contains(&node) {
                true => &subnet,
                false => &its_own,
            };
            cluster.start_sidecar(node, subscriptions(&[wanted], &[]));
        }
        eventually("the region to say what it wants", || {
            cluster.live(0).subscribers(&subnet).len() == subscribers.len()
        })
        .await;
        // The first attestations on the subnet are what make the relays intern an id for it,
        // and they are lost while the announcement crosses the control stream.
        let mut warm = 0;
        eventually("every subscriber to be given one", || {
            warm += 1;
            cluster.from_bn(0, &subnet, &payload(format!("warming {warm}").as_bytes()));
            subscribers
                .iter()
                .all(|node| !cluster.published(*node).is_empty())
        })
        .await;
        let counted: Vec<usize> = subscribers
            .iter()
            .map(|node| cluster.published(*node).len())
            .collect();

        let once = payload(b"the one attestation this test counts");
        assert!(cluster.from_bn(0, &subnet, &once));

        for (node, before) in subscribers.iter().zip(counted) {
            eventually("the subscriber to be given it", || {
                cluster.published(*node).len() > before
            })
            .await;
        }
        tokio::time::sleep(SETTLE).await;
        for node in 1..21 {
            let copies = cluster
                .published(node)
                .iter()
                .filter(|item| item.payload == once)
                .count();
            assert_eq!(
                copies,
                usize::from(subscribers.contains(&node)),
                "node {node}"
            );
        }
    }

    /// D21: the relay re-coalesces through its own batcher, so an in-region subscriber gets one
    /// batch holding the entries it asked for and nothing else. The relay itself wants both
    /// topics and publishes both; the host beside it wants one and is sent one.
    #[tokio::test(flavor = "multi_thread")]
    async fn relay_recoalesces_entries_per_in_region_subscriber() {
        let (wanted, other) = (topic("beacon_attestation_1"), topic("beacon_attestation_2"));
        let one = payload(b"an attestation on the subnet the sibling wants");
        let two = payload(b"an attestation on a subnet only the relay wants");
        let mut cluster = Builder::new(&[NodeKind::Bare, NodeKind::Manager, NodeKind::Manager])
            .regions(&["us", "eu", "eu"])
            .start()
            .await;
        cluster.start_sidecar(1, subscriptions(&[&wanted, &other], &[]));
        cluster.start_sidecar(2, subscriptions(&[&wanted], &[]));
        eventually("the sibling to say which of the two it wants", || {
            cluster.live(1).subscribers(&wanted).len() == 1
                && cluster.live(1).subscribers(&other).is_empty()
        })
        .await;
        let peer = cluster
            .dial_announcing(
                0,
                1,
                &cluster.self_hello(0),
                vec![
                    (TopicId::new(3), wanted.to_string()),
                    (TopicId::new(4), other.to_string()),
                ],
            )
            .await;

        datagram(&peer, relay_batch(vec![entry(3, &one), entry(4, &two)]));

        eventually("the relay to publish both entries", || {
            cluster.published(1).len() == 2
        })
        .await;
        eventually("the sibling to be given the one it wants", || {
            cluster.published(2).len() == 1
        })
        .await;
        tokio::time::sleep(SETTLE).await;
        assert_eq!(cluster.published(2).len(), 1);
        assert_eq!(cluster.published(2)[0].topic, wanted);
        assert_eq!(cluster.published(2)[0].payload, one);
        assert_eq!(cluster.datagrams_received(2, &cluster.hostname(1)), 1);
    }

    /// The bit is what asks for the second hop, and without it a batch from another region is
    /// this host's alone. Without that rule `small.cross_region: direct` would have every host
    /// in a region forward every batch the WAN brought it (D11).
    #[tokio::test(flavor = "multi_thread")]
    async fn relay_clear_batch_from_remote_peer_is_not_forwarded() {
        let subnet = topic("beacon_attestation_7");
        let payload = payload(b"an attestation sent across the WAN directly");
        let (cluster, peer) = relay_of(&subnet, relay_cluster()).await;

        datagram(&peer, batch(vec![entry(3, &payload)]));

        eventually("the host it was sent to to queue it", || {
            cluster.published(1).len() == 1
        })
        .await;
        tokio::time::sleep(SETTLE).await;
        assert!(cluster.published(2).is_empty());
        assert_eq!(cluster.stats(1).relayed_batches(), 0);
    }

    /// DX-N3: re-fanning is fan-out a remote peer asked for, so it is metered per peer. Over
    /// budget the batch is still delivered here, because the payloads are good and this host
    /// wants them; what the peer does not get is a region fanned out on its say-so.
    #[tokio::test(flavor = "multi_thread")]
    async fn relay_batches_over_the_budget_are_delivered_locally_and_not_refanned() {
        let subnet = topic("beacon_attestation_7");
        let payload = payload(b"an attestation from a peer asking for too much");
        let (cluster, peer) = relay_of(
            &subnet,
            relay_cluster().budget(FanoutBudget::new(1, 1, Instant::now())),
        )
        .await;

        datagram(&peer, relay_batch(vec![entry(3, &payload)]));

        eventually("the relay to queue it for its own beacon node", || {
            cluster.published(1).len() == 1
        })
        .await;
        tokio::time::sleep(SETTLE).await;
        assert!(cluster.published(2).is_empty(), "it was re-fanned anyway");
        assert_eq!(
            cluster
                .stats(1)
                .fanout_suppressed(&cluster.hostname(0), FanoutKind::Relay),
            1
        );
        assert_eq!(cluster.stats(1).relayed_batches(), 0);
    }

    /// A peer that keeps asking past its budget for longer than [`SUSTAINED_VIOLATION`] loses
    /// the connection with `RateExceeded` (DX-N3, T-023). The ten seconds are the sidecar's
    /// injected clock, so nothing here waits for them, and the bucket refills at nothing so the
    /// second batch is refused for the same reason as the first.
    #[tokio::test(flavor = "multi_thread")]
    async fn sustained_budget_violation_closes_the_connection_with_rate_exceeded() {
        let subnet = topic("beacon_attestation_7");
        let clock = FakeClock::new();
        let (cluster, peer) = relay_of(
            &subnet,
            relay_cluster()
                .budget(FanoutBudget::new(0, 1, clock.now()))
                .clock(Arc::new(clock.clone())),
        )
        .await;
        let origin = cluster.hostname(0);

        datagram(&peer, relay_batch(vec![entry(3, &payload(b"over budget"))]));

        eventually("the first refusal", || {
            cluster
                .stats(1)
                .fanout_suppressed(&origin, FanoutKind::Relay)
                == 1
        })
        .await;
        assert_eq!(cluster.live(1).len(), 2, "one refusal is not a close");

        clock.advance(SUSTAINED_VIOLATION + Duration::from_secs(1));
        datagram(
            &peer,
            relay_batch(vec![entry(3, &payload(b"still over budget"))]),
        );

        eventually("the connection to go", || {
            cluster.live(1).get(&origin).is_none()
        })
        .await;
        assert_eq!(
            cluster
                .stats(1)
                .fanout_suppressed(&origin, FanoutKind::Relay),
            2
        );
    }

    /// §5.4 end to end over two regions: an attestation reaches every subscriber in the remote
    /// one, and the WAN carried one copy per relay rather than one per host. The relay's own
    /// batch goes out with `RELAY` clear, so the hosts it fans to spread nothing further and
    /// each of them is offered the attestation once.
    #[tokio::test(flavor = "multi_thread")]
    async fn relay_forwards_a_relay_batch_in_region_once_with_relay_clear() {
        let subnet = topic("beacon_attestation_7");
        let payload = payload(b"one attestation for two regions");
        let mut cluster = Builder::new(&[NodeKind::Manager; 6])
            .regions(&["eu", "eu", "eu", "us", "us", "us"])
            .fanout(relaying(3, 1))
            .start()
            .await;
        for node in 0..6 {
            cluster.start_sidecar(node, subscriptions(&[&subnet], &[]));
        }
        eventually("every host to say it wants the subnet", || {
            (0..6).all(|node| cluster.live(node).subscribers(&subnet).len() == 5)
        })
        .await;

        assert!(cluster.from_bn(0, &subnet, &payload));

        for node in 1..6 {
            eventually("every other host to queue it", || {
                cluster.published(node).len() == 1
            })
            .await;
        }
        tokio::time::sleep(SETTLE).await;
        let origin = cluster.hostname(0);
        let over_the_wan = (3..6)
            .filter(|node| cluster.stats(*node).messages(Direction::In, &origin) > 0)
            .count();
        assert_eq!(over_the_wan, 1, "one WAN copy per relay, not one per host");
        for node in 0..6 {
            assert_eq!(cluster.published(node).len(), usize::from(node != 0));
            assert_eq!(cluster.stats(node).duplicates(Class::Small), 0);
            for peer in 0..6 {
                assert_eq!(
                    cluster
                        .stats(node)
                        .relay_same_region(&cluster.hostname(peer)),
                    0,
                    "a batch was re-fanned with RELAY still set"
                );
            }
        }
    }

    /// A relay fans out for the region on the other side of the WAN, never for its own: a
    /// `RELAY` batch from a peer in this host's region is a peer breaking the protocol, and
    /// honouring it would have every host in a region spread what its neighbours already have.
    /// The batch is counted, delivered here and forwarded nowhere (D20).
    #[tokio::test(flavor = "multi_thread")]
    async fn relay_set_from_same_region_peer_is_counted_and_not_forwarded() {
        let subnet = topic("beacon_attestation_7");
        let relayed = payload(b"an attestation asking to be spread further");
        // The bare node is the lowest hostname, so it dials, and the two managers pair with
        // each other and wait for it: a peer of the test's own on one side of a live pair.
        let mut cluster = Builder::new(&[NodeKind::Bare, NodeKind::Manager, NodeKind::Manager])
            .start()
            .await;
        for node in [1, 2] {
            cluster.start_sidecar(node, subscriptions(&[&subnet], &[]));
        }
        eventually("the two siblings to pair and subscribe", || {
            cluster.live(1).subscribers(&subnet).len() == 1
        })
        .await;
        let peer = cluster
            .dial_announcing(
                0,
                1,
                &cluster.self_hello(0),
                vec![(TopicId::new(3), subnet.to_string())],
            )
            .await;

        datagram(
            &peer,
            encode_datagram(&Frame::Batch {
                flags: BatchFlags::RELAY,
                entries: vec![entry(3, &relayed)],
            }),
        );

        eventually("the host it was sent to to queue it", || {
            cluster.published(1).len() == 1
        })
        .await;
        tokio::time::sleep(SETTLE).await;
        assert!(cluster.published(2).is_empty());
        assert_eq!(
            cluster.stats(1).relay_same_region(&cluster.hostname(0)),
            1,
            "a same-region relay batch was not counted"
        );
        assert_eq!(cluster.stats(1).relayed_batches(), 0);
    }

    /// Any number of regions, each decided on its own (§5.4): the fleet is three, three and one
    /// host, and the origin relays into the region at the threshold while the single-host one is
    /// sent to directly. Every beacon node in the fleet is offered the attestation once.
    #[tokio::test(flavor = "multi_thread")]
    async fn three_region_fleet_relays_into_regions_at_the_threshold_and_goes_direct_below_it() {
        let subnet = topic("beacon_attestation_7");
        let payload = payload(b"one attestation for three regions");
        let mut cluster = Builder::new(&[NodeKind::Manager; 7])
            .regions(&["eu", "eu", "eu", "us", "us", "us", "ap"])
            .fanout(relaying(3, 1))
            .start()
            .await;
        for node in 0..7 {
            cluster.start_sidecar(node, subscriptions(&[&subnet], &[]));
        }
        eventually("every host to say it wants the subnet", || {
            (0..7).all(|node| cluster.live(node).subscribers(&subnet).len() == 6)
        })
        .await;

        assert!(cluster.from_bn(0, &subnet, &payload));

        for node in 1..7 {
            eventually("every other host to queue it", || {
                cluster.published(node).len() == 1
            })
            .await;
        }
        tokio::time::sleep(SETTLE).await;
        let origin = cluster.hostname(0);
        let over_the_wan = |nodes: std::ops::Range<usize>| {
            nodes
                .filter(|node| cluster.stats(*node).messages(Direction::In, &origin) > 0)
                .count()
        };
        assert_eq!(over_the_wan(3..6), 1, "the region at the threshold relays");
        assert_eq!(over_the_wan(6..7), 1, "the single-host region is direct");
        for node in 0..7 {
            assert_eq!(cluster.published(node).len(), usize::from(node != 0));
        }
    }

    /// Nothing tracks who the relays are: the selection is re-derived from the live set on every
    /// message, so a relay that dies is out of the pool and the next batch goes to whoever the
    /// hash lands on now (D20, §9). The region keeps getting its attestations throughout.
    #[tokio::test(flavor = "multi_thread")]
    async fn relay_going_down_is_replaced_in_the_next_selection() {
        let subnet = topic("beacon_attestation_7");
        let (first, second) = (payload(b"before the relay went"), payload(b"after it went"));
        let mut cluster = Builder::new(&[NodeKind::Manager; 5])
            .regions(&["eu", "us", "us", "us", "us"])
            .fanout(relaying(3, 1))
            .start()
            .await;
        for node in 0..5 {
            cluster.start_sidecar(node, subscriptions(&[&subnet], &[]));
        }
        eventually("every host to say it wants the subnet", || {
            (0..5).all(|node| cluster.live(node).subscribers(&subnet).len() == 4)
        })
        .await;
        assert!(cluster.from_bn(0, &subnet, &first));
        for node in 1..5 {
            eventually("the region to be given the first attestation", || {
                cluster.published(node).len() == 1
            })
            .await;
        }
        let origin = cluster.hostname(0);
        let relay = (1..5)
            .find(|node| cluster.stats(*node).messages(Direction::In, &origin) > 0)
            .expect("one host of the region carried the batch");

        cluster.set_roster_for(0, &(0..5).filter(|node| *node != relay).collect::<Vec<_>>());
        eventually("the origin to lose the relay", || {
            cluster.live(0).get(&cluster.hostname(relay)).is_none()
        })
        .await;
        assert!(cluster.from_bn(0, &subnet, &second));

        for node in 1..5 {
            eventually("the region to be given the second attestation", || {
                cluster.published(node).len() == 2
            })
            .await;
        }
        let carried = (1..5)
            .filter(|node| cluster.stats(*node).messages(Direction::In, &origin) > 0)
            .collect::<Vec<_>>();
        assert!(
            carried.len() == 2 && carried.contains(&relay),
            "the second batch went to a host that was not the first relay: {carried:?}"
        );
    }

    /// An entry id the peer never announced costs that entry and nothing else (D21): the rest of
    /// the batch is delivered and the connection carries on, because the sender is one release
    /// ahead or its `TOPIC_ADD` has not arrived yet, neither of which is a protocol error.
    #[tokio::test(flavor = "multi_thread")]
    async fn unknown_topic_id_drops_only_that_batch_entry_and_keeps_the_connection() {
        let block = topic("beacon_block");
        let wanted = payload(b"the entry with an id this host knows");
        let (cluster, peer) = peer_of(subscriptions(&[&block], &[]), &[(4, &block)]).await;

        send(
            &peer,
            &[encode_datagram(&Frame::Batch {
                flags: BatchFlags::NONE,
                entries: vec![
                    BatchEntry {
                        topic_id: 9,
                        payload: Bytes::from_static(b"nobody can read this"),
                    },
                    BatchEntry {
                        topic_id: 4,
                        payload: Bytes::from(wanted.clone()),
                    },
                ],
            })],
        )
        .await;

        eventually("the readable entry to be queued", || {
            cluster.published(1).len() == 1
        })
        .await;
        assert_eq!(cluster.published(1)[0].payload, wanted);
        let sender = cluster.hostname(0);
        assert_eq!(cluster.stats(1).unknown_topic_ids(&sender), 1);
        assert_eq!(cluster.live(1).len(), 1);
    }

    /// A frame type this release has never heard of is skipped and reading goes on, which is
    /// what lets a fleet run two releases at once (D10). The next frame on the same stream is
    /// delivered as if the first had not been there.
    #[tokio::test(flavor = "multi_thread")]
    async fn unknown_frame_type_on_a_stream_is_skipped_and_the_next_frame_is_delivered() {
        let block = topic("beacon_block");
        let wanted = payload(b"the frame after the one from the future");
        let (cluster, peer) = peer_of(subscriptions(&[&block], &[]), &[(0, &block)]).await;
        let from_the_future = Bytes::from_static(&[200, 0, 1, 2, 3]);

        send(&peer, &[from_the_future, whole(0, &block, &wanted)]).await;

        eventually("the frame after it to be queued", || {
            cluster.published(1).len() == 1
        })
        .await;
        assert_eq!(cluster.published(1)[0].payload, wanted);
        assert_eq!(
            cluster.stats(1).unknown_frame_types(&cluster.hostname(0)),
            1
        );
    }

    /// A sidecar publishes only what its own beacon node subscribed to (DX-N1). A sibling can
    /// hold an id for one of T-015's extra column topics, which this host interned and announced
    /// so its own proposals have ids, and sending on it is still traffic nobody here wants.
    #[tokio::test(flavor = "multi_thread")]
    async fn payload_on_a_topic_outside_the_advertised_set_is_dropped_and_counted_unwanted() {
        let block = topic("beacon_block");
        let column = topic("data_column_sidecar_37");
        let unwanted = payload(b"a column this beacon node does not custody");
        let (cluster, peer) = peer_of(subscriptions(&[&block], &[&column]), &[(0, &column)]).await;

        send(&peer, &[whole(0, &column, &unwanted)]).await;

        let sender = cluster.hostname(0);
        eventually("the payload to be refused", || {
            cluster.stats(1).unwanted_topics(&sender) == 1
        })
        .await;
        tokio::time::sleep(SETTLE).await;
        assert!(cluster.published(1).is_empty());
        assert!(cluster.seen(1).is_empty());
        assert_eq!(cluster.stats(1).messages(Direction::In, &sender), 1);
    }

    /// Lighthouse refuses a payload that does not decompress before it computes an id for it, so
    /// one that reaches this host must not be published and must not be remembered either: the
    /// id it would be remembered under is not an id the beacon node would ever agree with (D03).
    /// A whole message whose header names an id the payload does not hash to is the same case.
    #[tokio::test(flavor = "multi_thread")]
    async fn invalid_snappy_payload_is_dropped_counted_and_neither_inserted_nor_published() {
        let block = topic("beacon_block");
        let good = payload(b"a payload that does decompress");
        let (cluster, peer) = peer_of(subscriptions(&[&block], &[]), &[(0, &block)]).await;
        let not_snappy = Bytes::from_static(b"\x05\x10not snappy at all");
        let wrong_id = encode_datagram(&Frame::whole_message(
            MessageId([7; 20]),
            0,
            Bytes::from(good.clone()),
        ));

        send(&peer, &[whole(0, &block, &not_snappy), wrong_id]).await;

        let sender = cluster.hostname(0);
        eventually("both payloads to be refused", || {
            cluster.stats(1).invalid_payloads(&sender) == 2
        })
        .await;
        tokio::time::sleep(SETTLE).await;
        assert!(cluster.published(1).is_empty());
        assert!(cluster.seen(1).is_empty());
    }

    /// The v1 flow end to end (§6.1): the beacon node forwards a block to its sidecar, the
    /// sidecar routes it to the siblings whose beacon nodes are subscribed, and each of them
    /// queues one copy for its own node. The origin publishes nothing back into the node the
    /// message came from.
    #[tokio::test(flavor = "multi_thread")]
    async fn message_from_a_bn_reaches_every_subscribed_peer_exactly_once() {
        let block = topic("beacon_block");
        let payload = payload(b"one block, three nodes");
        let mut cluster = TestCluster::start(3).await;
        for node in 0..3 {
            cluster.start_sidecar(node, subscriptions(&[&block], &[]));
        }
        eventually("both siblings to subscribe", || {
            cluster.live(0).subscribers(&block).len() == 2
        })
        .await;

        assert!(cluster.from_bn(0, &block, &payload));

        for node in [1, 2] {
            eventually("the sibling to queue it", || {
                cluster.published(node).len() == 1
            })
            .await;
        }
        tokio::time::sleep(SETTLE).await;
        assert_eq!(cluster.published(1).len(), 1);
        assert_eq!(cluster.published(2).len(), 1);
        assert!(cluster.published(0).is_empty());
        for sibling in [1, 2] {
            let hostname = cluster.hostname(sibling);
            assert_eq!(cluster.stats(0).messages(Direction::Out, &hostname), 1);
            assert_eq!(
                cluster.stats(0).bytes(Direction::Out, &hostname),
                payload.len() as u64
            );
        }
    }

    /// A message goes only to peers whose beacon node is subscribed to its topic (§5.4). The
    /// unsubscribed peer is connected and healthy; it is simply not sent anything, so the
    /// overlay costs nothing for topics a host does not want.
    #[tokio::test(flavor = "multi_thread")]
    async fn unsubscribed_peer_receives_nothing() {
        let block = topic("beacon_block");
        let attestation = topic("beacon_attestation_3");
        let payload = payload(b"a block only two of the three want");
        let mut cluster = TestCluster::start(3).await;
        cluster.start_sidecar(0, subscriptions(&[&block], &[]));
        cluster.start_sidecar(1, subscriptions(&[&block], &[]));
        cluster.start_sidecar(2, subscriptions(&[&attestation], &[]));
        eventually("both siblings to say what they want", || {
            cluster.live(0).subscribers(&block).len() == 1
                && cluster.live(0).subscribers(&attestation).len() == 1
        })
        .await;

        assert!(cluster.from_bn(0, &block, &payload));

        eventually("the subscribed sibling to queue it", || {
            cluster.published(1).len() == 1
        })
        .await;
        tokio::time::sleep(SETTLE).await;
        assert!(cluster.published(2).is_empty());
        assert_eq!(
            cluster
                .stats(0)
                .messages(Direction::Out, &cluster.hostname(2)),
            0
        );
    }

    /// Two beacon nodes that both got a message from public gossip hand it to their sidecars,
    /// and both route it to the third (§5.5). The copies carry the same id, so the second one
    /// is dropped at the seen cache and the beacon node is offered the message once.
    #[tokio::test(flavor = "multi_thread")]
    async fn same_message_from_two_origins_is_published_once() {
        let block = topic("beacon_block");
        let payload = payload(b"a block two nodes received first");
        let mut cluster = TestCluster::start(3).await;
        for node in 0..3 {
            cluster.start_sidecar(node, subscriptions(&[&block], &[]));
        }
        eventually("the mesh to subscribe", || {
            cluster.live(2).subscribers(&block).len() == 2
        })
        .await;

        assert!(cluster.from_bn(0, &block, &payload));
        assert!(cluster.from_bn(1, &block, &payload));

        eventually("both copies to reach the third node", || {
            cluster
                .stats(2)
                .messages(Direction::In, &cluster.hostname(0))
                == 1
                && cluster
                    .stats(2)
                    .messages(Direction::In, &cluster.hostname(1))
                    == 1
        })
        .await;
        assert_eq!(cluster.published(2).len(), 1);
        assert_eq!(cluster.stats(2).duplicates(Class::Large), 1);
        assert_eq!(cluster.stats(2).first_seen(Class::Large), 1);
    }

    /// A beacon node forwards back what its sidecar published into it, because it validated the
    /// message and does not know where it came from. The seen cache holds the id from the
    /// receive path (D08), so the echo stops at the sidecar and never goes back out to the peer
    /// that sent it.
    #[tokio::test(flavor = "multi_thread")]
    async fn bn_echo_of_an_overlay_message_is_dropped() {
        let block = topic("beacon_block");
        let payload = payload(b"a block that comes straight back");
        let mut cluster = TestCluster::start(2).await;
        for node in 0..2 {
            cluster.start_sidecar(node, subscriptions(&[&block], &[]));
        }
        eventually("the pair to subscribe", || {
            cluster.live(0).subscribers(&block).len() == 1
        })
        .await;
        assert!(cluster.from_bn(0, &block, &payload));
        eventually("the sibling to queue it", || {
            cluster.published(1).len() == 1
        })
        .await;

        assert!(!cluster.from_bn(1, &block, &payload));

        tokio::time::sleep(SETTLE).await;
        assert_eq!(
            cluster
                .stats(1)
                .messages(Direction::Out, &cluster.hostname(0)),
            0
        );
        assert!(cluster.published(0).is_empty());
    }

    /// The overlay carries the gossipsub wire form and never looks inside it (§7), so what the
    /// beacon node at the far end is offered is byte for byte what the near one produced.
    #[tokio::test(flavor = "multi_thread")]
    async fn payload_bytes_are_identical_end_to_end() {
        let block = topic("beacon_block");
        let every_byte: Vec<u8> = (0..=255).cycle().take(8192).collect();
        let payload = payload(&every_byte);
        let mut cluster = TestCluster::start(2).await;
        for node in 0..2 {
            cluster.start_sidecar(node, subscriptions(&[&block], &[]));
        }
        eventually("the pair to subscribe", || {
            cluster.live(0).subscribers(&block).len() == 1
        })
        .await;

        assert!(cluster.from_bn(0, &block, &payload));

        eventually("the sibling to queue it", || {
            cluster.published(1).len() == 1
        })
        .await;
        let published = cluster.published(1);
        assert_eq!(published[0].payload, payload);
        assert_eq!(published[0].topic, block);
    }

    /// Nothing on this path waits for the beacon node (DX-N4). With the publish queue full and
    /// nothing draining it, every stream still completes and the queue drops its oldest entries;
    /// a receiver that awaited the beacon node would instead leave the peer's streams open and
    /// its receive window shut.
    #[tokio::test(flavor = "multi_thread")]
    async fn receive_path_keeps_draining_when_the_publisher_is_stalled() {
        let block = topic("beacon_block");
        let mut cluster = Builder::new(&[NodeKind::Bare, NodeKind::Manager])
            .start()
            .await;
        cluster.start_sidecar_with(1, subscriptions(&[&block], &[]), 2);
        let peer = cluster
            .dial_announcing(
                0,
                1,
                &cluster.self_hello(0),
                vec![(TopicId::new(0), block.to_string())],
            )
            .await;

        for message in 0..10 {
            let payload = payload(format!("message {message}").as_bytes());
            send(&peer, &[whole(0, &block, &payload)]).await;
        }

        let sender = cluster.hostname(0);
        eventually("every stream to complete", || {
            cluster.stats(1).messages(Direction::In, &sender) == 10
        })
        .await;
        assert_eq!(cluster.published(1).len(), 2);
        assert_eq!(cluster.publish_drops(1), 8);
        assert_eq!(cluster.live(1).len(), 1);
    }

    /// A topic name this release does not know is classified by payload size, because the class
    /// only picks the transport path and a wrong guess must not cost a fork's worth of traffic
    /// (D02). Both ends count the same message under the same class.
    #[tokio::test(flavor = "multi_thread")]
    async fn metrics_label_class_by_payload_length_for_unknown_kinds() {
        let unknown = topic("something_this_release_has_never_heard_of");
        let small = payload(&[7; 240]);
        // Pseudo-random bytes, which snappy stores as literals, so the payload the class is
        // read from is about the size it started at, the way signed SSZ is.
        let mut state = 0x9E37_79B1u32;
        let large = payload(
            &(0..20 * 1024)
                .map(|_| {
                    state ^= state << 13;
                    state ^= state >> 17;
                    state ^= state << 5;
                    state as u8
                })
                .collect::<Vec<u8>>(),
        );
        assert!(small.len() < UNKNOWN_LARGE_THRESHOLD_BYTES);
        assert!(large.len() >= UNKNOWN_LARGE_THRESHOLD_BYTES);
        let mut cluster = TestCluster::start(2).await;
        for node in 0..2 {
            cluster.start_sidecar(node, subscriptions(&[&unknown], &[]));
        }
        eventually("the pair to subscribe", || {
            cluster.live(0).subscribers(&unknown).len() == 1
        })
        .await;

        assert!(cluster.from_bn(0, &unknown, &small));
        assert!(cluster.from_bn(0, &unknown, &large));

        eventually("both to be queued", || cluster.published(1).len() == 2).await;
        let (sender, receiver) = (cluster.hostname(0), cluster.hostname(1));
        for (class, bytes) in [(Class::Small, small.len()), (Class::Large, large.len())] {
            assert_eq!(
                cluster
                    .stats(0)
                    .messages_of(Direction::Out, class, &receiver),
                1
            );
            assert_eq!(
                cluster.stats(1).messages_of(Direction::In, class, &sender),
                1
            );
            assert_eq!(cluster.stats(1).first_seen(class), 1);
            assert!(
                cluster
                    .published(1)
                    .iter()
                    .any(|item| { item.class == class && item.payload.len() == bytes })
            );
        }
    }

    /// A peer that opens a stream, says how long its frame is and then stops writing holds a
    /// receive-window slot until something gives up on it (DX-N3). The reader gives up after
    /// [`STREAM_READ_TIMEOUT`], stops the stream and ends, so the task goes with it and the rest
    /// of the connection is untouched.
    #[tokio::test(start_paused = true)]
    async fn stalled_stream_is_closed_after_the_2s_read_timeout_without_leaking_a_task() {
        let block = topic("beacon_block");
        let published = Arc::new(PublishSpy::new(8));
        let (_sets, watching) = watch::channel(subscriptions(&[&block], &[]));
        let stats = Arc::new(CountingStats::default());
        let ctx = Arc::new(Ctx {
            peer: Hostname("stalled".to_owned()),
            region: Region("eu".to_owned()),
            site: None,
            state: Arc::new(Mutex::new(PeerState::default())),
            budget: Mutex::new(FanoutBudget::default_for(2, 2048, 12, Instant::now())),
            deps: Deps {
                seen: SharedSeenCache::new(SeenCache::new(
                    Duration::from_secs(60),
                    16,
                    Arc::new(SystemClock),
                )),
                recent: SharedRecentLarge::new(RecentLarge::new(RECENT_TTL, RECENT_MAX_BYTES)),
                custody: SharedCustody::new(&crate::testutil::mainnet_spec()),
                publish: published.clone(),
                sets: watching,
                reassembler: Arc::new(Reassembler::new(ReassembleConfig::default())),
                stats,
                node: Arc::new(SelfIdentity {
                    hostname: Hostname("stalled-host".to_owned()),
                    region: Region("eu".to_owned()),
                    site: None,
                }),
                clock: Arc::new(SystemClock),
                budget: FanoutBudget::default_for(2, 2048, 12, Instant::now()),
                large: config::LargeClass::default(),
                relaying: Relaying {
                    live: LiveSource::fixed(crate::manager::LiveView::default()),
                    topics: Arc::new(Mutex::new(OwnTopics::default())),
                    batches: crate::batching::Batching::spawn(
                        watch::channel(overlay_core::config::SmallClass::default()).1,
                        Arc::new(()),
                    )
                    .0,
                },
            },
            warned_invalid: AtomicBool::new(false),
        });
        let (mut peer, stream) = tokio::io::duplex(64);
        // A frame is coming, says the peer, and then nothing does.
        peer.write_all(&64u32.to_le_bytes()).await.unwrap();
        let started = tokio::time::Instant::now();

        let reading = tokio::spawn(async move {
            let mut stream = stream;
            read_frames(&mut stream, &ctx).await
        });

        let end = tokio::time::timeout(WAIT, reading)
            .await
            .expect("the reader gave up on the stream")
            .unwrap();
        assert_eq!(end, StreamEnd::Timeout);
        assert!(started.elapsed() >= STREAM_READ_TIMEOUT);
        assert!(published.published().is_empty());
    }

    /// A peer that keeps asking for more second-hop work than its budget covers loses the
    /// connection (DX-N3), and comes back through the ordinary reconnect backoff, which is what
    /// makes the close a pause rather than a punishment.
    #[tokio::test(flavor = "multi_thread")]
    async fn sustained_budget_violation_for_10s_closes_with_rate_exceeded_and_the_peer_reconnects()
    {
        let block = topic("beacon_block");
        let mut cluster = TestCluster::start(2).await;
        for node in 0..2 {
            cluster.start_sidecar(node, subscriptions(&[&block], &[]));
        }
        let sender = cluster.hostname(0);
        eventually("the pair to pair", || {
            cluster.receiver(1, &sender).is_some()
        })
        .await;
        let receiver = cluster.receiver(1, &sender).unwrap();
        let over_budget = 20 * 1024 * 1024;
        let went_over = Instant::now();

        assert_eq!(
            receiver.charge(FanoutKind::Chunk, over_budget, went_over),
            Charge::Suppressed
        );
        tokio::time::sleep(SETTLE).await;
        assert_eq!(
            cluster.live(1).len(),
            1,
            "one violation is not what the close is for"
        );

        assert_eq!(
            receiver.charge(
                FanoutKind::Chunk,
                over_budget,
                went_over + SUSTAINED_VIOLATION + Duration::from_secs(1)
            ),
            Charge::CloseRateExceeded
        );

        assert_eq!(
            cluster
                .stats(1)
                .fanout_suppressed(&sender, FanoutKind::Chunk),
            2
        );
        eventually("the connection to go", || cluster.live(1).is_empty()).await;
        eventually("the peer to come back", || {
            cluster.live(1).len() == 1 && cluster.live(0).len() == 1
        })
        .await;
    }

    /// A region of `hosts` sidecars with a peer of the test's own beside them, all subscribed to
    /// blocks. Node 0 is the peer, the lowest hostname and so the one that dials; the sidecars
    /// are nodes 1 upwards and pair with each other.
    async fn striping_region(hosts: usize) -> (TestCluster, PeerInfo, Topic) {
        striping_region_with(hosts, |builder| builder).await
    }

    /// The same, with `with` applied to the builder first, for a test that needs a clock of its
    /// own or bounds it can reach.
    async fn striping_region_with(
        hosts: usize,
        with: impl FnOnce(Builder) -> Builder,
    ) -> (TestCluster, PeerInfo, Topic) {
        let block = topic("beacon_block");
        let kinds: Vec<NodeKind> = std::iter::once(NodeKind::Bare)
            .chain(std::iter::repeat_n(NodeKind::Manager, hosts))
            .collect();
        let mut cluster = with(Builder::new(&kinds)).start().await;
        for node in 1..=hosts {
            cluster.start_sidecar(node, subscriptions(&[&block], &[]));
        }
        eventually("the region to pair and subscribe", || {
            (1..=hosts).all(|node| cluster.live(node).subscribers(&block).len() == hosts - 1)
        })
        .await;
        let peer = cluster
            .dial_announcing(
                0,
                1,
                &cluster.self_hello(0),
                vec![(TopicId::new(3), block.to_string())],
            )
            .await;
        (cluster, peer, block)
    }

    /// One chunk of a striped message, as the host it was assigned to would be sent it.
    fn chunk_frame(msg_id: MessageId, index: u16, flags: ChunkFlags) -> Bytes {
        encode_datagram(&Frame::Chunk {
            flags,
            chunk: Chunk {
                msg_id,
                topic_id: 3,
                k: 4,
                m: 1,
                index,
                total_len: 32,
                data: Bytes::from_static(b"12345678"),
            },
        })
    }

    /// D19 and §5.4 step 3: a chunk that arrives clear is the region's, so the host it landed on
    /// hands it to every live in-region peer subscribed to the topic, with `FORWARDED` set, and
    /// not back to the host it came from. That second hop is what turns one chunk per host into
    /// a whole message per host without the origin sending one.
    #[tokio::test(flavor = "multi_thread")]
    async fn clear_chunk_is_forwarded_in_region_with_forwarded_set_to_all_subscribed_peers_except_sender()
     {
        let (cluster, peer, _) = striping_region(3).await;
        let sender = cluster.hostname(0);
        let forwarder = cluster.hostname(1);

        send(
            &peer,
            &[chunk_frame(MessageId([5; 20]), 2, ChunkFlags::NONE)],
        )
        .await;

        for node in [2, 3] {
            eventually("the rest of the region to be given it", || {
                !cluster.stats(node).chunks_received(&forwarder).is_empty()
            })
            .await;
            assert_eq!(
                cluster.stats(node).chunks_received(&forwarder),
                vec![(ChunkFlags::FORWARDED, 2)]
            );
        }
        tokio::time::sleep(SETTLE).await;
        assert_eq!(
            cluster.stats(1).bytes(Direction::Out, &sender),
            0,
            "the chunk went back to the host it came from"
        );
    }

    /// D11: the second hop is never a third. A chunk that already carries `FORWARDED` reached
    /// this host from a neighbour that had it from the origin, so every host in the region is
    /// being offered it and passing it on again would cost the region a copy per host.
    #[tokio::test(flavor = "multi_thread")]
    async fn forwarded_chunk_is_never_forwarded_again() {
        let (cluster, peer, _) = striping_region(3).await;
        let forwarder = cluster.hostname(1);

        send(
            &peer,
            &[chunk_frame(MessageId([6; 20]), 1, ChunkFlags::FORWARDED)],
        )
        .await;

        eventually("the host it was sent to to count it", || {
            cluster.stats(1).chunks_received(&cluster.hostname(0)).len() == 1
        })
        .await;
        tokio::time::sleep(SETTLE).await;
        for node in [2, 3] {
            assert!(
                cluster.stats(node).chunks_received(&forwarder).is_empty(),
                "node {node}"
            );
        }
    }

    /// §5.4: the second hop never crosses the WAN. The origin builds a stripe per region, so a
    /// host that forwarded into another one would be sending copies that region is already
    /// being sent, over the link the whole scheme exists to spend once.
    #[tokio::test(flavor = "multi_thread")]
    async fn clear_chunk_is_not_forwarded_to_hosts_in_other_regions() {
        let block = topic("beacon_block");
        let mut cluster = Builder::new(&[
            NodeKind::Bare,
            NodeKind::Manager,
            NodeKind::Manager,
            NodeKind::Manager,
        ])
        .regions(&["eu", "eu", "eu", "us"])
        .start()
        .await;
        for node in 1..4 {
            cluster.start_sidecar(node, subscriptions(&[&block], &[]));
        }
        eventually("the three sidecars to pair and subscribe", || {
            (1..4).all(|node| cluster.live(node).subscribers(&block).len() == 2)
        })
        .await;
        let peer = cluster
            .dial_announcing(
                0,
                1,
                &cluster.self_hello(0),
                vec![(TopicId::new(3), block.to_string())],
            )
            .await;
        let forwarder = cluster.hostname(1);

        send(
            &peer,
            &[chunk_frame(MessageId([7; 20]), 0, ChunkFlags::NONE)],
        )
        .await;

        eventually("the host in the same region to be given it", || {
            !cluster.stats(2).chunks_received(&forwarder).is_empty()
        })
        .await;
        tokio::time::sleep(SETTLE).await;
        assert!(
            cluster.stats(3).chunks_received(&forwarder).is_empty(),
            "the chunk crossed into the other region"
        );
    }

    /// D19 and §5.4 step 2: two beacon nodes take the same block off public gossip and their
    /// sidecars, seeing the same live set, assign every chunk the same way. The second copy of
    /// an index is a duplicate the region has already been offered, and the bitmap in the
    /// reassembler entry is what says so; a side table keyed by anything else would have to be
    /// sized and expired on its own.
    #[tokio::test(flavor = "multi_thread")]
    async fn two_origins_with_same_assignment_cause_one_forward_per_chunk() {
        let block = topic("beacon_block");
        let mut cluster = Builder::new(&[
            NodeKind::Bare,
            NodeKind::Bare,
            NodeKind::Manager,
            NodeKind::Manager,
        ])
        .start()
        .await;
        for node in [2, 3] {
            cluster.start_sidecar(node, subscriptions(&[&block], &[]));
        }
        eventually("the two sidecars to pair and subscribe", || {
            cluster.live(2).subscribers(&block).len() == 1
        })
        .await;
        let announced = vec![(TopicId::new(3), block.to_string())];
        let first = cluster
            .dial_announcing(0, 2, &cluster.self_hello(0), announced.clone())
            .await;
        let second = cluster
            .dial_announcing(1, 2, &cluster.self_hello(1), announced)
            .await;
        let forwarder = cluster.hostname(2);
        let same = MessageId([8; 20]);

        send(&first, &[chunk_frame(same, 3, ChunkFlags::NONE)]).await;
        eventually("the first copy to be forwarded", || {
            !cluster.stats(3).chunks_received(&forwarder).is_empty()
        })
        .await;
        send(&second, &[chunk_frame(same, 3, ChunkFlags::NONE)]).await;

        eventually("the second copy to arrive", || {
            cluster.stats(2).chunks_received(&cluster.hostname(1)).len() == 1
        })
        .await;
        tokio::time::sleep(SETTLE).await;
        assert_eq!(
            cluster.stats(3).chunks_received(&forwarder),
            vec![(ChunkFlags::FORWARDED, 3)]
        );
    }

    /// D19: forward only what this host does not already hold. A chunk of a message in the seen
    /// cache is late, because this host had the message from the beacon node or from another
    /// sidecar and its region has been offered it already; forwarding would replay the second
    /// hop for a message every neighbour has.
    #[tokio::test(flavor = "multi_thread")]
    async fn clear_chunk_for_a_message_in_the_seen_cache_is_not_forwarded() {
        let (cluster, peer, _) = striping_region(3).await;
        let held = MessageId([9; 20]);
        let forwarder = cluster.hostname(1);
        assert!(cluster.seen(1).insert(held));

        send(&peer, &[chunk_frame(held, 0, ChunkFlags::NONE)]).await;

        eventually("the host it was sent to to count it", || {
            cluster.stats(1).chunks_received(&cluster.hostname(0)).len() == 1
        })
        .await;
        tokio::time::sleep(SETTLE).await;
        for node in [2, 3] {
            assert!(
                cluster.stats(node).chunks_received(&forwarder).is_empty(),
                "node {node}"
            );
        }
        assert_eq!(cluster.stats(1).duplicates(Class::Large), 1);
    }

    /// The other half of D19's rule. A message this host has put back together is one it holds
    /// as surely as one in the seen cache, and the completed set is what remembers that once the
    /// in-flight entry has gone. T-074's completion is what fills it in production.
    #[tokio::test(flavor = "multi_thread")]
    async fn clear_chunk_for_a_message_in_the_completed_set_is_not_forwarded() {
        let (cluster, peer, _) = striping_region(3).await;
        let done = MessageId([10; 20]);
        let forwarder = cluster.hostname(1);
        cluster.reassembler(1).complete(done);

        send(&peer, &[chunk_frame(done, 0, ChunkFlags::NONE)]).await;

        eventually("the host it was sent to to count it", || {
            cluster.stats(1).chunks_received(&cluster.hostname(0)).len() == 1
        })
        .await;
        tokio::time::sleep(SETTLE).await;
        for node in [2, 3] {
            assert!(
                cluster.stats(node).chunks_received(&forwarder).is_empty(),
                "node {node}"
            );
        }
    }

    /// D19's bound: the forwarded state is the entry's, so it is gone when the entry is, and
    /// nothing outside the reassembler had to be sized or expired for it. After the ttl the same
    /// clear chunk is one this host has no record of, and it is offered to the region again.
    #[tokio::test(flavor = "multi_thread")]
    async fn forwarded_state_dies_with_the_reassembler_entry() {
        let ttl = Duration::from_secs(4);
        let clock = FakeClock::new();
        let (cluster, peer, _) = striping_region_with(2, |builder| {
            builder
                .clock(Arc::new(clock.clone()))
                .reassembly(MAX_IN_FLIGHT, ttl)
        })
        .await;
        let forwarder = cluster.hostname(1);
        let again = MessageId([11; 20]);

        send(&peer, &[chunk_frame(again, 0, ChunkFlags::NONE)]).await;
        eventually("the first copy to be forwarded", || {
            cluster.stats(2).chunks_received(&forwarder).len() == 1
        })
        .await;
        assert_eq!(cluster.reassembler(1).in_flight(), 1);

        clock.advance(ttl + Duration::from_secs(1));
        send(&peer, &[chunk_frame(again, 0, ChunkFlags::NONE)]).await;

        eventually("the same chunk to be forwarded again", || {
            cluster.stats(2).chunks_received(&forwarder).len() == 2
        })
        .await;
        assert_eq!(
            cluster.reassembler(1).in_flight(),
            1,
            "the entry count is the only state that grew"
        );
    }

    /// DX-N3: a clear chunk asks this host to fan out to its whole region, so its bytes are
    /// charged to the peer that sent it. Over budget the chunk is still taken in for
    /// reassembly, because the payload is good and this host wants it; what the peer does not
    /// get is a region fanned out on its say-so.
    #[tokio::test(flavor = "multi_thread")]
    async fn chunk_over_the_fanout_budget_is_stored_but_not_forwarded_and_counted() {
        let (cluster, peer, _) = striping_region_with(2, |builder| {
            builder.budget(FanoutBudget::new(1, 1, Instant::now()))
        })
        .await;
        let sender = cluster.hostname(0);

        send(
            &peer,
            &[chunk_frame(MessageId([12; 20]), 0, ChunkFlags::NONE)],
        )
        .await;

        eventually("the chunk to be refused a second hop", || {
            cluster
                .stats(1)
                .fanout_suppressed(&sender, FanoutKind::Chunk)
                == 1
        })
        .await;
        tokio::time::sleep(SETTLE).await;
        assert!(
            cluster
                .stats(2)
                .chunks_received(&cluster.hostname(1))
                .is_empty(),
            "it was forwarded anyway"
        );
        assert_eq!(
            cluster.reassembler(1).in_flight(),
            1,
            "the chunk was refused rather than taken in"
        );
    }

    /// A gossipsub wire form of about `bytes` from a pattern snappy cannot shrink, so a test
    /// about how many chunks a message takes gets the number it asked for.
    fn incompressible(bytes: usize) -> Vec<u8> {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let raw: Vec<u8> = (0..bytes)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect();
        snap::raw::Encoder::new().compress_vec(&raw).unwrap()
    }

    /// A cluster of `hosts` sidecars, one per region name, every one subscribed to blocks and
    /// striping any region with two subscribers in it.
    async fn striping_cluster(regions: &[&str], block: &Topic) -> TestCluster {
        let hosts = regions.len();
        let mut cluster = Builder::new(&vec![NodeKind::Manager; hosts])
            .regions(regions)
            .fanout(config::Fanout {
                large: config::LargeFanout {
                    stripe_min_recipients: 2,
                    ..config::LargeFanout::default()
                },
                ..config::Fanout::default()
            })
            .start()
            .await;
        for node in 0..hosts {
            cluster.start_sidecar(node, subscriptions(&[block], &[]));
        }
        eventually("every host to say it wants blocks", || {
            (0..hosts).all(|node| cluster.live(node).subscribers(block).len() == hosts - 1)
        })
        .await;
        cluster
    }

    /// Every index a host has been sent, whoever sent it, in ascending order.
    fn indices(cluster: &TestCluster, node: usize, hosts: usize) -> Vec<u16> {
        let mut seen: Vec<u16> = (0..hosts)
            .flat_map(|peer| cluster.stats(node).chunks_received(&cluster.hostname(peer)))
            .map(|(_, index)| index)
            .collect();
        seen.sort_unstable();
        seen
    }

    /// §5.4 end to end: the origin sends each host a share of the chunks and each host hands
    /// what it was sent to the rest of the region, so every host ends up with the message having
    /// read one message-worth of bytes off the origin between them. No index arrives twice,
    /// which is the second hop not doubling up.
    ///
    /// A host is not sent every index. It stops passing chunks on the moment it holds the
    /// message (D19), so the tail of its own share never makes the rounds, and the last few
    /// indices exist only on the hosts the origin sent them to. That is the point: the region
    /// stops spending bandwidth once it has what it was after.
    #[tokio::test(flavor = "multi_thread")]
    async fn every_host_in_region_ends_up_with_the_message_and_no_index_twice() {
        let block = topic("beacon_block");
        let payload = incompressible(20 * 1024);
        let hosts = 6;
        let cluster = striping_cluster(&vec!["eu"; hosts], &block).await;

        assert!(cluster.from_bn(0, &block, &payload));

        for node in 1..hosts {
            eventually("the host to put the message together", || {
                cluster.published(node).len() == 1
            })
            .await;
        }
        tokio::time::sleep(SETTLE).await;
        for node in 1..hosts {
            assert_eq!(cluster.published(node)[0].payload, payload, "node {node}");
            let held = indices(&cluster, node, hosts);
            let mut once = held.clone();
            once.dedup();
            assert_eq!(held, once, "node {node} was sent an index twice");
        }
        assert!(
            cluster.published(0).is_empty(),
            "the origin published to itself"
        );
    }

    /// §5.4: the origin builds one stripe per region and each region's second hop stays inside
    /// it, so the WAN carries one message-worth of chunks and nothing comes back the other way.
    #[tokio::test(flavor = "multi_thread")]
    async fn cross_region_stripe_second_hop_stays_in_remote_region() {
        let block = topic("beacon_block");
        let payload = incompressible(20 * 1024);
        let cluster =
            striping_cluster(&["eu", "eu", "eu", "eu", "us", "us", "us", "us"], &block).await;

        assert!(cluster.from_bn(0, &block, &payload));

        for node in 1..8 {
            eventually("every host in both regions to hold the message", || {
                cluster.published(node).len() == 1
            })
            .await;
        }
        tokio::time::sleep(SETTLE).await;
        for home in 0..4 {
            for remote in 4..8 {
                assert!(
                    cluster
                        .stats(home)
                        .chunks_received(&cluster.hostname(remote))
                        .is_empty(),
                    "node {remote} forwarded across the WAN to node {home}"
                );
                assert_eq!(
                    cluster
                        .stats(remote)
                        .bytes(Direction::Out, &cluster.hostname(home)),
                    0,
                    "node {remote} sent node {home} something"
                );
            }
        }
    }

    /// D18: the stripe runs over the region's subscribers and the second hop offers a chunk to
    /// the same set, so a host whose beacon node does not want blocks is sent none. A chunk it
    /// took would be a chunk that bought nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn unsubscribed_host_receives_no_chunks() {
        let block = topic("beacon_block");
        let subnet = topic("beacon_attestation_7");
        let payload = incompressible(20 * 1024);
        let hosts = 4;
        let mut cluster = Builder::new(&vec![NodeKind::Manager; hosts])
            .fanout(config::Fanout {
                large: config::LargeFanout {
                    stripe_min_recipients: 2,
                    ..config::LargeFanout::default()
                },
                ..config::Fanout::default()
            })
            .start()
            .await;
        for node in 0..hosts - 1 {
            cluster.start_sidecar(node, subscriptions(&[&block], &[]));
        }
        cluster.start_sidecar(hosts - 1, subscriptions(&[&subnet], &[]));
        eventually("the region to say what each host wants", || {
            cluster.live(0).subscribers(&block).len() == hosts - 2
        })
        .await;
        assert!(cluster.from_bn(0, &block, &payload));

        for node in 1..hosts - 1 {
            eventually("the subscribers to hold the message", || {
                cluster.published(node).len() == 1
            })
            .await;
        }
        tokio::time::sleep(SETTLE).await;
        assert!(
            indices(&cluster, hosts - 1, hosts).is_empty(),
            "a host that wants no blocks was sent chunks"
        );
    }

    /// D12's residual race, from the receiving end: an id travels on the control stream and a
    /// chunk naming it on a stream of its own, so a chunk can arrive first. It costs that chunk
    /// and nothing else, and the connection carries on with the next one.
    #[tokio::test(flavor = "multi_thread")]
    async fn chunk_under_an_unannounced_topic_id_is_counted_and_dropped() {
        let (cluster, peer, _) = striping_region(2).await;
        let sender = cluster.hostname(0);
        let mut unannounced = chunk_frame(MessageId([13; 20]), 0, ChunkFlags::NONE);
        // The same chunk under an id this peer never put in its HELLO or a `TOPIC_ADD`.
        unannounced = encode_datagram(&Frame::Chunk {
            flags: ChunkFlags::NONE,
            chunk: Chunk {
                topic_id: 31,
                ..match wire::decode_datagram(unannounced) {
                    Ok(Frame::Chunk { chunk, .. }) => chunk,
                    other => panic!("a chunk frame, not {other:?}"),
                }
            },
        });

        send(
            &peer,
            &[
                unannounced,
                chunk_frame(MessageId([14; 20]), 1, ChunkFlags::NONE),
            ],
        )
        .await;

        eventually("the readable chunk to be forwarded", || {
            !cluster
                .stats(2)
                .chunks_received(&cluster.hostname(1))
                .is_empty()
        })
        .await;
        tokio::time::sleep(SETTLE).await;
        assert_eq!(cluster.stats(1).unknown_topic_ids(&sender), 1);
        assert_eq!(
            cluster.stats(2).chunks_received(&cluster.hostname(1)),
            vec![(ChunkFlags::FORWARDED, 1)],
            "the chunk under the unknown id was forwarded"
        );
    }

    /// §12: `messages_total` counts messages and a chunk is a piece of one, so a striped block
    /// must not read as a hundred messages on the panel the rate is watched on, or as a hundred
    /// against the publish limits `docs/symptoms.md` has an operator compare it with. The bytes
    /// are still counted at both ends, which is what the two ends agreeing on what crossed the
    /// connection rests on, and `chunks_received_total` is where the count of chunks lives.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_chunk_moves_the_byte_counter_and_not_the_message_counter() {
        let (cluster, peer, _) = striping_region(2).await;
        let (sender, forwarder) = (cluster.hostname(0), cluster.hostname(1));

        send(
            &peer,
            &[chunk_frame(MessageId([15; 20]), 0, ChunkFlags::NONE)],
        )
        .await;

        eventually(
            "the chunk to reach the host behind the one it landed on",
            || !cluster.stats(2).chunks_received(&forwarder).is_empty(),
        )
        .await;
        tokio::time::sleep(SETTLE).await;
        for (node, from) in [(1, &sender), (2, &forwarder)] {
            assert_eq!(
                cluster.stats(node).bytes(Direction::In, from),
                8,
                "node {node}"
            );
            assert_eq!(
                cluster.stats(node).messages(Direction::In, from),
                0,
                "node {node} counted a chunk as a message"
            );
        }
        assert_eq!(cluster.stats(1).bytes(Direction::Out, &forwarder), 0);
        assert_eq!(
            cluster.stats(1).bytes(Direction::Out, &cluster.hostname(2)),
            8,
            "the forward is what the sending end counts"
        );
    }

    /// The chunks a striped message arrives as, under the id its payload hashes to on `topic`,
    /// and the split they were cut with.
    fn striped(
        topic_id: u16,
        topic: &Topic,
        payload: &[u8],
        chunk_bytes: usize,
    ) -> (MessageId, Params, Vec<Bytes>) {
        let msg_id = msgid::compute(&topic.to_string(), payload, wire::MAX_PAYLOAD_BYTES).id;
        let params = Params::for_len(payload.len(), chunk_bytes, 0.25).expect("a split");
        let frames = overlay_core::rs::encode(payload, params)
            .into_iter()
            .enumerate()
            .map(|(index, data)| {
                encode_datagram(&Frame::Chunk {
                    flags: ChunkFlags::NONE,
                    chunk: Chunk {
                        msg_id,
                        topic_id,
                        k: params.k,
                        m: params.m,
                        index: index as u16,
                        total_len: params.total_len,
                        data,
                    },
                })
            })
            .collect();
        (msg_id, params, frames)
    }

    /// D08 site 3 of 3 and DX-N4: the message a host puts back together is remembered and then
    /// queued for its beacon node, in that order, so a copy that arrives while the queue is
    /// draining is dropped rather than published twice. Nothing on the way waits for the node:
    /// every step from the chunk to the queue is a synchronous call, which is what
    /// `PublishSink::enqueue` taking no future buys.
    #[tokio::test(flavor = "multi_thread")]
    async fn completion_inserts_into_the_seen_cache_then_enqueues_without_awaiting() {
        let block = topic("beacon_block");
        let payload = incompressible(4096);
        let (cluster, peer) = peer_of(subscriptions(&[&block], &[]), &[(0, &block)]).await;
        let (msg_id, params, frames) = striped(0, &block, &payload, 512);

        send(&peer, &frames[..usize::from(params.k)]).await;

        eventually("the message to be queued for the beacon node", || {
            cluster.published(1).len() == 1
        })
        .await;
        let published = cluster.published(1);
        assert_eq!(published[0].id, msg_id);
        assert_eq!(published[0].payload, payload);
        assert_eq!(published[0].class, Class::Large);
        assert!(cluster.seen(1).contains(&msg_id));
        assert_eq!(
            cluster.held_when_published(1),
            vec![true],
            "the enqueue ran before the seen cache knew the id"
        );
    }

    /// The third of the recent store's insert sites (§5.6), and the gap T-081 left open.
    ///
    /// A large message that arrives whole rather than striped is one this host is holding and
    /// can answer for. Chunk repair would never ask such a host, because it sent nobody a chunk
    /// and is nobody's candidate (D23); column repair asks in-region live peers by round trip
    /// whatever they sent, so without this insert a host that took the whole message answers
    /// `not_found` for a column it has, and the requester spends an attempt finding that out.
    #[tokio::test(flavor = "multi_thread")]
    async fn whole_delivery_inserts_into_the_recent_store() {
        let block = topic("beacon_block");
        let payload = Bytes::from(incompressible(4096));
        let (cluster, peer) = peer_of(subscriptions(&[&block], &[]), &[(0, &block)]).await;
        let msg_id = msgid::compute(&block.to_string(), &payload, wire::MAX_PAYLOAD_BYTES).id;

        send(&peer, &[whole(0, &block, &payload)]).await;

        eventually("the message to be queued for the beacon node", || {
            cluster.published(1).len() == 1
        })
        .await;
        assert_eq!(
            cluster.recent(1).get(&msg_id),
            Some((block, payload)),
            "a whole delivery is held for repair like a reassembled one"
        );
    }

    /// The second of the recent store's two insert sites (§5.6): a message this host put back
    /// together is one that a peer which lost the same chunks can now repair from here. There is
    /// no announcement to go with it; the peer already knows this host holds the message,
    /// because it was this host that forwarded it a chunk of it (D23).
    #[tokio::test(flavor = "multi_thread")]
    async fn completed_reassembly_inserts_into_the_recent_store() {
        let block = topic("beacon_block");
        let payload = incompressible(4096);
        let (cluster, peer) = peer_of(subscriptions(&[&block], &[]), &[(0, &block)]).await;
        let (msg_id, params, frames) = striped(0, &block, &payload, 512);

        send(&peer, &frames[..usize::from(params.k)]).await;

        eventually("the message to be queued for the beacon node", || {
            cluster.published(1).len() == 1
        })
        .await;
        let (held_topic, held) = cluster
            .recent(1)
            .get(&msg_id)
            .expect("the reassembled block is held for repair");
        assert_eq!(held_topic, block);
        assert_eq!(held, payload);
    }

    /// §12's win rate and T-044's event log at the third insert site: a message this host put
    /// back together is one the overlay brought it before its beacon node had it, so it counts
    /// as a first arrival and is logged as one. Without this every block a striping fleet wins
    /// is missing from the numerator of `OverlayWinRateFalling` while the beacon node's own
    /// copies still count in the denominator, and the ratio reads "never wins" exactly when the
    /// overlay is working.
    ///
    /// The event names the origin that cut the message up rather than whoever sent the last
    /// chunk, and carries the first chunk's arrival, which is when this host heard of the
    /// message at all. That is what the fleet-spread query in `docs/rollout.md` compares
    /// across hosts.
    #[tokio::test(flavor = "multi_thread")]
    async fn completion_counts_a_first_arrival_and_logs_it_against_the_origin() {
        let mark = LOG.len();
        let block = topic("beacon_block");
        // A payload no other test sends, so its id picks this test's line out of the shared log.
        let payload = payload(b"a striped block only the reassembly test sends");
        let (cluster, peer) = peer_of(subscriptions(&[&block], &[]), &[(0, &block)]).await;
        let (msg_id, params, frames) = striped(0, &block, &payload, 64);

        send(&peer, &frames[..usize::from(params.k)]).await;

        eventually("the message to be queued for the beacon node", || {
            cluster.published(1).len() == 1
        })
        .await;
        assert_eq!(cluster.stats(1).first_seen(Class::Large), 1);
        let line = LOG
            .since(mark)
            .lines()
            .find(|line| line.contains(&msg_id.to_string()))
            .unwrap_or_default()
            .to_owned();
        assert!(line.contains(r#"event="first_arrival""#), "{line}");
        assert!(line.contains(r#"source="overlay""#), "{line}");
        assert!(line.contains(r#"class="large""#), "{line}");
        assert!(
            line.contains(&format!("origin_peer={}", cluster.hostname(0))),
            "{line}"
        );
        assert!(
            line.contains(&format!("node={}", cluster.hostname(1))),
            "{line}"
        );
    }

    /// DX-N1 at the third ingress site: a host reassembles a message for a topic its own beacon
    /// node never asked for, and publishes nothing. The chunks were still worth taking in, since
    /// the region was owed them.
    #[tokio::test(flavor = "multi_thread")]
    async fn completion_on_an_unadvertised_topic_is_dropped_counted_and_not_enqueued() {
        let block = topic("beacon_block");
        let column = topic("data_column_sidecar_37");
        let payload = incompressible(4096);
        let (cluster, peer) = peer_of(subscriptions(&[&block], &[&column]), &[(0, &column)]).await;
        let (_, params, frames) = striped(0, &column, &payload, 512);

        send(&peer, &frames[..usize::from(params.k)]).await;

        let sender = cluster.hostname(0);
        eventually("the message to be refused", || {
            cluster.stats(1).unwanted_topics(&sender) == 1
        })
        .await;
        tokio::time::sleep(SETTLE).await;
        assert!(cluster.published(1).is_empty());
        assert!(cluster.seen(1).is_empty());
    }

    /// D03 at completion: a message whose payload does not decompress is one no beacon node
    /// would take, so it is counted against the host the chunks came from and neither
    /// remembered nor published. The chunks that keep arriving afterwards are still late, which
    /// is what keeps a broken origin cheap.
    #[tokio::test(flavor = "multi_thread")]
    async fn reassembled_payload_that_does_not_decompress_is_counted_and_not_published() {
        let block = topic("beacon_block");
        let (cluster, peer) = peer_of(subscriptions(&[&block], &[]), &[(0, &block)]).await;
        let (_, params, frames) = striped(0, &block, b"not snappy at all, at any length", 64);

        send(&peer, &frames[..usize::from(params.k)]).await;

        let sender = cluster.hostname(0);
        eventually("the message to be refused", || {
            cluster.stats(1).invalid_payloads(&sender) == 1
        })
        .await;
        tokio::time::sleep(SETTLE).await;
        assert!(cluster.published(1).is_empty());
        assert!(cluster.seen(1).is_empty());
    }

    /// §12: a message put back together from chunks is timed from its first chunk, and one that
    /// needed a parity chunk says so, because that is the signal a host or a chunk was lost.
    #[tokio::test(flavor = "multi_thread")]
    async fn completion_times_the_reconstruction_and_reports_a_parity_chunk() {
        let block = topic("beacon_block");
        let payload = incompressible(4096);
        let clock = FakeClock::new();
        let (cluster, peer) = peer_of_clocked(
            subscriptions(&[&block], &[]),
            &[(0, &block)],
            Arc::new(clock.clone()),
        )
        .await;
        let (_, params, frames) = striped(0, &block, &payload, 512);
        let mut with_parity: Vec<Bytes> = frames[1..usize::from(params.k)].to_vec();
        with_parity.push(frames[usize::from(params.k)].clone());

        send(&peer, &with_parity[..1]).await;
        eventually("the first chunk to land", || {
            cluster.stats(1).chunks_received(&cluster.hostname(0)).len() == 1
        })
        .await;
        clock.advance(Duration::from_millis(40));
        send(&peer, &with_parity[1..]).await;

        eventually("the message to be queued", || {
            cluster.published(1).len() == 1
        })
        .await;
        assert_eq!(cluster.stats(1).parity_used(), 1);
        assert_eq!(
            cluster.stats(1).reconstructed(Class::Large),
            vec![Duration::from_millis(40)]
        );
    }

    /// A chunk is a piece of a message, so one chunk of a message that needs two is counted,
    /// offered to the region and held. Nothing reaches the beacon node until the rest arrive.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_chunk_of_a_message_still_missing_chunks_publishes_nothing() {
        let block = topic("beacon_block");
        let (cluster, peer) = peer_of(subscriptions(&[&block], &[]), &[(0, &block)]).await;
        let striped = encode_datagram(&Frame::Chunk {
            flags: ChunkFlags::NONE,
            chunk: Chunk {
                msg_id: MessageId([1; 20]),
                topic_id: 0,
                k: 2,
                m: 0,
                index: 0,
                total_len: 8,
                data: Bytes::from_static(b"half"),
            },
        });

        send(&peer, &[striped]).await;

        let sender = cluster.hostname(0);
        eventually("the chunk to be counted", || {
            cluster.stats(1).chunks_received(&sender).len() == 1
        })
        .await;
        tokio::time::sleep(SETTLE).await;
        assert_eq!(
            cluster.stats(1).chunks_received(&sender),
            vec![(ChunkFlags::NONE, 0)]
        );
        assert!(cluster.published(1).is_empty());
    }

    /// One line per connection, however many bad payloads a peer sends: a broken sibling must
    /// not be able to fill this host's log, and the next connection gets a fresh line because it
    /// may be a different fault (D03).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_peer_sending_invalid_payloads_is_warned_about_once() {
        let mark = LOG.len();
        let block = topic("beacon_block");
        let (cluster, peer) = peer_of(subscriptions(&[&block], &[]), &[(0, &block)]).await;
        let refused = whole(0, &block, b"not snappy at all");

        send(&peer, &[refused.clone(), refused.clone(), refused.clone()]).await;

        let sender = cluster.hostname(0);
        eventually("all three to be refused", || {
            cluster.stats(1).invalid_payloads(&sender) == 3
        })
        .await;
        let lines = LOG
            .since(mark)
            .lines()
            .filter(|line| line.contains(sender.0.as_str()) && line.contains("dropping a payload"))
            .count();
        assert_eq!(lines, 1);
    }

    /// The overlay's half of the win rate (§12): a message this host had not seen, arriving
    /// from a peer, is logged as an arrival naming that peer, so the query can tell an overlay
    /// win from the beacon node's own copy.
    #[tokio::test(flavor = "multi_thread")]
    async fn first_arrival_from_a_peer_names_the_peer_it_came_from() {
        let mark = LOG.len();
        let block = topic("beacon_block");
        // A payload no other test sends, so its id picks this test's line out of the shared log.
        let payload = payload(b"a block only the origin test sends");
        let (cluster, peer) = peer_of(subscriptions(&[&block], &[]), &[(0, &block)]).await;

        send(&peer, &[whole(0, &block, &payload)]).await;

        eventually("the block to be queued for the beacon node", || {
            cluster.published(1).len() == 1
        })
        .await;
        let id = msgid::compute(&block.to_string(), &payload, wire::MAX_PAYLOAD_BYTES).id;
        let line = LOG
            .since(mark)
            .lines()
            .find(|line| line.contains(&id.to_string()))
            .unwrap_or_default()
            .to_owned();
        assert!(line.contains(r#"event="first_arrival""#), "{line}");
        assert!(line.contains(r#"source="overlay""#), "{line}");
        assert!(
            line.contains(&format!("origin_peer={}", cluster.hostname(0))),
            "{line}"
        );
        assert!(
            line.contains(&format!("node={}", cluster.hostname(1))),
            "{line}"
        );
    }

    /// A peer that reconnects is a new connection, and a sender bound to the old one can only
    /// write into a connection that is gone (D15). The budget close is the one way v1 has to
    /// make a peer come back on a new connection.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_message_after_a_reconnect_goes_out_on_the_new_connection() {
        let block = topic("beacon_block");
        let before = payload(b"before the reconnect");
        let after = payload(b"after the reconnect");
        let mut cluster = TestCluster::start(2).await;
        for node in 0..2 {
            cluster.start_sidecar(node, subscriptions(&[&block], &[]));
        }
        let sender = cluster.hostname(0);
        eventually("the pair to pair", || {
            cluster.live(0).subscribers(&block).len() == 1 && cluster.receiver(1, &sender).is_some()
        })
        .await;
        assert!(cluster.from_bn(0, &block, &before));
        eventually("the first message", || cluster.published(1).len() == 1).await;

        let receiver = cluster.receiver(1, &sender).unwrap();
        let went_over = Instant::now();
        receiver.charge(FanoutKind::Chunk, 20 * 1024 * 1024, went_over);
        receiver.charge(
            FanoutKind::Chunk,
            20 * 1024 * 1024,
            went_over + SUSTAINED_VIOLATION + Duration::from_secs(1),
        );
        eventually("the connection to go", || cluster.live(0).is_empty()).await;
        eventually("the pair to pair again", || {
            cluster.live(0).subscribers(&block).len() == 1
        })
        .await;

        assert!(cluster.from_bn(0, &block, &after));

        eventually("the second message", || cluster.published(1).len() == 2).await;
    }

    /// The property the whole design rests on (§3 principle 1, §5.5). A sidecar publishes what
    /// the overlay brings it into its own beacon node and sends it nowhere: only what a beacon
    /// node hands its sidecar enters the overlay, which is what bounds duplicates to the number
    /// of beacon nodes that received a message from public gossip. Node C is reachable from B
    /// and not from A, and is subscribed to the topic, so a receiver that "helpfully" forwarded
    /// what it had just published would be caught here and nowhere else.
    #[tokio::test(flavor = "multi_thread")]
    async fn message_received_from_overlay_is_not_re_forwarded_to_the_overlay() {
        let block = topic("beacon_block");
        let payload = payload(b"a block from public gossip");
        let mut cluster = TestCluster::start(3).await;
        cluster.set_roster_for(0, &[0, 1]);
        for node in 0..3 {
            cluster.start_sidecar(node, subscriptions(&[&block], &[]));
        }
        eventually("the cut mesh to settle", || {
            cluster.live(0).subscribers(&block).len() == 1
                && cluster.live(1).subscribers(&block).len() == 2
        })
        .await;

        assert!(cluster.from_bn(0, &block, &payload));

        eventually("B to publish what A sent", || {
            cluster.published(1).len() == 1
        })
        .await;
        tokio::time::sleep(SETTLE).await;
        assert!(
            cluster.published(2).is_empty(),
            "C was published a message it could only have got by a second hop"
        );
        assert_eq!(
            cluster
                .stats(1)
                .messages(Direction::Out, &cluster.hostname(2)),
            0,
            "B sent C something after receiving from the overlay"
        );
    }

    /// A gossipsub payload of about `bytes` that snappy cannot shrink much, so a repair test
    /// works on a message that really was cut into several chunks.
    fn large_payload(bytes: usize) -> Vec<u8> {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let raw: Vec<u8> = (0..bytes)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                (state >> 33) as u8
            })
            .collect();
        payload(&raw)
    }

    /// Puts `body` in node 1's recent store under the id it hashes to on `topic`, which is what
    /// an arrival from its own beacon node or a message it reassembled would have done (§5.6).
    fn holding(cluster: &TestCluster, topic: &Topic, body: &[u8]) -> MessageId {
        let id = msgid::compute(&topic.to_string(), body, wire::MAX_PAYLOAD_BYTES).id;
        cluster.recent(1).insert(
            id,
            topic.clone(),
            Bytes::copy_from_slice(body),
            None,
            Instant::now(),
        );
        id
    }

    /// Returns once node 1 has told node 0 the id it names `topic` by, so a frame it answers
    /// with is one node 0 can resolve (MD-04).
    async fn told_about(cluster: &TestCluster, topic: &Topic) {
        let peer = cluster.hostname(0);
        eventually("node 1 to announce its id for the topic", || {
            let own = crate::hello::lock(cluster.topics(1));
            own.table
                .get(topic)
                .is_some_and(|id| own.announcer.told(&peer, id))
        })
        .await;
    }

    /// Asks node 1 for `missing` of `msg_id` on a stream of its own and reads back everything it
    /// answers, up to and including the `REPAIR_RESP` that ends the exchange.
    async fn ask(peer: &PeerInfo, msg_id: MessageId, missing: Vec<u16>) -> Vec<Frame> {
        ask_for(peer, RepairReq::Missing { msg_id, missing }).await
    }

    /// The same for a column named by identity, which is what a peer that never saw one sends.
    async fn ask_column(peer: &PeerInfo, block_root: [u8; 32], index: u8) -> Vec<Frame> {
        ask_for(peer, RepairReq::Column { block_root, index }).await
    }

    async fn ask_for(peer: &PeerInfo, request: RepairReq) -> Vec<Frame> {
        let (mut send, mut recv) = peer.connection.open_bi().await.unwrap();
        wire::write_frame(&mut send, &Frame::RepairReq(request))
            .await
            .unwrap();
        send.finish().unwrap();

        let mut answer = Vec::new();
        while let Ok(Ok(wire::Read::Frame(frame))) = tokio::time::timeout(
            WAIT,
            wire::read_frame(&mut recv, overlay_core::protocol::MAX_FRAME_BYTES),
        )
        .await
        {
            let last = matches!(frame, Frame::RepairResp(_));
            answer.push(frame);
            if last {
                break;
            }
        }
        answer
    }

    /// §5.6's other half: a host that holds a message answers a peer's request with the indices
    /// it asked for and nothing else. Each chunk travels as a `CHUNK` frame, because that is the
    /// only shape that carries `FORWARDED`, and the bit is what stops the requester passing them
    /// on to a region that has already been offered them (D11, D19). A `REPAIR_RESP` ends the
    /// exchange so the requester knows there is no more coming.
    #[tokio::test(flavor = "multi_thread")]
    async fn responder_returns_requested_indices_only_with_forwarded_set_and_a_trailer() {
        let block = topic("beacon_block");
        let (cluster, peer) = peer_of(subscriptions(&[&block], &[]), &[(1, &block)]).await;
        let body = large_payload(8 * 1024);
        let msg_id = holding(&cluster, &block, &body);
        told_about(&cluster, &block).await;

        let answer = ask(&peer, msg_id, vec![1, 3]).await;

        let split = Params::for_len(body.len(), 2048, 0.10).unwrap();
        let chunks = overlay_core::rs::encode(&body, split);
        let (indices, trailer) = answer.split_at(answer.len() - 1);
        assert_eq!(trailer, [Frame::RepairResp(RepairResp::Chunks(Vec::new()))]);
        let sent: Vec<(ChunkFlags, u16, Bytes)> = indices
            .iter()
            .map(|frame| match frame {
                Frame::Chunk { flags, chunk } => (*flags, chunk.index, chunk.data.clone()),
                other => panic!("{other:?} is not a chunk"),
            })
            .collect();
        assert_eq!(
            sent,
            vec![
                (ChunkFlags::FORWARDED, 1, chunks[1].clone()),
                (ChunkFlags::FORWARDED, 3, chunks[3].clone()),
            ]
        );
    }

    /// T-083's per-peer repair bound is a number `overlay-core` cannot see, so it is written
    /// down there and checked here: the four bidirectional streams a peer accepts, less the one
    /// HELLO's control stream holds for the life of the connection (T-025).
    #[test]
    fn repair_in_flight_per_peer_is_the_stream_budget_less_the_control_stream() {
        assert_eq!(
            overlay_core::repair::MAX_REPAIR_IN_FLIGHT_PER_PEER,
            MAX_REPAIR_STREAMS_PER_PEER - 1
        );
    }

    /// The arm T-082 left answering `not_found`. A peer that never saw a column has no message
    /// id for it, so it names the column and this host resolves it through the recent store's
    /// index (D23, T-081's hook). Every data chunk comes back, because a requester asking by
    /// identity holds none of them.
    #[tokio::test(flavor = "multi_thread")]
    async fn responder_answers_a_column_request_by_block_root_and_index() {
        let column = topic("data_column_sidecar_5");
        let (cluster, peer) = peer_of(subscriptions(&[&column], &[]), &[(1, &column)]).await;
        let body = large_payload(8 * 1024);
        let msg_id = holding(&cluster, &column, &body);
        cluster.recent(1).index_column([9; 32], 5, msg_id);
        told_about(&cluster, &column).await;

        let answer = ask_column(&peer, [9; 32], 5).await;

        let split = Params::for_len(body.len(), 2048, 0.10).unwrap();
        let sent: Vec<u16> = answer
            .iter()
            .filter_map(|frame| match frame {
                Frame::Chunk { chunk, .. } => Some(chunk.index),
                _ => None,
            })
            .collect();
        assert_eq!(sent, (0..split.k).collect::<Vec<u16>>());
        assert_eq!(
            answer.last(),
            Some(&Frame::RepairResp(RepairResp::Chunks(Vec::new())))
        );

        assert_eq!(
            ask_column(&peer, [8; 32], 5).await,
            [Frame::RepairResp(RepairResp::NotFound)],
            "a column this host does not hold is answered, not left hanging"
        );
    }

    /// A message this host never had, or one the recent store has already let go of, is answered
    /// rather than left unanswered: the requester moves on to its next candidate at once instead
    /// of spending an attempt's timeout on a host that cannot help (D24).
    #[tokio::test(flavor = "multi_thread")]
    async fn responder_replies_not_found_for_unknown_message() {
        let block = topic("beacon_block");
        let (cluster, peer) = peer_of(subscriptions(&[&block], &[]), &[(1, &block)]).await;
        told_about(&cluster, &block).await;

        let answer = ask(&peer, MessageId([4; 20]), vec![0, 1]).await;

        assert_eq!(answer, [Frame::RepairResp(RepairResp::NotFound)]);
    }

    /// The bound on what one request may cost this host (D24). Any `k` chunks put a message back
    /// together, so a peer asking for more than that is not repairing anything, and encoding the
    /// whole split for it would be work its own arithmetic never asked for.
    #[tokio::test(flavor = "multi_thread")]
    async fn responder_refuses_requests_above_k_indices() {
        let block = topic("beacon_block");
        let (cluster, peer) = peer_of(subscriptions(&[&block], &[]), &[(1, &block)]).await;
        let body = large_payload(8 * 1024);
        let msg_id = holding(&cluster, &block, &body);
        told_about(&cluster, &block).await;
        let split = Params::for_len(body.len(), 2048, 0.10).unwrap();

        let wanted: Vec<u16> = (0..split.k).collect();
        assert_eq!(
            ask(&peer, msg_id, wanted).await.len(),
            usize::from(split.k) + 1
        );

        let one_too_many: Vec<u16> = (0..=split.k).collect();

        assert_eq!(
            ask(&peer, msg_id, one_too_many).await,
            [Frame::RepairResp(RepairResp::NotFound)]
        );
    }

    /// D24's responder cap, which is DX-N3's `max_concurrent_bidi_streams` under another name.
    ///
    /// Two halves. A peer cannot have more streams of this kind open at once than the constant,
    /// because the connection was given that number and the control stream it opened during
    /// HELLO is one of them; that is the bound the responder is held to and the reason its own
    /// guard is a second line rather than the first. And every stream inside the bound is served
    /// by a task of its own, so the peers that opened a stream and said nothing hold up neither
    /// each other nor the one that did ask.
    #[tokio::test(flavor = "multi_thread")]
    async fn responder_caps_concurrent_repair_streams_per_peer_at_the_constant() {
        assert_eq!(
            MAX_REPAIR_STREAMS_PER_PEER,
            crate::endpoint::MAX_BIDI_STREAMS as usize
        );
        let block = topic("beacon_block");
        let (cluster, peer) = peer_of(subscriptions(&[&block], &[]), &[(1, &block)]).await;
        let body = large_payload(8 * 1024);
        let msg_id = holding(&cluster, &block, &body);
        told_about(&cluster, &block).await;

        // Every stream the peer is allowed beyond its control stream, opened and left silent.
        let mut held = Vec::new();
        while let Ok(Ok(stream)) = tokio::time::timeout(SETTLE, peer.connection.open_bi()).await {
            held.push(stream);
        }
        assert_eq!(held.len() + 1, MAX_REPAIR_STREAMS_PER_PEER);

        // The last of them still gets an answer while the others sit there saying nothing.
        let (mut send, mut recv) = held.pop().unwrap();
        wire::write_frame(
            &mut send,
            &Frame::RepairReq(RepairReq::Missing {
                msg_id,
                missing: vec![0],
            }),
        )
        .await
        .unwrap();
        send.finish().unwrap();

        let answered = tokio::time::timeout(WAIT, wire::read_frame(&mut recv, MAX_FRAME_BYTES))
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(&answered, Read::Frame(Frame::Chunk { chunk, .. }) if chunk.index == 0),
            "{answered:?}"
        );
    }
}
