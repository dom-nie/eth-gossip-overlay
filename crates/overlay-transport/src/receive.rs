//! What a peer sends this host, on its way into the beacon node.
//!
//! One task per live peer reads both carriers. It accepts unidirectional streams and reads the
//! frames off each, and it reads the peer's datagrams, which is where the small class arrives
//! (§5.3). A whole message is a `CHUNK` with `k = 1, m = 0`; any other chunk is a stripe, which
//! this release does not know how to put together and hands to [`Stripes`] (T-074). A `BATCH`
//! feeds each entry through the same path on either carrier, because an entry names its own
//! topic and an id this host cannot resolve costs that entry alone (D21).
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
//! The exception is a `BATCH` carrying `RELAY` from a peer in another region, which asks this
//! host to fan it out inside its own (D11, D20). That second hop is [`Relaying`], handed to the
//! receiver rather than reached for, and it is metered: the bytes are charged to the peer's
//! fan-out budget, and a peer that asks for more of it than its share closes (DX-N3). T-073's
//! cut-through forwarding gets the same treatment behind its own flag.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use bytes::Bytes;
use overlay_core::budget::{Charge, FanoutBudget, FanoutKind};
use overlay_core::events::{self, FirstArrival};
use overlay_core::msgid::{self, Branch, MessageId};
use overlay_core::protocol::MAX_FRAME_BYTES;
use overlay_core::pubqueue::{PublishItem, PublishSink};
use overlay_core::roster::{Hostname, Region, SelfIdentity};
use overlay_core::seen::SharedSeenCache;
use overlay_core::subs::PeerState;
use overlay_core::time::Clock;
use overlay_core::topic::table::TopicId;
use overlay_core::topic::{Class, SubscriptionSets, Topic};
use overlay_core::wire::{self, BatchEntry, BatchFlags, Chunk, ChunkFlags, Frame, Read};
use quinn::VarInt;
use tokio::io::AsyncRead;
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

use crate::batching::{BatchHandle, Small};
use crate::fanout::{Direction, PeerLabels, TrafficStats};
use crate::hello::OwnTopics;
use crate::manager::{CloseCode, LiveSource, ManagerStats, PeerInfo};
use crate::subs;

/// How long one frame may take to arrive once its stream has started (DX-N3). A peer that opens
/// a stream and stops writing holds a slot in the receive window until this fires; T-076 takes
/// the constant over when it tunes the transport.
pub const STREAM_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// What a stalled stream is stopped with. The peer learns nothing from the number, so it is the
/// unremarkable zero; the connection's own codes are [`CloseCode`](crate::manager::CloseCode).
const STALLED_STREAM_CODE: u32 = 0;

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

/// What to do with a chunk that is a piece of a message rather than a whole one. T-074 puts the
/// reassembler behind this without touching the dispatch above it.
pub trait Stripes: Send + Sync {
    /// One chunk of a striped message, with the flags its frame carried (`FORWARDED` is D19's).
    fn chunk(&self, peer: &Hostname, flags: ChunkFlags, chunk: Chunk);
}

/// v1's answer: a stripe is a form this release does not know how to read, so it is counted as
/// one and dropped (D10). Nothing sends stripes until T-073, and no v1 peer can be talked into
/// it, because `STRIPING` is a feature bit this release never advertises (D29).
pub struct NoStripes(Arc<dyn ReceiveStats>);

impl NoStripes {
    /// Counts what it drops on `stats`.
    pub fn new(stats: Arc<dyn ReceiveStats>) -> Self {
        Self(stats)
    }
}

impl Stripes for NoStripes {
    fn chunk(&self, peer: &Hostname, _: ChunkFlags, _: Chunk) {
        self.0.unknown_frame_type(peer);
    }
}

/// What every peer's receiver shares: the caches, the queue and the hooks that belong to the
/// host rather than to one connection.
#[derive(Clone)]
pub struct Deps {
    /// The seen cache all three insert sites share (D08).
    pub seen: SharedSeenCache,
    /// T-017's publish queue, behind the trait that keeps `overlay-transport` clear of libp2p.
    pub publish: Arc<dyn PublishSink>,
    /// What the mirror says the beacon node is subscribed to, which is the gate (DX-N1).
    pub sets: watch::Receiver<SubscriptionSets>,
    /// Where a chunk that is not a whole message goes.
    pub stripes: Arc<dyn Stripes>,
    /// Where every counter above lands.
    pub stats: Arc<dyn ReceiveStats>,
    /// Who this host is, which the event log names as the host that saw the message.
    pub node: Arc<SelfIdentity>,
    /// The clock the arrival time in that event is read from.
    pub clock: Arc<dyn Clock>,
    /// The budget each peer gets a copy of. A bucket that starts full is what a peer that
    /// connects an hour later would have anyway, since a refill saturates at the capacity.
    pub budget: FanoutBudget,
    /// What a `RELAY` batch is fanned out with.
    pub relaying: Relaying,
}

/// The second hop, as the receive path is handed it: what a relay needs to fan a `RELAY` batch
/// out inside its own region and nothing more (D20). Nothing else here can send, which is what
/// makes one hop structural for everything but this.
#[derive(Clone)]
pub struct Relaying {
    /// The live set, read once per batch for the in-region subscribers of each entry's topic.
    pub live: LiveSource,
    /// This host's own topic ids, which a re-fanned entry travels under: an entry is named by
    /// whoever sends it, and the relay is the sender of the second hop (D13).
    pub topics: Arc<Mutex<OwnTopics>>,
    /// The batcher the entries are re-coalesced through, so each in-region subscriber gets one
    /// batch holding only what it asked for (D21).
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
                if ctx.datagram(datagram) == After::Close {
                    close_rate_exceeded(&ctx.peer, FanoutKind::Relay, &connection);
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

/// Why a stream stopped being read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamEnd {
    /// It ended, or the peer sent something that did not decode.
    Ended,
    /// A frame did not arrive within [`STREAM_READ_TIMEOUT`].
    Timeout,
    /// The peer has been asking for more second-hop work than its budget covers for longer than
    /// the connection is given (DX-N3).
    RateExceeded,
}

/// Whether the connection a frame arrived on carries on. A `RELAY` batch from a peer that has
/// been over its fan-out budget for too long is the one thing on this path that ends it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum After {
    /// Keep reading.
    Carry,
    /// Close with [`CloseCode::RateExceeded`].
    Close,
}

/// One stream from the peer's first byte to whatever ends it, and the one place a stalled
/// stream is given up on.
async fn read_stream(mut stream: quinn::RecvStream, ctx: Arc<Ctx>, connection: quinn::Connection) {
    match read_frames(&mut stream, &ctx).await {
        StreamEnd::Timeout => {
            tracing::debug!(peer = %ctx.peer, "closing a stream that stalled mid-frame");
            let _ = stream.stop(VarInt::from_u32(STALLED_STREAM_CODE));
        }
        StreamEnd::RateExceeded => close_rate_exceeded(&ctx.peer, FanoutKind::Relay, &connection),
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
                if ctx.frame(frame) == After::Close {
                    return StreamEnd::RateExceeded;
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
            Frame::Chunk { flags, chunk } => {
                self.deps.stripes.chunk(&self.peer, flags, chunk);
                After::Carry
            }
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
        let charge = self.charge(FanoutKind::Relay, bytes, Instant::now());
        if charge != Charge::Allowed {
            self.deliver_all(entries, arrived);
            return match charge {
                Charge::CloseRateExceeded => After::Close,
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
    /// without a second check. A topic this host has no id of its own for is not re-fanned: an
    /// id its peers have never been told is unreadable on a frame, and minting one mid-flight is
    /// what D12 rules out.
    fn refan(&self, new: Vec<(Topic, Bytes)>) {
        if new.is_empty() {
            return;
        }
        let relaying = &self.deps.relaying;
        let view = relaying.live.live();
        let mut refanned = false;
        for (topic, payload) in new {
            let Some(topic_id) = crate::hello::lock(&relaying.topics).table.get(&topic) else {
                tracing::debug!(%topic, "no id of this host's own to re-fan an entry under");
                continue;
            };
            for (hostname, peer) in view.in_region(&self.deps.node.region) {
                let wanted = *hostname != self.deps.node.hostname
                    && subs::state(&peer.state).subscribed(&topic);
                let Some(max_bytes) = wanted
                    .then(|| crate::fanout::datagram_limit(&self.deps.node.hostname, peer))
                    .flatten()
                else {
                    continue;
                };
                let queued = relaying.batches.push(Small {
                    dest: hostname.clone(),
                    topic_id,
                    payload: payload.clone(),
                    max_bytes,
                    relay: false,
                    sender: peer.sender.clone(),
                });
                refanned |= queued.is_ok();
            }
        }
        if refanned {
            self.deps.stats.relayed_batch();
        }
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
        let computed = msgid::compute(&topic.to_string(), &payload, wire::MAX_PAYLOAD_BYTES);
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
            events::emit_first_arrival(&FirstArrival {
                id: computed.id,
                class,
                topic: &topic,
                node: &self.deps.node,
                at: arrived,
                source: events::Source::Overlay { origin: &self.peer },
            });
            self.deps.publish.enqueue(PublishItem {
                topic,
                id: computed.id,
                payload,
                class,
            });
        }
        owed
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
    use overlay_core::seen::SeenCache;
    use overlay_core::time::{FakeClock, SystemClock};
    use overlay_core::topic::UNKNOWN_LARGE_THRESHOLD_BYTES;
    use overlay_core::wire::{BatchEntry, BatchFlags, encode_datagram};
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
        peer_of_queueing(sets, announced, PUBLISHED_MAX).await
    }

    /// The same with a publish queue of `published_max` entries, for the one test about a beacon
    /// node that has stopped draining.
    async fn peer_of_queueing(
        sets: SubscriptionSets,
        announced: &[(u16, &Topic)],
        published_max: usize,
    ) -> (TestCluster, PeerInfo) {
        let mut cluster = Builder::new(&[NodeKind::Bare, NodeKind::Manager])
            .start()
            .await;
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
                publish: published.clone(),
                sets: watching,
                stripes: Arc::new(NoStripes::new(stats.clone())),
                stats,
                node: Arc::new(SelfIdentity {
                    hostname: Hostname("stalled-host".to_owned()),
                    region: Region("eu".to_owned()),
                    site: None,
                }),
                clock: Arc::new(SystemClock),
                budget: FanoutBudget::default_for(2, 2048, 12, Instant::now()),
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

    /// A chunk that is a piece of a message is a form this release cannot put together, so it is
    /// counted as a frame type it does not know and dropped (D10). T-074 puts the reassembler
    /// behind the same hook without touching the dispatch.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_striped_chunk_is_counted_and_dropped_until_the_reassembler_lands() {
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
            cluster.stats(1).unknown_frame_types(&sender) == 1
        })
        .await;
        tokio::time::sleep(SETTLE).await;
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
}
