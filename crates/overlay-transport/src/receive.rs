//! What a peer sends this host, on its way into the beacon node.
//!
//! One task per live peer accepts unidirectional streams and reads the frames off each. A whole
//! message is a `CHUNK` with `k = 1, m = 0`; any other chunk is a stripe, which v1 does not know
//! how to put together and hands to [`Stripes`] (T-074). A `BATCH` on a stream feeds each entry
//! through the same path, because an entry names its own topic and an id this host cannot
//! resolve costs that entry alone (D21).
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
//! The only awaits are accepting a stream and reading a frame. Publishing is a push into T-017's
//! bounded queue and returns whether or not anything is draining it (DX-N4), so a wedged beacon
//! node costs queue drops and never a stalled stream. Every read is bounded twice: by
//! [`MAX_FRAME_BYTES`] before a body is allocated, and by [`STREAM_READ_TIMEOUT`], after which
//! the stream is closed and the rest of the connection carries on.
//!
//! # One hop
//!
//! Nothing here can send. A message from the overlay is published locally and goes no further
//! (§3 principle 1); only what the beacon node hands this host enters the overlay, through
//! [`crate::fanout`], which this module holds nothing of. That is what keeps duplicates bounded
//! by the number of beacon nodes that received a message from public gossip (§5.5). Relays
//! (T-063) and cut-through forwarding (T-073) add their second hop behind their own flags.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use overlay_core::msgid::{self, Branch, MessageId};
use overlay_core::protocol::MAX_FRAME_BYTES;
use overlay_core::pubqueue::{PublishItem, PublishSink};
use overlay_core::roster::{Hostname, Region};
use overlay_core::seen::SharedSeenCache;
use overlay_core::subs::PeerState;
use overlay_core::topic::table::TopicId;
use overlay_core::topic::{Class, SubscriptionSets, Topic};
use overlay_core::wire::{self, Chunk, ChunkFlags, Frame, Read};
use quinn::VarInt;
use tokio::io::AsyncRead;
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

use crate::fanout::{Direction, PeerLabels, TrafficStats};
use crate::manager::{ManagerStats, PeerInfo};
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
}

impl ReceiveStats for () {
    fn unknown_topic_id(&self, _: &Hostname) {}
    fn unwanted_topic(&self, _: &Hostname) {}
    fn invalid_payload(&self, _: &Hostname) {}
    fn first_seen(&self, _: Class) {}
    fn duplicate(&self, _: Class) {}
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
}

/// One peer's receiver. Dropping it stops the task: everything it holds belongs to a connection,
/// and a connection that is gone has nothing left to read.
pub struct PeerReceiver {
    task: JoinHandle<()>,
}

impl PeerReceiver {
    /// Starts reading `peer`'s streams. One of these per live peer, started from
    /// [`PeerEvent::Up`](crate::manager::PeerEvent::Up) and dropped on its `Down`.
    pub fn spawn(peer: &PeerInfo, deps: Deps) -> Self {
        let connection = peer.connection.clone();
        let ctx = Arc::new(Ctx {
            peer: peer.hostname.clone(),
            region: peer.region.clone(),
            site: peer.site.clone(),
            state: peer.state.clone(),
            deps,
            warned_invalid: AtomicBool::new(false),
        });
        Self {
            task: tokio::spawn(accept(connection, ctx)),
        }
    }
}

impl Drop for PeerReceiver {
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
    deps: Deps,
    /// Whether this connection has already had its line about a payload that did not check out.
    /// A peer sending a stream of them costs one line, and a reconnect gets a fresh one.
    warned_invalid: AtomicBool,
}

/// Accepts this peer's streams, each read by a task of its own so one stalled stream holds up
/// nothing. Finished ones are reaped on the next accept; the peer may have at most
/// `max_concurrent_uni_streams` open at once (DX-N3), so the set is bounded by that.
async fn accept(connection: quinn::Connection, ctx: Arc<Ctx>) {
    let mut streams = JoinSet::new();
    loop {
        match connection.accept_uni().await {
            Ok(stream) => {
                streams.spawn(read_stream(stream, ctx.clone()));
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
}

async fn read_stream(mut stream: quinn::RecvStream, ctx: Arc<Ctx>) {
    if read_frames(&mut stream, &ctx).await == StreamEnd::Timeout {
        tracing::debug!(peer = %ctx.peer, "closing a stream that stalled mid-frame");
        let _ = stream.stop(VarInt::from_u32(STALLED_STREAM_CODE));
    }
}

/// Reads frames until the stream ends or stalls. An unknown frame type is skipped and reading
/// continues, which is what lets a peer one release ahead send frames this one has never heard
/// of (D10).
async fn read_frames<R: AsyncRead + Unpin>(stream: &mut R, ctx: &Ctx) -> StreamEnd {
    loop {
        let read = tokio::time::timeout(
            STREAM_READ_TIMEOUT,
            wire::read_frame(stream, MAX_FRAME_BYTES),
        )
        .await;
        match read {
            Err(_) => return StreamEnd::Timeout,
            Ok(Ok(Read::Frame(frame))) => ctx.frame(frame),
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
    /// Sends one frame down the path its carrier and shape call for.
    fn frame(&self, frame: Frame) {
        todo!("T-032: dispatch the frame and deliver its payloads")
    }

    /// One payload, from a whole message or from a batch entry. `header_id` is the id the frame
    /// claimed for it, which only a chunk header carries.
    fn deliver(&self, topic_id: u16, payload: Bytes, header_id: Option<MessageId>) {
        todo!("T-032: resolve, gate, check, deduplicate and queue for publish")
    }

    /// The topic the peer means by `id`, read against the peer's own table and nobody else's
    /// (D13). The lock is held for the lookup and the clone, never across the hashing below.
    fn topic(&self, id: u16) -> Option<Topic> {
        subs::state(&self.state).table.resolve(TopicId::new(id)).cloned()
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
    use crate::testutil::{SETTLE, TestCluster, eventually, subscriptions, topic};

    /// The gossipsub wire form of `data`: snappy-compressed, which is what a payload has to be
    /// for its id to come out of the valid branch (D03).
    fn payload(data: &[u8]) -> Vec<u8> {
        snap::raw::Encoder::new().compress_vec(data).unwrap()
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
            cluster.stats(1).messages(Direction::Out, &cluster.hostname(2)),
            0,
            "B sent C something after receiving from the overlay"
        );
    }
}
