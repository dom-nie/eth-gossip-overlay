//! What the beacon node hands this host, on its way to the peers that want it.
//!
//! The task drains T-016's lanes, asks the router where each message goes (T-031) and writes one
//! whole-message frame per target: a `CHUNK` with `k = 1, m = 0` on a unidirectional stream of
//! its own. `BATCH` cannot carry one, because its entries have a `u16` length that a block does
//! not fit in (D21), and the same whole-message form is what a v2 sender falls back to toward a
//! peer that advertised neither `STRIPING` nor `DATAGRAM_BATCHES` (D29), so this path stays for
//! every release.
//!
//! Only what the beacon node sent comes through here. A message that arrived from the overlay is
//! published locally and never sent on (§3 principle 1), which is what bounds duplicates to the
//! number of beacon nodes that got it from public gossip (§5.5). [`crate::receive`] holds no
//! handle to this task and has nothing to hand one.
//!
//! # Per-peer senders
//!
//! The loop awaits nothing but the lanes. Opening a stream and writing to it belong to a task per
//! peer, reached with `try_send`, so one slow sibling delays nobody else (D17). The plain channel
//! here is a placeholder: T-033 replaces it with the bounded, byte-and-age-aware lanes and the
//! drop policy it owns.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use overlay_core::config;
use overlay_core::fanout::Outbound;
use overlay_core::lanes::ClassLanes;
use overlay_core::roster::{Hostname, Region, SelfIdentity};
use overlay_core::topic::Class;
use overlay_core::topic::table::TopicId;
use overlay_core::wire::{Frame, write_frame};
use tokio::sync::mpsc;
use tokio::task::{AbortHandle, JoinHandle, JoinSet};

use crate::hello::{OwnTopics, lock};
use crate::manager::{LivePeer, LiveSource};
use crate::router::{RoutePlan, route};

/// Frames one peer's sender holds before the next is dropped. A placeholder for T-033, which
/// bounds the lane by bytes and age instead and counts what it drops.
const PEER_LANE_FRAMES: usize = 64;

/// What a whole message costs on the wire besides its payload: the `type` and `flags` bytes and
/// the chunk header (`msg_id`, `topic_id`, `k`, `m`, `index`, `total_len`, data length). The
/// stream's own `u32` length prefix is not part of it, because the limit HELLO names is what
/// that prefix may say (T-024). `whole_message_header_is_what_the_codec_writes` holds it to the
/// codec.
const WHOLE_MESSAGE_HEADER_BYTES: usize = 38;

/// Which way a message crossed the overlay, the `direction` label of `messages_total` and
/// `bytes_total` (§12).
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub enum Direction {
    /// This host sent it to a peer.
    Out,
    /// A peer sent it to this host.
    In,
}

impl Direction {
    /// The label value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Out => "out",
            Self::In => "in",
        }
    }
}

/// The `{peer, region, site}` labels the traffic counters carry, borrowed from the live view or
/// the receiver's own peer so counting a message allocates nothing.
#[derive(Clone, Copy, Debug)]
pub struct PeerLabels<'a> {
    /// The peer at the other end.
    pub hostname: &'a Hostname,
    /// The region it declared.
    pub region: &'a Region,
    /// Its site label, when it has one.
    pub site: Option<&'a str>,
}

/// Traffic accounting for both directions, which both ends of the overlay count the same way:
/// one message and its payload bytes. T-041 binds it to `messages_total{direction, class, peer,
/// region, site}` and `bytes_total{..}`. `()` counts nothing.
pub trait TrafficStats: Send + Sync {
    /// One message of `class` and `bytes` payload crossed the overlay in `direction`.
    fn message(&self, direction: Direction, class: Class, peer: PeerLabels<'_>, bytes: usize);
}

impl TrafficStats for () {
    fn message(&self, _: Direction, _: Class, _: PeerLabels<'_>, _: usize) {}
}

/// One peer's sender: the channel the fanout loop pushes into and the task draining it.
struct PeerSender {
    frames: mpsc::Sender<Frame>,
    /// The connection the task writes on. A peer that reconnects or is superseded (D15) gets a
    /// new one, and the sender built for the old connection is of no use on it.
    connection: usize,
    task: AbortHandle,
}

/// The task that turns what the beacon node sent into frames on the overlay.
pub struct Fanout {
    lanes: ClassLanes<Outbound>,
    live: LiveSource,
    self_id: SelfIdentity,
    cfg: config::Fanout,
    topics: Arc<Mutex<OwnTopics>>,
    stats: Arc<dyn TrafficStats>,
    senders: HashMap<Hostname, PeerSender>,
    tasks: JoinSet<()>,
    /// Peers already warned about a frame they would refuse. In v1 both ends run the same limit,
    /// so this is a guard rather than a path, and one line per peer per process is plenty.
    oversize_warned: HashSet<Hostname>,
}

impl Fanout {
    /// Starts draining `lanes`, which is what T-016's inbound task fills through
    /// [`ClassLanes::pusher`](overlay_core::lanes::ClassLanes::pusher). It runs until aborted,
    /// because the lanes hold their own senders and never close.
    pub fn spawn(
        lanes: ClassLanes<Outbound>,
        live: LiveSource,
        self_id: SelfIdentity,
        cfg: config::Fanout,
        topics: Arc<Mutex<OwnTopics>>,
        stats: Arc<dyn TrafficStats>,
    ) -> JoinHandle<()> {
        let mut fanout = Self {
            lanes,
            live,
            self_id,
            cfg,
            topics,
            stats,
            senders: HashMap::new(),
            tasks: JoinSet::new(),
            oversize_warned: HashSet::new(),
        };
        tokio::spawn(async move {
            loop {
                let outbound = fanout.lanes.recv().await;
                fanout.send(outbound);
            }
        })
    }

    /// Routes one message and hands it to every target's sender. Nothing here waits: the live
    /// view is a snapshot, the route is a pure function over it, and the frame goes out with
    /// `try_send`.
    fn send(&mut self, outbound: Outbound) {
        todo!("T-032: route the message and write one whole-message frame per target")
    }

    /// The id this host's peers know `topic` by. Never interns: an id nobody has been told about
    /// is useless on a frame, so a message on a topic that has not been announced waits for the
    /// announcement instead (D12).
    fn own_id(&self, topic: &overlay_core::topic::Topic) -> Option<TopicId> {
        lock(&self.topics).table.get(topic)
    }

    /// The channel for `peer`, started on first use and again whenever the connection under it
    /// is replaced. A peer that goes away leaves its entry behind until it comes back, which
    /// costs a closed channel per roster host at worst.
    fn sender(&mut self, peer: &Hostname, live: &LivePeer) -> mpsc::Sender<Frame> {
        let Self {
            senders, tasks, ..
        } = self;
        let connection = live.connection.stable_id();
        if let Some(held) = senders.get(peer)
            && held.connection == connection
        {
            return held.frames.clone();
        }
        let (frames, queued) = mpsc::channel(PEER_LANE_FRAMES);
        let task = tasks.spawn(write_frames(
            queued,
            live.connection.clone(),
            peer.clone(),
        ));
        let sender = PeerSender {
            frames: frames.clone(),
            connection,
            task,
        };
        if let Some(replaced) = senders.insert(peer.clone(), sender) {
            replaced.task.abort();
        }
        frames
    }
}

/// One peer's writer: a stream per frame, which is what a whole message travels on (§7).
async fn write_frames(
    mut frames: mpsc::Receiver<Frame>,
    connection: quinn::Connection,
    peer: Hostname,
) {
    while let Some(frame) = frames.recv().await {
        let stream = match connection.open_uni().await {
            Ok(stream) => stream,
            Err(error) => {
                tracing::debug!(%peer, %error, "connection gone: nothing more to send on it");
                return;
            }
        };
        let mut stream = stream;
        if let Err(error) = write_frame(&mut stream, &frame).await {
            tracing::debug!(%peer, %error, "stream stopped taking the frame");
            return;
        }
        let _ = stream.finish();
    }
}
