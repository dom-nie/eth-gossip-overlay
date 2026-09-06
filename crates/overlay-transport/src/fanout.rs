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
        let view = self.live.live();
        let RoutePlan::Direct(targets) = route(
            &outbound.topic,
            outbound.class,
            &view,
            &self.self_id,
            &self.cfg,
        ) else {
            return;
        };
        let Some(topic_id) = self.own_id(&outbound.topic) else {
            tracing::debug!(
                topic = %outbound.topic,
                "no id for this topic yet, so no peer could read a frame carrying it"
            );
            return;
        };
        let frame = Frame::whole_message(outbound.id, topic_id.get(), outbound.payload.clone());
        let bytes = outbound.payload.len();
        for target in targets {
            // A peer can leave the live set between the plan and the send, and the send is what
            // finds out (§5.3).
            let Some(live) = view.get(&target) else {
                continue;
            };
            let allowed = live.negotiated.peer_max_frame_bytes;
            if !fits(bytes, allowed) {
                // Both ends of a v1 pair advertise the same limit, so this is a guard against a
                // peer that advertised a smaller one rather than a path anything travels (D29).
                if self.oversize_warned.insert(target.clone()) {
                    tracing::warn!(peer = %target, bytes, allowed, "message is larger than the peer accepts");
                }
                continue;
            }
            let labels = PeerLabels {
                hostname: &target,
                region: &live.region,
                site: live.site.as_deref(),
            };
            if self.sender(&target, live).try_send(frame.clone()).is_err() {
                tracing::debug!(peer = %target, "peer sender full or gone: message dropped");
                continue;
            }
            self.stats
                .message(Direction::Out, outbound.class, labels, bytes);
        }
        while self.tasks.try_join_next().is_some() {}
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
        let Self { senders, tasks, .. } = self;
        let connection = live.connection.stable_id();
        if let Some(held) = senders.get(peer)
            && held.connection == connection
        {
            return held.frames.clone();
        }
        let (frames, queued) = mpsc::channel(PEER_LANE_FRAMES);
        let task = tasks.spawn(write_frames(queued, live.connection.clone(), peer.clone()));
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

/// Whether a whole message of `payload_bytes` is within the frame limit the peer advertised in
/// its HELLO. A sender never exceeds the limits the peer named (D29), and the limit is on the
/// frame, so the header counts towards it.
fn fits(payload_bytes: usize, peer_max_frame_bytes: u32) -> bool {
    payload_bytes + WHOLE_MESSAGE_HEADER_BYTES <= peer_max_frame_bytes as usize
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

#[cfg(test)]
mod tests {
    use bytes::{Bytes, BytesMut};
    use overlay_core::msgid::MessageId;

    use super::*;

    /// The allowance is arithmetic and the codec is what decides it, so a field added to a chunk
    /// header without a change here would let a frame past a peer's limit.
    #[test]
    fn whole_message_header_is_what_the_codec_writes() {
        let mut encoded = BytesMut::new();
        Frame::whole_message(MessageId([0; 20]), 0, Bytes::from_static(b"x")).encode(&mut encoded);

        assert_eq!(encoded.len(), WHOLE_MESSAGE_HEADER_BYTES + 1);
    }

    /// The limit is on the frame, so a payload that fills it to the byte still has to carry its
    /// header.
    #[test]
    fn a_payload_fits_only_with_room_for_its_header() {
        let limit = 1024;

        assert!(fits(limit as usize - WHOLE_MESSAGE_HEADER_BYTES, limit));
        assert!(!fits(
            limit as usize - WHOLE_MESSAGE_HEADER_BYTES + 1,
            limit
        ));
    }
}
