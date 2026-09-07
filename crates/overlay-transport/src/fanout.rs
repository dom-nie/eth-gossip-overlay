//! What the beacon node hands this host, on its way to the peers that want it.
//!
//! The task drains T-016's lanes, asks the router where each message goes (T-031) and hands each
//! target what it can read.
//!
//! | Message | Carrier |
//! |---|---|
//! | small class, toward a peer that advertised `DATAGRAM_BATCHES` and takes datagrams | the batcher (T-061), then one `BATCH` datagram per window ([`crate::batching`]) |
//! | everything else | a `CHUNK` with `k = 1, m = 0` on a unidirectional stream of its own |
//!
//! The whole-message form is what every release can read, so it is both v1's only path and what
//! a v2 sender falls back to toward a peer that advertised neither `STRIPING` nor
//! `DATAGRAM_BATCHES` (D29), which is what makes the upgrade a rolling one. It also carries the
//! small-class payloads no `BATCH` can: an entry's length is a `u16` and small class is decided
//! by kind, so an `AttesterSlashing` runs past what a batch entry holds (D21).
//!
//! Only what the beacon node sent comes through here. A message that arrived from the overlay is
//! published locally and never sent on (§3 principle 1), which is what bounds duplicates to the
//! number of beacon nodes that got it from public gossip (§5.5). [`crate::receive`] holds no
//! handle to this task and has nothing to hand one.
//!
//! # Per-peer senders
//!
//! The loop awaits nothing but the lanes. Opening a stream and writing to it belong to a task per
//! peer, reached through the bounded queues in [`crate::sender`], so one slow sibling delays
//! nobody else (D17). The frame is encoded once here and every peer's queue holds the same
//! bytes, because what goes to one peer is what goes to all of them.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bytes::Bytes;
use overlay_core::config;
use overlay_core::fanout::Outbound;
use overlay_core::lanes::ClassLanes;
use overlay_core::progress::PROGRESS_TICK;
use overlay_core::protocol::features;
use overlay_core::roster::{Hostname, Region, SelfIdentity};
use overlay_core::topic::table::TopicId;
use overlay_core::topic::{Class, Topic};
use overlay_core::wire::{Frame, MAX_BATCH_ENTRY_BYTES, encode_stream};
use tokio::task::JoinHandle;

use crate::batching::{BatchHandle, Small};
use crate::hello::{OwnTopics, lock};
use crate::manager::{LivePeer, LiveSource};
use crate::router::{RoutePlan, route};

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

/// The task that turns what the beacon node sent into frames on the overlay.
pub struct Fanout {
    lanes: ClassLanes<Outbound>,
    live: LiveSource,
    self_id: SelfIdentity,
    cfg: config::Fanout,
    topics: Arc<Mutex<OwnTopics>>,
    batches: BatchHandle,
    stats: Arc<dyn TrafficStats>,
    /// Peers already warned about a frame they would refuse. In v1 both ends run the same limit,
    /// so this is a guard rather than a path, and one line per peer per process is plenty.
    oversize_warned: HashSet<Hostname>,
}

impl Fanout {
    /// Starts draining `lanes`, which is what T-016's inbound task fills through
    /// [`ClassLanes::pusher`](overlay_core::lanes::ClassLanes::pusher). It runs until aborted,
    /// because the lanes hold their own senders and never close.
    ///
    /// `progress` is the watchdog counter this loop owns (OPS-N5): it goes up once per
    /// iteration, and the tick arm is what keeps it going up on a fleet with no traffic.
    #[expect(
        clippy::too_many_arguments,
        reason = "the fanout's wiring: where messages come from, where they go, who this host \
                  is, and one handle per consumer. Every parameter has its own type, so a call \
                  site cannot mix two up"
    )]
    pub fn spawn(
        lanes: ClassLanes<Outbound>,
        live: LiveSource,
        self_id: SelfIdentity,
        cfg: config::Fanout,
        topics: Arc<Mutex<OwnTopics>>,
        batches: BatchHandle,
        stats: Arc<dyn TrafficStats>,
        progress: Arc<AtomicU64>,
    ) -> JoinHandle<()> {
        let mut fanout = Self {
            lanes,
            live,
            self_id,
            cfg,
            topics,
            batches,
            stats,
            oversize_warned: HashSet::new(),
        };
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(PROGRESS_TICK);
            loop {
                progress.fetch_add(1, Ordering::Relaxed);
                tokio::select! {
                    outbound = fanout.lanes.recv() => fanout.send(outbound),
                    _ = tick.tick() => {}
                }
            }
        })
    }

    /// Routes one message and hands it to every target's sender. Nothing here waits: the live
    /// view is a snapshot, the route is a pure function over it, and a push into a peer's queue
    /// takes a lock and returns.
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
        let bytes = outbound.payload.len();
        // Encoded at most once, and only if some target is being sent a whole message: the
        // batched targets share nothing, because a batch belongs to the destination it was
        // collected for.
        let mut whole: Option<Bytes> = None;
        let now = Instant::now();
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
            let queued = match self.batch_bytes(outbound.class, bytes, live) {
                Some(max_bytes) => self.batches.push(Small {
                    dest: target.clone(),
                    topic_id,
                    payload: outbound.payload.clone(),
                    max_bytes,
                    sender: live.sender.clone(),
                }),
                None => {
                    let frame = whole.get_or_insert_with(|| {
                        encode_stream(&Frame::whole_message(
                            outbound.id,
                            topic_id.get(),
                            outbound.payload.clone(),
                        ))
                    });
                    live.sender.push(outbound.class, frame.clone(), now)
                }
            };
            if queued.is_err() {
                tracing::debug!(peer = %target, "peer has no sender to queue the message on");
                continue;
            }
            self.stats
                .message(Direction::Out, outbound.class, labels, bytes);
        }
    }

    /// The datagram a batch for `live` may fill, or nothing when this payload does not travel in
    /// one.
    ///
    /// Three things have to hold. The class has to be the small one, since only it is batched
    /// (§5.4). The peer has to have advertised `DATAGRAM_BATCHES`, or it is running a release
    /// that reads nothing but whole messages (D29). And the payload has to fit the `u16` length a
    /// `BATCH` entry carries, which a small-class `AttesterSlashing` need not: small class is by
    /// kind, and `wire`'s narrowing would stop a debug build and write a frame that decodes as
    /// something else in a release one (D21).
    fn batch_bytes(&self, class: Class, bytes: usize, live: &LivePeer) -> Option<usize> {
        (class == Class::Small
            && live.negotiated.allows(features::DATAGRAM_BATCHES)
            && bytes <= MAX_BATCH_ENTRY_BYTES)
            .then(|| self.datagram_limit(live))
            .flatten()
    }

    /// What a datagram to `live` currently holds, which moves with path MTU discovery, or
    /// nothing when the peer's transport takes no datagram at all and the whole-message path is
    /// the only one it has.
    fn datagram_limit(&self, live: &LivePeer) -> Option<usize> {
        // The one seam a test has into this number. `send_datagram` refuses a batch built
        // against a limit the path does not hold, and nothing a test can do to a loopback
        // connection makes quinn's own answer disagree with it (T-062 test 7).
        #[cfg(any(test, feature = "test-util"))]
        if let Some(forced) = crate::testutil::datagram_limit::forced(&self.self_id.hostname) {
            return Some(forced);
        }
        live.connection.max_datagram_size()
    }

    /// The id this host's peers know `topic` by. Never interns: an id nobody has been told about
    /// is useless on a frame, so a message on a topic that has not been announced waits for the
    /// announcement instead (D12).
    fn own_id(&self, topic: &Topic) -> Option<TopicId> {
        lock(&self.topics).table.get(topic)
    }
}

/// Whether a whole message of `payload_bytes` is within the frame limit the peer advertised in
/// its HELLO. A sender never exceeds the limits the peer named (D29), and the limit is on the
/// frame, so the header counts towards it.
fn fits(payload_bytes: usize, peer_max_frame_bytes: u32) -> bool {
    payload_bytes + WHOLE_MESSAGE_HEADER_BYTES <= peer_max_frame_bytes as usize
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use bytes::{Bytes, BytesMut};
    use overlay_core::msgid::MessageId;
    use overlay_core::subs::PeerState;

    use super::*;
    use crate::manager::LiveSource;
    use crate::sender::{LARGE_QUEUED_BYTES_MAX, LargeLedger, PeerSender};
    use crate::testutil::{
        Builder, NodeKind, REGION, SendSpy, TestCluster, WAIT, eventually, peer_state,
        subscriptions, topic, view, within,
    };

    /// The gossipsub wire form of an attestation nothing else in a test will produce, so ten of
    /// them are ten payloads to the seen cache rather than one repeated ten times.
    fn attestation(n: usize) -> Vec<u8> {
        snap::raw::Encoder::new()
            .compress_vec(format!("attestation {n}").as_bytes())
            .unwrap()
    }

    /// A gossipsub wire form of about `bytes`, from a pattern snappy cannot shrink, so a test
    /// that is about a size bound is asserting on the size it asked for.
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

    /// The label an alert and a dashboard are keyed on (§12), so the strings are pinned rather
    /// than derived.
    #[test]
    fn directions_are_the_metric_labels_they_are_counted_under() {
        assert_eq!(Direction::Out.as_str(), "out");
        assert_eq!(Direction::In.as_str(), "in");
    }

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

    /// §5.4: ten attestations for one destination inside one window leave as one datagram, and
    /// the destination publishes ten payloads. That is the whole point of batching, and the two
    /// halves of it are what an operator sees on either end: one frame on the wire, ten
    /// messages in the counters.
    ///
    /// The window is the test's rather than the shipped 10 ms, because what is being asserted is
    /// what one window does and not how much of one a loaded machine has to spare. T-051's burst
    /// scenario runs at the default.
    #[tokio::test(flavor = "multi_thread")]
    async fn ten_attestations_pushed_within_the_window_arrive_as_one_datagram_and_ten_publishes() {
        let subnet = topic("beacon_attestation_7");
        let mut cluster = Builder::new(&[NodeKind::Manager; 2])
            .small(config::SmallClass {
                batch_window: Duration::from_millis(200),
                ..config::SmallClass::default()
            })
            .start()
            .await;
        for node in 0..2 {
            cluster.start_sidecar(node, subscriptions(&[&subnet], &[]));
        }
        eventually("the sibling to say it wants the subnet", || {
            cluster.live(0).subscribers(&subnet).len() == 1
        })
        .await;

        for n in 0..10 {
            let payload = attestation(n);
            assert!(cluster.from_bn(0, &subnet, &payload));
        }

        eventually("all ten to be queued at the sibling", || {
            cluster.published(1).len() == 10
        })
        .await;
        assert_eq!(cluster.datagrams_received(1, &cluster.hostname(0)), 1);
    }

    /// A payload no datagram on this path holds still travels alone, on a stream, rather than
    /// being split: only the large class is chunked (D21). It arrives as the batch it is, of one
    /// entry.
    #[tokio::test(flavor = "multi_thread")]
    async fn payload_above_max_datagram_size_arrives_via_stream() {
        let subnet = topic("beacon_attestation_7");
        let big = incompressible(4096);
        let mut cluster = TestCluster::start(2).await;
        for node in 0..2 {
            cluster.start_sidecar(node, subscriptions(&[&subnet], &[]));
        }
        eventually("the sibling to say it wants the subnet", || {
            cluster.live(0).subscribers(&subnet).len() == 1
        })
        .await;

        assert!(cluster.from_bn(0, &subnet, &big));

        eventually("the sibling to queue it", || {
            cluster.published(1).len() == 1
        })
        .await;
        assert_eq!(cluster.published(1)[0].payload, big);
        assert_eq!(cluster.datagrams_received(1, &cluster.hostname(0)), 0);
    }

    /// The invariant the module is shaped around (§5.7): a message that goes to a hundred peers
    /// with one of them stalled is done for the other ninety-nine at once. The loop hands each
    /// peer's queue a frame and waits for none of them.
    #[tokio::test(flavor = "multi_thread")]
    async fn fanout_to_100_fake_peers_with_one_stalled_completes_in_under_100_ms() {
        let cluster = Builder::new(&[NodeKind::Bare, NodeKind::Bare])
            .start()
            .await;
        let connection = tokio::time::timeout(WAIT, cluster.connected_pair(0, 1))
            .await
            .expect("the pair to connect")
            .0;
        let block = topic("beacon_block");
        let peers: Vec<(Hostname, PeerState)> = (0..100)
            .map(|n| {
                (
                    Hostname(format!("bn-{n:03}")),
                    peer_state(&[(1, &block)], &[1]),
                )
            })
            .collect();
        let links: Vec<SendSpy> = (0..peers.len())
            .map(|n| {
                if n == 0 {
                    SendSpy::stalled()
                } else {
                    SendSpy::open()
                }
            })
            .collect();
        let deps = crate::sender::Deps {
            ledger: Arc::new(LargeLedger::new(LARGE_QUEUED_BYTES_MAX)),
            stats: Arc::new(()),
        };
        let mut live = view(&connection, peers);
        for ((hostname, peer), link) in live.0.iter_mut().zip(&links) {
            peer.sender = PeerSender::spawn(hostname.clone(), link.clone(), deps.clone());
        }
        let topics = Arc::new(Mutex::new(OwnTopics::default()));
        lock(&topics).table.intern(&block).expect("a fresh table");
        let lanes = ClassLanes::new(Arc::new(()));
        let pusher = lanes.pusher();
        let _fanout = Fanout::spawn(
            lanes,
            LiveSource::fixed(live),
            SelfIdentity {
                hostname: Hostname("bn-me".to_owned()),
                region: Region(REGION.to_owned()),
                site: None,
            },
            config::Fanout::default(),
            topics,
            crate::batching::Batching::spawn(
                tokio::sync::watch::channel(config::SmallClass::default()).1,
                Arc::new(()),
            )
            .0,
            Arc::new(()),
            Arc::default(),
        );

        pusher
            .push(
                Class::Large,
                Outbound {
                    topic: block.clone(),
                    class: Class::Large,
                    id: MessageId([7; 20]),
                    payload: Bytes::from(vec![0; 128 * 1024]),
                    received_at: Instant::now(),
                },
            )
            .expect("the fanout lane has room");

        within(
            Duration::from_millis(100),
            "every peer but the stalled one",
            || links[1..].iter().all(|link| link.sent().len() == 1),
        )
        .await;
        assert!(links[0].sent().is_empty());
    }
}
