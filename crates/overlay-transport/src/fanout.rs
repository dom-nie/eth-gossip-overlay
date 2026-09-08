//! What the beacon node hands this host, on its way to the peers that want it.
//!
//! The task drains T-016's lanes, asks the router where each message goes (T-031) and hands each
//! target what it can read.
//!
//! | Message | Carrier |
//! |---|---|
//! | small class, toward a peer that advertised `DATAGRAM_BATCHES` and takes datagrams | the batcher (T-061), then one `BATCH` datagram per window ([`crate::batching`]), carrying `RELAY` when the peer is a relay for it |
//! | everything else | a `CHUNK` with `k = 1, m = 0` on a unidirectional stream of its own |
//!
//! The whole-message form is what every release can read, so it is both v1's only path and what
//! a v2 sender falls back to toward a peer that advertised neither `STRIPING` nor
//! `DATAGRAM_BATCHES` (D29), which is what makes the upgrade a rolling one. It also carries the
//! small-class payloads no `BATCH` can: an entry's length is a `u16` and small class is decided
//! by kind, so an `AttesterSlashing` runs past what a batch entry holds (D21).
//!
//! A small-class batch crossing to a region large enough to be worth the hop goes to a few of
//! that region's hosts with `RELAY` set, and each of them delivers it inside its own region
//! (D11, D20). The router decides which hosts and this loop marks the batches for them; the
//! second hop itself is [`crate::receive`]'s.
//!
//! Only what the beacon node sent comes through here. [`crate::receive`] holds no handle to this
//! task and has nothing to hand one, so what a host takes off the overlay is published locally
//! and goes no further except as that one relay hop (§3 principle 1), which is what bounds
//! duplicates to the number of beacon nodes that got a message from public gossip (§5.5).
//!
//! # Per-peer senders
//!
//! The loop awaits nothing but the lanes. Opening a stream and writing to it belong to a task per
//! peer, reached through the bounded queues in [`crate::sender`], so one slow sibling delays
//! nobody else (D17). The frame is encoded once here and every peer's queue holds the same
//! bytes, because what goes to one peer is what goes to all of them.

use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bytes::{Bytes, BytesMut};
use overlay_core::config;
use overlay_core::fanout::Outbound;
use overlay_core::lanes::ClassLanes;
use overlay_core::progress::PROGRESS_TICK;
use overlay_core::protocol::features;
use overlay_core::roster::{Hostname, Region, SelfIdentity};
use overlay_core::rs::{self, Params};
use overlay_core::topic::table::TopicId;
use overlay_core::topic::{Class, Topic};
use overlay_core::wire::{Chunk, ChunkFlags, Frame, MAX_BATCH_ENTRY_BYTES, encode_stream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::batching::{BatchHandle, Small};
use crate::hello::{OwnTopics, lock};
use crate::manager::{LivePeer, LiveSource};
use crate::router::{Chunked, RegionPlan, RoutePlan, route};

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

    /// `unannounced_topic_total`: a payload this host could not put on the wire, because it has
    /// no id of its own for the topic that its peers have been told (D12). Both senders count
    /// it here: a message from the beacon node on a topic the mirror has not caught up with,
    /// and an entry a relay will not intern for (MD-04). It should stay at zero; anything else
    /// means a table and the view that named the topic have disagreed.
    fn unannounced_topic(&self);

    /// `chunks_sent_total`: one chunk of a striped message written to a peer, from the origin's
    /// stripe or from the in-region hop that follows it (§12).
    fn chunk_sent(&self);
}

impl TrafficStats for () {
    fn message(&self, _: Direction, _: Class, _: PeerLabels<'_>, _: usize) {}
    fn unannounced_topic(&self) {}
    fn chunk_sent(&self) {}
}

/// The task that turns what the beacon node sent into frames on the overlay.
pub struct Fanout {
    lanes: ClassLanes<Outbound>,
    live: LiveSource,
    self_id: SelfIdentity,
    /// What the router routes under, re-read per message so a reload of the relay threshold or
    /// the relay count takes hold on the next one (T-043, D36).
    cfg: watch::Receiver<config::Fanout>,
    topics: Arc<Mutex<OwnTopics>>,
    batches: BatchHandle,
    stats: Arc<dyn TrafficStats>,
    /// How a large message is cut up. Both keys need a restart, so this is a value and not a
    /// `watch` like the fanout beside it (T-043).
    large: config::LargeClass,
    /// Peers already warned about a frame they would refuse. In v1 both ends run the same limit,
    /// so this is a guard rather than a path, and one line per peer per process is plenty.
    oversize_warned: HashSet<Hostname>,
    /// Whether the one line about a message this host cannot split has been logged.
    split_warned: bool,
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
        cfg: watch::Receiver<config::Fanout>,
        topics: Arc<Mutex<OwnTopics>>,
        batches: BatchHandle,
        stats: Arc<dyn TrafficStats>,
        large: config::LargeClass,
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
            large,
            oversize_warned: HashSet::new(),
            split_warned: false,
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
        let chunked = self.chunked(&outbound);
        let (targets, relays, striped) = match route(
            &outbound.topic,
            outbound.class,
            chunked,
            &view,
            &self.self_id,
            &self.cfg.borrow(),
        ) {
            RoutePlan::Direct(targets) => (targets, Vec::new(), BTreeMap::new()),
            RoutePlan::SmallRelayed { direct, relays } => (direct, relays, BTreeMap::new()),
            RoutePlan::Large(regions) => {
                let (whole, striped) = stripes(regions);
                (whole, Vec::new(), striped)
            }
            RoutePlan::Nothing => return,
        };
        let Some(topic_id) = self.own_id(&outbound.topic) else {
            tracing::debug!(
                topic = %outbound.topic,
                "no id for this topic yet, so no peer could read a frame carrying it"
            );
            self.stats.unannounced_topic();
            return;
        };
        let bytes = outbound.payload.len();
        // Encoded at most once, and only if some target is being sent a whole message: the
        // batched targets share nothing, because a batch belongs to the destination it was
        // collected for.
        let mut whole: Option<Bytes> = None;
        let now = Instant::now();
        // A relay is a target like any other; what it gets is the `RELAY` bit, which asks it to
        // fan the batch out inside its own region (D11).
        let targets = targets
            .into_iter()
            .map(|target| (target, false))
            .chain(relays.into_iter().map(|target| (target, true)));
        for (target, relay) in targets {
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
                    relay,
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
        if let Some(chunked) = chunked.filter(|_| !striped.is_empty()) {
            self.send_chunks(&outbound, topic_id, chunked.split, &striped, &view, now);
        }
    }

    /// How a large message is cut up, or nothing when it travels whole: every small-class
    /// message, and a large one no split covers.
    ///
    /// [`Params::for_len`] owns every limit the codec and the chunk header have (T-071), and a
    /// configuration this sidecar started with cannot break any of them: `chunk_bytes` is
    /// validated at load and a payload past the maximum never reaches the overlay. So a refusal
    /// here is something an operator should see rather than something to plan around, and the
    /// message goes out whole on the path v1 sent everything by rather than not at all.
    fn chunked(&mut self, outbound: &Outbound) -> Option<Chunked> {
        if outbound.class != Class::Large {
            return None;
        }
        match Params::for_len(
            outbound.payload.len(),
            self.large.chunk_bytes,
            self.large.parity_ratio,
        ) {
            Ok(split) => Some(Chunked {
                id: outbound.id,
                split,
            }),
            Err(error) => {
                if !std::mem::replace(&mut self.split_warned, true) {
                    tracing::warn!(
                        %error,
                        bytes = outbound.payload.len(),
                        chunk_bytes = self.large.chunk_bytes,
                        "cannot split large messages, sending them whole instead"
                    );
                }
                None
            }
        }
    }

    /// Writes each target the chunks the assignment gave it, all of them on one stream, with
    /// `FORWARDED` clear so the host that receives them hands them to the rest of its region
    /// (D11, D19). One stream per (message, target) is what keeps a 200 KB block at one stream
    /// per host rather than one per chunk (D19).
    ///
    /// The parity is computed once for the whole message and every target's frames borrow from
    /// that one buffer (T-071), so what this costs per target is the header bytes and the copy
    /// into its stream.
    fn send_chunks(
        &self,
        outbound: &Outbound,
        topic_id: TopicId,
        split: Params,
        striped: &BTreeMap<Hostname, Vec<u16>>,
        view: &crate::manager::LiveView,
        now: Instant,
    ) {
        let chunks = rs::encode(&outbound.payload, split);
        for (target, indices) in striped {
            // A peer can leave the live set between the plan and the send, and the send is what
            // finds out (§5.3).
            let Some(live) = view.get(target) else {
                continue;
            };
            let mut stream = BytesMut::new();
            for index in indices {
                let Some(data) = chunks.get(usize::from(*index)) else {
                    continue;
                };
                stream.extend_from_slice(&encode_stream(&Frame::Chunk {
                    flags: ChunkFlags::NONE,
                    chunk: Chunk {
                        msg_id: outbound.id,
                        topic_id: topic_id.get(),
                        k: split.k,
                        m: split.m,
                        index: *index,
                        total_len: split.total_len,
                        data: data.clone(),
                    },
                }));
            }
            if live
                .sender
                .push(Class::Large, stream.freeze(), now)
                .is_err()
            {
                tracing::debug!(peer = %target, "peer has no sender to queue its chunks on");
                continue;
            }
            let labels = PeerLabels {
                hostname: target,
                region: &live.region,
                site: live.site.as_deref(),
            };
            for _ in indices {
                self.stats.chunk_sent();
                self.stats
                    .message(Direction::Out, Class::Large, labels, split.chunk_bytes);
            }
        }
    }

    /// The datagram a batch for `live` may fill, or nothing when this payload does not travel in
    /// one.
    ///
    /// Three things have to hold. The class has to be the small one, since only it is batched
    /// (§5.4). The payload has to fit the `u16` length a `BATCH` entry carries, which a
    /// small-class `AttesterSlashing` need not: small class is by kind, and `wire`'s narrowing
    /// would stop a debug build and write a frame that decodes as something else in a release
    /// one (D21). And the peer has to take a batch datagram at all, which is
    /// [`datagram_limit`]'s question.
    fn batch_bytes(&self, class: Class, bytes: usize, live: &LivePeer) -> Option<usize> {
        (class == Class::Small && bytes <= MAX_BATCH_ENTRY_BYTES)
            .then(|| datagram_limit(&self.self_id.hostname, live))
            .flatten()
    }

    /// The id this host's peers know `topic` by. Never interns: an id nobody has been told about
    /// is useless on a frame, so a message on a topic that has not been announced waits for the
    /// announcement instead (D12).
    fn own_id(&self, topic: &Topic) -> Option<TopicId> {
        lock(&self.topics).table.get(topic)
    }
}

/// What a batch datagram to `live` may fill, which moves with path MTU discovery, or nothing
/// when the peer takes no such batch: it advertised no `DATAGRAM_BATCHES`, so it runs a release
/// that reads whole messages only (D29), or its transport carries no datagram at all. A relay's
/// re-fan asks the same question of its own region (T-063), so `self_host` is the sending host
/// rather than a field of one caller.
#[cfg_attr(
    not(any(test, feature = "test-util")),
    allow(
        unused_variables,
        reason = "self_host is read only by the limit a test forces"
    )
)]
pub(crate) fn datagram_limit(self_host: &Hostname, live: &LivePeer) -> Option<usize> {
    if !live.negotiated.allows(features::DATAGRAM_BATCHES) {
        return None;
    }
    // The one seam a test has into this number. `send_datagram` refuses a batch built against a
    // limit the path does not hold, and nothing a test can do to a loopback connection makes
    // quinn's own answer disagree with it (T-062 test 7).
    #[cfg(any(test, feature = "test-util"))]
    if let Some(forced) = crate::testutil::datagram_limit::forced(self_host) {
        return Some(forced);
    }
    live.connection.max_datagram_size()
}

/// A large message's plan as the send loop wants it: the hosts that take it whole, in the order
/// the plan lists them, and the chunk indices each striped host is owed.
///
/// Both arms travel. A region below `stripe_min_recipients`, and every host of a striped region
/// that reads whole messages only, are on the path v1 sent everything by; the rest are sent
/// their chunks (§5.4, D29).
fn stripes(regions: Vec<RegionPlan>) -> (Vec<Hostname>, BTreeMap<Hostname, Vec<u16>>) {
    let mut whole = Vec::new();
    let mut striped: BTreeMap<Hostname, Vec<u16>> = BTreeMap::new();
    for region in regions {
        match region {
            RegionPlan::Whole { targets } => whole.extend(targets),
            RegionPlan::Stripe {
                targets_per_chunk, ..
            } => {
                for (index, target) in targets_per_chunk.into_iter().enumerate() {
                    // `Params::for_len` narrows `k + m` into a `u16` already, so there is no
                    // index here that a chunk header could not carry.
                    if let Ok(index) = u16::try_from(index) {
                        striped.entry(target).or_default().push(index);
                    }
                }
            }
        }
    }
    (whole, striped)
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
    use overlay_core::rs::Params;
    use overlay_core::subs::PeerState;
    use overlay_core::wire::{self, Chunk, ChunkFlags, Read};

    use super::*;
    use crate::manager::{LiveSource, LiveView};
    use crate::sender::{LARGE_QUEUED_BYTES_MAX, LargeLedger, PeerSender};
    use crate::testutil::{
        Builder, NodeKind, REGION, SendSpy, TestCluster, WAIT, datagram_limit, eventually,
        peer_state, subscriptions, topic, view, within,
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

    /// The large class is untouched by any of this (§5.4). A block is a whole message on a
    /// stream, as v1 sent it, until T-073 stripes it: a `BATCH` entry could not carry one
    /// anyway, since its length is a `u16` (D21).
    #[tokio::test(flavor = "multi_thread")]
    async fn large_class_message_still_uses_a_stream_and_is_not_batched() {
        let block = topic("beacon_block");
        let payload = incompressible(4096);
        let mut cluster = TestCluster::start(2).await;
        for node in 0..2 {
            cluster.start_sidecar(node, subscriptions(&[&block], &[]));
        }
        eventually("the sibling to say it wants blocks", || {
            cluster.live(0).subscribers(&block).len() == 1
        })
        .await;

        assert!(cluster.from_bn(0, &block, &payload));

        eventually("the sibling to queue it", || {
            cluster.published(1).len() == 1
        })
        .await;
        assert_eq!(cluster.published(1)[0].class, Class::Large);
        assert_eq!(cluster.datagrams_received(1, &cluster.hostname(0)), 0);
    }

    /// Small class is not the same as small. `Class::of` puts an `AttesterSlashing` in it on
    /// kind alone, and a post-Electra one carries every attesting index of a slot twice, well
    /// past the `u16` length a `BATCH` entry has for it. Such a payload never reaches the
    /// batcher: it goes as a whole message, the way v1 sent everything, because `wire`'s
    /// narrowing would stop a debug build and a release build would write a frame that decodes
    /// as something else (D21).
    #[tokio::test(flavor = "multi_thread")]
    async fn small_class_payload_no_batch_entry_can_hold_goes_as_a_whole_message() {
        let slashing = topic("attester_slashing");
        let payload = incompressible(MAX_BATCH_ENTRY_BYTES + 4096);
        assert!(payload.len() > MAX_BATCH_ENTRY_BYTES, "{}", payload.len());
        let mut cluster = TestCluster::start(2).await;
        for node in 0..2 {
            cluster.start_sidecar(node, subscriptions(&[&slashing], &[]));
        }
        eventually("the sibling to say it wants slashings", || {
            cluster.live(0).subscribers(&slashing).len() == 1
        })
        .await;

        assert!(cluster.from_bn(0, &slashing, &payload));

        eventually("the sibling to queue it", || {
            cluster.published(1).len() == 1
        })
        .await;
        assert_eq!(cluster.published(1)[0].class, Class::Small);
        assert_eq!(cluster.published(1)[0].payload, payload);
        assert_eq!(cluster.datagrams_received(1, &cluster.hostname(0)), 0);
    }

    /// The fallback D29 exists for, which is what lets a fleet be upgraded host by host: toward
    /// a peer that never advertised `DATAGRAM_BATCHES`, the small class goes as whole messages
    /// on streams the way v1 sent it, and it arrives.
    #[tokio::test(flavor = "multi_thread")]
    async fn peer_without_datagram_batches_feature_still_receives_whole_messages_on_streams() {
        let subnet = topic("beacon_attestation_7");
        let payload = attestation(0);
        let mut cluster = Builder::new(&[NodeKind::Manager; 2])
            .advertising(1, 0)
            .start()
            .await;
        for node in 0..2 {
            cluster.start_sidecar(node, subscriptions(&[&subnet], &[]));
        }
        eventually("the older sibling to say it wants the subnet", || {
            cluster.live(0).subscribers(&subnet).len() == 1
        })
        .await;
        assert_eq!(
            cluster
                .live(0)
                .get(&cluster.hostname(1))
                .unwrap()
                .negotiated
                .features,
            0
        );

        assert!(cluster.from_bn(0, &subnet, &payload));

        eventually("the older sibling to queue it", || {
            cluster.published(1).len() == 1
        })
        .await;
        assert_eq!(cluster.published(1)[0].payload, payload);
        assert_eq!(cluster.datagrams_received(1, &cluster.hostname(0)), 0);
    }

    /// Path MTU discovery can lower what a path holds between the batcher's check and the send,
    /// and quinn answers `TooLarge` (§5.3). The batch is not lost for it: it goes on a stream,
    /// which is what carries a payload no datagram ever held either.
    ///
    /// The only way to make quinn's own answer disagree with what the same connection will take
    /// is to build the batch against a different number, so the test sets the limit the sending
    /// node batches to above what its loopback path really holds.
    #[tokio::test(flavor = "multi_thread")]
    async fn too_large_error_falls_back_to_stream_and_the_batch_still_arrives() {
        let subnet = topic("beacon_attestation_7");
        let payload = incompressible(4096);
        let mut cluster = TestCluster::start(2).await;
        datagram_limit::set(&cluster.hostname(0), Some(8192));
        for node in 0..2 {
            cluster.start_sidecar(node, subscriptions(&[&subnet], &[]));
        }
        eventually("the sibling to say it wants the subnet", || {
            cluster.live(0).subscribers(&subnet).len() == 1
        })
        .await;

        assert!(cluster.from_bn(0, &subnet, &payload));

        eventually("the sibling to queue it", || {
            cluster.published(1).len() == 1
        })
        .await;
        assert_eq!(cluster.published(1)[0].payload, payload);
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
            // Nothing here is striped: this is about a hundred queues moving independently, and
            // a stripe would leave the peers the assignment missed with nothing to wait for.
            tokio::sync::watch::channel(config::Fanout {
                large: config::LargeFanout {
                    stripe_min_recipients: usize::MAX,
                    ..config::LargeFanout::default()
                },
                ..config::Fanout::default()
            })
            .1,
            topics,
            crate::batching::Batching::spawn(
                tokio::sync::watch::channel(config::SmallClass::default()).1,
                Arc::new(()),
            )
            .0,
            Arc::new(()),
            config::LargeClass::default(),
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

    /// A view of `hosts` peers in one region, each subscribed to `block` under the id this
    /// host's table hands out, each with a sender a test can read, and each having negotiated
    /// the bit a stripe needs. Sorted-hostname order is the map's own, which is what the
    /// assignment is computed against (D18).
    fn striped_view(
        connection: &quinn::Connection,
        block: &Topic,
        hosts: usize,
    ) -> (LiveView, Vec<Hostname>, Vec<SendSpy>) {
        let names: Vec<Hostname> = (0..hosts).map(|n| Hostname(format!("bn-{n:02}"))).collect();
        let peers: Vec<(Hostname, PeerState)> = names
            .iter()
            .map(|name| (name.clone(), peer_state(&[(1, block)], &[1])))
            .collect();
        let spies: Vec<SendSpy> = (0..hosts).map(|_| SendSpy::open()).collect();
        let deps = crate::sender::Deps {
            ledger: Arc::new(LargeLedger::new(LARGE_QUEUED_BYTES_MAX)),
            stats: Arc::new(()),
        };
        let mut live = view(connection, peers);
        for ((hostname, peer), spy) in live.0.iter_mut().zip(&spies) {
            peer.negotiated.features = overlay_core::protocol::SUPPORTED_FEATURES;
            peer.sender = PeerSender::spawn(hostname.clone(), spy.clone(), deps.clone());
        }
        (live, names, spies)
    }

    /// Starts a fanout over `live` with `block` interned, and hands back what pushes into it.
    fn striping_fanout(
        live: LiveView,
        block: &Topic,
        stripe_min_recipients: usize,
    ) -> (overlay_core::lanes::LanePusher<Outbound>, JoinHandle<()>) {
        let topics = Arc::new(Mutex::new(OwnTopics::default()));
        lock(&topics).table.intern(block).expect("a fresh table");
        let lanes = ClassLanes::new(Arc::new(()));
        let pusher = lanes.pusher();
        let fanout = Fanout::spawn(
            lanes,
            LiveSource::fixed(live),
            SelfIdentity {
                hostname: Hostname("bn-me".to_owned()),
                region: Region(REGION.to_owned()),
                site: None,
            },
            tokio::sync::watch::channel(config::Fanout {
                large: config::LargeFanout {
                    stripe_min_recipients,
                    ..config::LargeFanout::default()
                },
                ..config::Fanout::default()
            })
            .1,
            topics,
            crate::batching::Batching::spawn(
                tokio::sync::watch::channel(config::SmallClass::default()).1,
                Arc::new(()),
            )
            .0,
            Arc::new(()),
            config::LargeClass::default(),
            Arc::default(),
        );
        (pusher, fanout)
    }

    /// Every `CHUNK` on one stream, in the order it was written.
    async fn chunks_of(frame: &Bytes) -> Vec<(ChunkFlags, Chunk)> {
        let mut stream = &frame[..];
        let mut chunks = Vec::new();
        while let Ok(Read::Frame(Frame::Chunk { flags, chunk })) =
            wire::read_frame(&mut stream, overlay_core::protocol::MAX_FRAME_BYTES).await
        {
            chunks.push((flags, chunk));
        }
        chunks
    }

    /// A large message for `topic` under an id a test picked, so the rotation the assignment
    /// starts at is the test's to compute as well.
    fn large(topic: &Topic, id: MessageId, payload: Vec<u8>) -> Outbound {
        Outbound {
            topic: topic.clone(),
            class: Class::Large,
            id,
            payload: Bytes::from(payload),
            received_at: Instant::now(),
        }
    }

    /// §5.4 step 2 and D18: chunk `i` goes to the host `stripe::assign` names and to nobody
    /// else, and it leaves with `FORWARDED` clear, which is what asks the host that receives it
    /// to hand it to the rest of the region (D11).
    #[tokio::test(flavor = "multi_thread")]
    async fn origin_sends_each_chunk_to_its_assigned_host_with_forwarded_clear() {
        let block = topic("beacon_block");
        let id = MessageId([9; 20]);
        let payload = incompressible(20 * 1024);
        let cluster = Builder::new(&[NodeKind::Bare, NodeKind::Bare])
            .start()
            .await;
        let connection = tokio::time::timeout(WAIT, cluster.connected_pair(0, 1))
            .await
            .expect("the pair to connect")
            .0;
        let (live, names, spies) = striped_view(&connection, &block, 6);
        let (pusher, _fanout) = striping_fanout(live, &block, 2);
        let split = Params::for_len(payload.len(), 2048, 0.10).expect("a split for this payload");
        let chunks = usize::from(split.k) + usize::from(split.m);
        let assignment = overlay_core::stripe::assign(&id, &names, chunks);

        pusher
            .push(Class::Large, large(&block, id, payload))
            .expect("the fanout lane has room");

        eventually("every assigned host to be written to", || {
            names
                .iter()
                .enumerate()
                .all(|(n, name)| spies[n].sent().len() == usize::from(assignment.contains(name)))
        })
        .await;
        for (n, name) in names.iter().enumerate() {
            let mut indices = Vec::new();
            for frame in spies[n].sent() {
                for (flags, chunk) in chunks_of(&frame).await {
                    assert_eq!(flags, ChunkFlags::NONE, "{name}");
                    assert_eq!((chunk.k, chunk.m), (split.k, split.m), "{name}");
                    indices.push(chunk.index);
                }
            }
            let expected: Vec<u16> = (0..split.k + split.m)
                .filter(|index| assignment[usize::from(*index)] == *name)
                .collect();
            assert_eq!(indices, expected, "{name}");
        }
    }

    /// D19: one unidirectional stream per (message, target), whatever the assignment gave that
    /// target. A stream per chunk would cost a 200 KB block a hundred streams per host instead
    /// of one, which is the whole saving striping is for.
    #[tokio::test(flavor = "multi_thread")]
    async fn chunks_for_one_target_travel_on_one_stream() {
        let block = topic("beacon_block");
        let id = MessageId([4; 20]);
        let payload = incompressible(20 * 1024);
        let cluster = Builder::new(&[NodeKind::Bare, NodeKind::Bare])
            .start()
            .await;
        let connection = tokio::time::timeout(WAIT, cluster.connected_pair(0, 1))
            .await
            .expect("the pair to connect")
            .0;
        let (live, names, spies) = striped_view(&connection, &block, 3);
        let (pusher, _fanout) = striping_fanout(live, &block, 2);
        let split = Params::for_len(payload.len(), 2048, 0.10).expect("a split for this payload");
        let chunks = usize::from(split.k) + usize::from(split.m);
        assert!(
            chunks > names.len(),
            "every host should take several chunks"
        );

        pusher
            .push(Class::Large, large(&block, id, payload))
            .expect("the fanout lane has room");

        eventually("every host to be written to", || {
            spies.iter().all(|spy| !spy.sent().is_empty())
        })
        .await;
        let mut written = 0;
        for (n, name) in names.iter().enumerate() {
            let streams = spies[n].sent();
            assert_eq!(streams.len(), 1, "{name}");
            let on_it = chunks_of(&streams[0]).await.len();
            assert!(on_it > 1, "{name} took {on_it} chunks");
            written += on_it;
        }
        assert_eq!(written, chunks);
    }

    /// What a large plan means to the send loop: the regions too small to stripe are the whole
    /// answer, in the order the plan lists them, and a striped region turns into the chunk
    /// indices each of its hosts is owed.
    #[test]
    fn whole_takes_the_regions_a_stripe_would_not_cover() {
        let striped_host = Hostname("bn-us-01".to_owned());
        let plan = vec![
            RegionPlan::Whole {
                targets: vec![Hostname("bn-eu-a".to_owned())],
            },
            RegionPlan::Stripe {
                region: Region("us".to_owned()),
                targets_per_chunk: vec![striped_host.clone(), striped_host.clone()],
            },
            RegionPlan::Whole {
                targets: vec![Hostname("bn-ap-01".to_owned())],
            },
        ];

        let (whole, striped) = stripes(plan);

        assert_eq!(
            whole,
            vec![
                Hostname("bn-eu-a".to_owned()),
                Hostname("bn-ap-01".to_owned())
            ]
        );
        assert_eq!(striped, BTreeMap::from([(striped_host, vec![0, 1])]));
    }
}
