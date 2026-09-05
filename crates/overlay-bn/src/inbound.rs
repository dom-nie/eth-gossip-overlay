//! The first hop of everything the beacon node forwards (§5.2, §6.1 to §6.3): each message the
//! link queued is acknowledged, classified, checked against the seen cache and, when new,
//! handed to the fanout task as an [`Outbound`].
//!
//! Three hand-offs, none of which waits. The link's lanes are drained with `recv()`, large
//! first, so a block is never queued behind attestations (D07). `Accept` goes back to the
//! swarm loop with `try_send` before anything else happens to the message, so neither the seen
//! cache nor a full fanout lane can hold up gossipsub's memcache cleanup. The `Outbound` goes
//! out with `push`, which is `try_send` too, so a stalled fanout drops here instead of backing
//! up into the swarm loop.
//!
//! `Accept` is the only verdict there is: the beacon node validated the message before
//! forwarding it, and the sidecar has no other gossipsub peers, so the report only lets
//! gossipsub forget the message.

use std::collections::BTreeSet;
use std::sync::Arc;

use overlay_core::fanout::Outbound;
use overlay_core::lanes::{ClassLanes, LanePusher};
use overlay_core::msgid::MessageId;
use overlay_core::seen::SharedSeenCache;
use overlay_core::time::Clock;
use overlay_core::topic::{Class, Topic};
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio::task::JoinHandle;

use crate::link::{BnCommand, BnMessage};

/// Where the inbound path counts. Every call is about the beacon node side, so `source="bn"`
/// is implied rather than passed: T-041 binds [`first_seen`](Self::first_seen) and
/// [`duplicate`](Self::duplicate) to `first_seen_total` and `duplicates_dropped_total` under
/// that label, [`unknown_kind`](Self::unknown_kind) to `unknown_topic_kind_total{class}` and
/// [`dropped_full`](Self::dropped_full) to the fanout lane's drop series. `()` counts nothing.
pub trait InboundStats: Send + Sync {
    /// The seen cache did not hold the id: the beacon node reached this host before the
    /// overlay did.
    fn first_seen(&self, class: Class);
    /// The seen cache already held the id: the overlay delivered the message earlier and the
    /// beacon node is echoing it, or another beacon node's copy (§5.5).
    fn duplicate(&self, class: Class);
    /// The fanout lane for `class` was full and the message was dropped. The [`LanePusher`]
    /// counts the same drop on the [`LaneStats`](overlay_core::lanes::LaneStats) the fanout
    /// lanes were built with, so pass `()` there when this is the only series wanted.
    fn dropped_full(&self, class: Class);
    /// A message on a topic name the sidecar does not know, classified by payload size
    /// (D02). Its name is logged once so a fork that adds a topic is visible before a release
    /// names it.
    fn unknown_kind(&self, class: Class);
}

impl InboundStats for () {
    fn first_seen(&self, _: Class) {}
    fn duplicate(&self, _: Class) {}
    fn dropped_full(&self, _: Class) {}
    fn unknown_kind(&self, _: Class) {}
}

/// The task's state. [`spawn`](Self::spawn) starts it; it runs until aborted, because the
/// lanes never close.
pub struct Inbound {
    lanes: ClassLanes<BnMessage>,
    commands: mpsc::Sender<BnCommand>,
    seen: SharedSeenCache,
    out: LanePusher<Outbound>,
    clock: Arc<dyn Clock>,
    stats: Arc<dyn InboundStats>,
    /// Topic strings already warned about, so a stream of messages on one costs one line.
    warned: BTreeSet<String>,
}

impl Inbound {
    /// Starts draining `lanes`. Every message is reported `Accept` on `commands`; a new one
    /// becomes an [`Outbound`] on `out`, stamped with `clock`'s time.
    pub fn spawn(
        lanes: ClassLanes<BnMessage>,
        commands: mpsc::Sender<BnCommand>,
        seen: SharedSeenCache,
        out: LanePusher<Outbound>,
        clock: Arc<dyn Clock>,
        stats: Arc<dyn InboundStats>,
    ) -> JoinHandle<()> {
        let mut inbound = Self {
            lanes,
            commands,
            seen,
            out,
            clock,
            stats,
            warned: BTreeSet::new(),
        };
        tokio::spawn(async move {
            loop {
                let msg = inbound.lanes.recv().await;
                inbound.handle(msg);
            }
        })
    }

    fn handle(&mut self, msg: BnMessage) {
        let received_at = self.clock.now();
        // The swarm loop drains its commands without ever waiting, so a full channel means it
        // is wedged, and waiting here would only add this task to what it holds up.
        match self.commands.try_send(BnCommand::ReportAccept {
            id: msg.id.clone(),
            source: msg.source,
        }) {
            Ok(()) | Err(TrySendError::Closed(_)) => {}
            Err(TrySendError::Full(_)) => {
                tracing::warn!(id = %msg.id, "command channel full: accept not reported");
            }
        }
        // The mirror only subscribes to strings it was given, so a message on one that does
        // not parse means the beacon node announced it; the mirror warned then, this warns
        // once more when a payload arrives, and T-041 has no series for it.
        let topic = match Topic::parse(&msg.topic) {
            Ok(topic) => topic,
            Err(err) => {
                if self.warned.insert(msg.topic.clone()) {
                    tracing::warn!(topic = msg.topic, %err, "dropping messages on a topic the sidecar cannot parse");
                }
                return;
            }
        };
        let class = Class::of(topic.kind(), msg.data.len());
        // T-012's id function always yields 20 bytes; this only guards a future id function.
        let Some(id) = MessageId::from_slice(&msg.id.0) else {
            tracing::error!(id = %msg.id, topic = msg.topic, "gossipsub id is not 20 bytes");
            return;
        };
        // Insert site 1 of 3 (D08). The other two are T-032's receiver, for what arrives whole
        // from the overlay, and T-074's completion, for what the reassembler puts together.
        if !self.seen.insert(id) {
            self.stats.duplicate(class);
            return;
        }
        self.stats.first_seen(class);
        // A full fanout lane is counted, and for the large lane logged, by the pusher.
        let _ = self.out.push(
            class,
            Outbound {
                topic,
                class,
                id,
                payload: msg.data.into(),
                received_at,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, LazyLock, Mutex};
    use std::time::Duration;

    use libp2p::PeerId;
    use libp2p::gossipsub;
    use libp2p::identity::Keypair;
    use overlay_core::fanout::Outbound;
    use overlay_core::lanes::{ClassLanes, LanePusher};
    use overlay_core::msgid::{self, MessageId};
    use overlay_core::seen::{SeenCache, SharedSeenCache};
    use overlay_core::time::FakeClock;
    use overlay_core::topic::{Class, Topic, UNKNOWN_LARGE_THRESHOLD_BYTES};
    use tokio::sync::mpsc;

    use super::*;
    use crate::gossip::wire;
    use crate::link::{BnCommand, BnMessage};

    const ATTESTATION_3: &str = "/eth2/00000000/beacon_attestation_3/ssz_snappy";
    /// A name the sidecar does not know, as a future fork might add one.
    const NEW_THING: &str = "/eth2/00000000/new_thing_topic/ssz_snappy";

    static BN: LazyLock<PeerId> =
        LazyLock::new(|| Keypair::generate_ed25519().public().to_peer_id());

    /// A message as the link pushes it: `data` is the wire payload and the id is the one
    /// T-012's function gives it, so two payloads never share an id and a repeat is a real
    /// duplicate.
    fn message(topic: &str, data: &[u8]) -> BnMessage {
        let id = msgid::compute(topic, data, wire::MAX_PAYLOAD_SIZE as usize).id;
        BnMessage {
            id: gossipsub::MessageId::from(&id.0[..]),
            topic: topic.to_owned(),
            data: data.to_vec(),
            source: *BN,
        }
    }

    fn core_id(msg: &BnMessage) -> MessageId {
        MessageId::from_slice(&msg.id.0).unwrap()
    }

    /// Whether the fanout lanes stay empty. Under `start_paused` the timeout fires as soon as
    /// the runtime has nothing left to run, so this costs no wall-clock time.
    async fn nothing_out(out: &mut ClassLanes<Outbound>) -> bool {
        tokio::time::timeout(Duration::from_secs(1), out.recv())
            .await
            .is_err()
    }

    /// Every stats call in the order it was made.
    #[derive(Default)]
    struct Recorded(Mutex<Vec<(&'static str, Class)>>);

    impl Recorded {
        fn record(&self, what: &'static str, class: Class) {
            self.0.lock().unwrap().push((what, class));
        }

        fn count(&self, what: &str, class: Class) -> usize {
            self.0
                .lock()
                .unwrap()
                .iter()
                .filter(|(w, c)| *w == what && *c == class)
                .count()
        }

        fn total(&self) -> usize {
            self.0.lock().unwrap().len()
        }
    }

    impl InboundStats for Recorded {
        fn first_seen(&self, class: Class) {
            self.record("first_seen", class);
        }

        fn duplicate(&self, class: Class) {
            self.record("duplicate", class);
        }

        fn dropped_full(&self, class: Class) {
            self.record("dropped_full", class);
        }

        fn unknown_kind(&self, class: Class) {
            self.record("unknown_kind", class);
        }
    }

    /// The task's surroundings. Messages pushed before [`start`](Self::start) are waiting in
    /// the lanes when the task begins; pushes after it go through the same pusher the link
    /// would hold.
    struct Harness {
        lanes: Option<ClassLanes<BnMessage>>,
        pusher: LanePusher<BnMessage>,
        command_tx: mpsc::Sender<BnCommand>,
        commands: mpsc::Receiver<BnCommand>,
        seen: SharedSeenCache,
        out: ClassLanes<Outbound>,
        clock: FakeClock,
        stats: Arc<Recorded>,
    }

    impl Harness {
        fn new() -> Self {
            Self::with_out(ClassLanes::new(Arc::new(())))
        }

        fn with_out(out: ClassLanes<Outbound>) -> Self {
            let lanes = ClassLanes::new(Arc::new(()));
            let (command_tx, commands) = mpsc::channel(64);
            let clock = FakeClock::new();
            let seen = SharedSeenCache::new(SeenCache::new(
                Duration::from_secs(60),
                1024,
                Arc::new(clock.clone()),
            ));
            Self {
                pusher: lanes.pusher(),
                lanes: Some(lanes),
                command_tx,
                commands,
                seen,
                out,
                clock,
                stats: Arc::new(Recorded::default()),
            }
        }

        fn push(&self, class: Class, msg: BnMessage) {
            self.pusher.push(class, msg).unwrap();
        }

        fn start(&mut self) {
            Inbound::spawn(
                self.lanes.take().expect("start() is called once"),
                self.command_tx.clone(),
                self.seen.clone(),
                self.out.pusher(),
                Arc::new(self.clock.clone()),
                self.stats.clone(),
            );
        }

        /// The next command, which has to be a `ReportAccept`, as its id and source.
        async fn accepted(&mut self) -> (gossipsub::MessageId, PeerId) {
            match self.commands.recv().await.unwrap() {
                BnCommand::ReportAccept { id, source } => (id, source),
                other => panic!("expected ReportAccept, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn new_message_is_forwarded_once_with_topic_class_id_and_payload() {
        let mut h = Harness::new();
        h.clock.advance(Duration::from_secs(5));
        let msg = message(ATTESTATION_3, b"an attestation");
        h.push(Class::Small, msg.clone());
        h.start();

        let out = h.out.recv().await;

        assert_eq!(out.topic, Topic::parse(ATTESTATION_3).unwrap());
        assert_eq!(out.class, Class::Small);
        assert_eq!(out.id, core_id(&msg));
        assert_eq!(out.payload, msg.data);
        assert_eq!(out.received_at, h.clock.now());
        assert_eq!(h.stats.count("first_seen", Class::Small), 1);
        assert_eq!(h.stats.total(), 1);
    }

    #[tokio::test]
    async fn accept_is_reported_for_every_message_including_duplicates() {
        let mut h = Harness::new();
        let msg = message(ATTESTATION_3, b"an attestation");
        h.push(Class::Small, msg.clone());
        h.push(Class::Small, msg.clone());
        h.start();

        assert_eq!(h.accepted().await, (msg.id.clone(), *BN));
        assert_eq!(h.accepted().await, (msg.id, *BN));
    }

    #[tokio::test(start_paused = true)]
    async fn duplicate_id_is_dropped_and_counted() {
        let mut h = Harness::new();
        let msg = message(ATTESTATION_3, b"an attestation");
        h.push(Class::Small, msg.clone());
        h.push(Class::Small, msg.clone());
        h.start();

        let out = h.out.recv().await;

        assert_eq!(out.id, core_id(&msg));
        assert!(nothing_out(&mut h.out).await);
        assert_eq!(h.stats.count("first_seen", Class::Small), 1);
        assert_eq!(h.stats.count("duplicate", Class::Small), 1);
        assert_eq!(h.stats.total(), 2);
    }

    /// The id got into the cache from the overlay side, and the beacon node is now echoing
    /// the message the sidecar published into it: the normal dedup path (§5.5).
    #[tokio::test(start_paused = true)]
    async fn message_already_in_seen_cache_from_overlay_is_dropped() {
        let mut h = Harness::new();
        let msg = message(ATTESTATION_3, b"an attestation");
        assert!(h.seen.insert(core_id(&msg)));
        h.push(Class::Small, msg.clone());
        h.start();

        assert_eq!(h.accepted().await, (msg.id, *BN));
        assert!(nothing_out(&mut h.out).await);
        assert_eq!(h.stats.count("duplicate", Class::Small), 1);
        assert_eq!(h.stats.total(), 1);
    }

    /// What the fanout task reads must already be in the cache, or a copy arriving from the
    /// overlay in between would be published back into the beacon node.
    #[tokio::test]
    async fn id_is_in_the_seen_cache_by_the_time_the_outbound_is_readable() {
        let mut h = Harness::new();
        h.push(Class::Small, message(ATTESTATION_3, b"an attestation"));
        h.start();

        let out = h.out.recv().await;

        assert!(h.seen.contains(&out.id));
    }

    #[tokio::test]
    async fn payload_is_forwarded_unchanged() {
        let mut h = Harness::new();
        let compressed = snap::raw::Encoder::new()
            .compress_vec(b"an attestation")
            .unwrap();
        h.push(Class::Small, message(ATTESTATION_3, &compressed));
        h.start();

        let out = h.out.recv().await;

        assert_eq!(out.payload, compressed);
        let decompressed = snap::raw::Decoder::new()
            .decompress_vec(&out.payload)
            .unwrap();
        assert_eq!(decompressed, b"an attestation");
    }

    #[tokio::test]
    async fn unknown_kind_class_follows_payload_length_at_16_kib() {
        let mut h = Harness::new();
        let at_threshold = vec![1u8; UNKNOWN_LARGE_THRESHOLD_BYTES];
        let below = vec![2u8; UNKNOWN_LARGE_THRESHOLD_BYTES - 1];
        h.push(Class::Large, message(NEW_THING, &at_threshold));
        h.push(Class::Small, message(NEW_THING, &below));
        h.start();

        let large = h.out.recv_from(Class::Large).await;
        let small = h.out.recv_from(Class::Small).await;

        assert_eq!(
            (large.class, large.payload.len()),
            (Class::Large, at_threshold.len())
        );
        assert_eq!(
            (small.class, small.payload.len()),
            (Class::Small, below.len())
        );
    }
}
