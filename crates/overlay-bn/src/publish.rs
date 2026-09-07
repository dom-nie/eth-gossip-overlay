//! The one path into the beacon node (§5.2 "Publishing into the BN", §5.7, DX-N4). Ingress
//! sites hold a [`PublishHandle`] and call [`enqueue`](PublishHandle::enqueue), which locks
//! the queue for a push and returns; nothing on the overlay receive path ever awaits the
//! beacon node. One [`Publisher`] task drains the queue large-first and is the only code in
//! the sidecar that awaits gossipsub: it sends `BnCommand::Publish` to the link and waits for
//! the reply, so a wedged beacon node stalls this task and nothing else.
//!
//! Neither the handle nor the publisher holds a seen cache (D08). The three ingress sites
//! insert immediately before they enqueue: T-016 for what the beacon node sent, T-032's
//! receiver for whole messages and batch entries from the overlay, T-074's completion for
//! reassembled messages. Because the insert precedes the queue, a copy suppressed here is
//! still remembered for the TTL.
//!
//! Gossipsub's own duplicate cache refuses anything it already received or published, so a
//! `Duplicate` reply is a normal outcome (the beacon node echoed a message the sidecar
//! already had), and `NoPeersSubscribedToTopic` is the `SUBS` race: a sibling routed on a
//! subscription the beacon node has since dropped. Both are counted and logged at debug, never
//! at error level. `idontwant_on_publish` is gossipsub's own flag (T-012); nothing here does
//! anything extra for it (CL-N4).

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use libp2p::gossipsub::PublishError;
use overlay_core::config::PublishRateLimit;
use overlay_core::progress::PROGRESS_TICK;
use overlay_core::pubqueue::{
    DropReason, PublishItem, PublishQueue, PublishSink, Pushed, QueueStats,
};
use overlay_core::ratelimit::PublishLimits;
use overlay_core::time::Clock;
use overlay_core::topic::Class;
use tokio::sync::{Notify, mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::link::BnCommand;

/// Where the publish path counts. T-041 binds [`published`](Self::published) to
/// `messages_total{direction="bn_out", class}`, [`suppressed_inject_off`](Self::suppressed_inject_off)
/// to `publish_suppressed_total{reason="inject_off", class}`,
/// [`rate_limited`](Self::rate_limited) to `rate_limited_total{class}`,
/// [`error`](Self::error) to `publish_errors_total{class, reason}` and
/// [`queue_drop`](Self::queue_drop) to `publish_queue_drops_total{class, reason}`. `()` counts
/// nothing.
pub trait PublishStats: Send + Sync {
    /// Gossipsub accepted the message; it is on its way to the beacon node.
    fn published(&self, class: Class);
    /// The inject kill switch is off; the item was dequeued and discarded.
    fn suppressed_inject_off(&self, class: Class);
    /// The class bucket or the bytes bucket was empty; the item was discarded.
    fn rate_limited(&self, class: Class);
    /// Gossipsub refused the message for `reason`: `duplicate` and `no_subscribers` are
    /// normal outcomes, the others are logged as warnings.
    fn error(&self, class: Class, reason: &'static str);
    /// The queue evicted or expired an entry. Runs inside the queue's lock, so an
    /// implementation must be a counter increment and nothing slower.
    fn queue_drop(&self, class: Class, reason: DropReason);
}

impl PublishStats for () {
    fn published(&self, _: Class) {}
    fn suppressed_inject_off(&self, _: Class) {}
    fn rate_limited(&self, _: Class) {}
    fn error(&self, _: Class, _: &'static str) {}
    fn queue_drop(&self, _: Class, _: DropReason) {}
}

/// The queue's drop counter, forwarded so T-041 implements one trait for the whole path.
struct QueueDrops(Arc<dyn PublishStats>);

impl QueueStats for QueueDrops {
    fn dropped(&self, class: Class, reason: DropReason) {
        self.0.queue_drop(class, reason);
    }
}

/// What an ingress site learns from [`PublishHandle::enqueue`]. The item is queued either way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnqueueOutcome {
    /// The lane had room.
    Enqueued,
    /// The lane was full and evicted its oldest entries to make room; they were counted.
    Dropped(DropReason),
}

/// What the drain task did with one item.
#[derive(Debug, PartialEq, Eq)]
pub enum PublishOutcome {
    /// Gossipsub accepted it.
    Published,
    /// The inject kill switch is off; the item was discarded before any command was sent.
    SuppressedInjectOff,
    /// The class bucket or the bytes bucket was empty; the item was discarded.
    RateLimited,
    /// Gossipsub already had it: the beacon node echoed a message the sidecar had received.
    Duplicate,
    /// The sidecar's gossipsub instance is no longer subscribed to the topic: the `SUBS` race.
    NoSubscribers,
    /// Gossipsub refused it for the named reason, the `reason` label of `publish_errors_total`.
    Error(&'static str),
}

/// The ingress sites' end of the publish queue. Cheap to clone; every clone feeds the same
/// queue and wakes the same drain task. Holds no seen cache: see the module doc for the
/// three insert sites.
#[derive(Clone)]
pub struct PublishHandle {
    queue: Arc<Mutex<PublishQueue>>,
    wake: Arc<Notify>,
    clock: Arc<dyn Clock>,
}

impl PublishHandle {
    /// Queues `item`, stamped with the clock's time, and wakes the drain task. Synchronous:
    /// the lock is held for the push and nothing else.
    pub fn enqueue(&self, item: PublishItem) -> EnqueueOutcome {
        let pushed = self.lock().push(item, self.clock.now());
        self.wake.notify_one();
        match pushed {
            Pushed::Enqueued => EnqueueOutcome::Enqueued,
            Pushed::Dropped { reason, .. } => EnqueueOutcome::Dropped(reason),
        }
    }

    fn pop(&self) -> Option<PublishItem> {
        self.lock().pop(self.clock.now())
    }

    fn lock(&self) -> MutexGuard<'_, PublishQueue> {
        // A poisoned lock means a thread panicked mid-push. The queue's accounting is updated
        // before any call that could panic, so recover it instead of spreading the panic.
        self.queue.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl PublishSink for PublishHandle {
    fn enqueue(&self, item: PublishItem) {
        // The outcome is the queue's to count, on the stats the whole publish path shares, so
        // an ingress site on the other side of the crate boundary has nothing to do with it.
        PublishHandle::enqueue(self, item);
    }
}

/// The drain task. [`spawn`](Self::spawn) starts it; it ends when the link's command channel
/// closes, because a publish can then never be answered.
pub struct Publisher {
    queue: PublishHandle,
    commands: mpsc::Sender<BnCommand>,
    inject: Arc<AtomicBool>,
    rates: watch::Receiver<PublishRateLimit>,
    limits: PublishLimits,
    stats: Arc<dyn PublishStats>,
}

impl Publisher {
    /// Builds the queue and starts draining it into `commands`. The handle is what T-032,
    /// T-062 and T-074 hold; the task keeps going until the link is gone. `inject` is the
    /// kill switch, shared with whoever flips it (config, SIGHUP, `eth-gossip-overlayctl`); it is
    /// read per item, so flipping it back on resumes without a restart. `rates` carries
    /// `bn.publish_rate_limit`, which T-043 sends a new value on when an operator changes it.
    ///
    /// `progress` is the watchdog counter this loop owns (OPS-N5): it goes up once per
    /// iteration, and the tick arm is what keeps it going up while the queue is empty.
    pub fn spawn(
        commands: mpsc::Sender<BnCommand>,
        inject: Arc<AtomicBool>,
        rates: watch::Receiver<PublishRateLimit>,
        stats: Arc<dyn PublishStats>,
        clock: Arc<dyn Clock>,
        progress: Arc<AtomicU64>,
    ) -> (PublishHandle, JoinHandle<()>) {
        let (handle, publisher) = Self::new(commands, inject, rates, stats, clock);
        (handle, tokio::spawn(publisher.run(progress)))
    }

    fn new(
        commands: mpsc::Sender<BnCommand>,
        inject: Arc<AtomicBool>,
        rates: watch::Receiver<PublishRateLimit>,
        stats: Arc<dyn PublishStats>,
        clock: Arc<dyn Clock>,
    ) -> (PublishHandle, Self) {
        let handle = PublishHandle {
            queue: Arc::new(Mutex::new(PublishQueue::new(Arc::new(QueueDrops(
                stats.clone(),
            ))))),
            wake: Arc::new(Notify::new()),
            clock,
        };
        let limits = PublishLimits::new(&rates.borrow(), handle.clock.now());
        let publisher = Self {
            queue: handle.clone(),
            commands,
            inject,
            rates,
            limits,
            stats,
        };
        (handle, publisher)
    }

    async fn run(mut self, progress: Arc<AtomicU64>) {
        loop {
            progress.fetch_add(1, Ordering::Relaxed);
            match self.queue.pop() {
                Some(item) => {
                    if self.step(item).await.is_none() {
                        return;
                    }
                }
                // The wake is a `notify_one`, which keeps a permit when nobody is waiting, so
                // a tick that wins the race loses nothing: the next pop takes the item.
                None => tokio::select! {
                    () = self.queue.wake.notified() => {}
                    _ = tokio::time::sleep(PROGRESS_TICK) => {}
                },
            }
        }
    }

    /// Publishes one item and reports what became of it. `None` means the link is gone:
    /// the command could not be delivered or its reply was dropped.
    async fn step(&mut self, item: PublishItem) -> Option<PublishOutcome> {
        self.refresh_limits();
        let class = item.class;
        if !self.inject.load(Ordering::Relaxed) {
            self.stats.suppressed_inject_off(class);
            return Some(PublishOutcome::SuppressedInjectOff);
        }
        if !self
            .limits
            .admit(class, item.payload.len(), self.queue.clock.now())
        {
            self.stats.rate_limited(class);
            return Some(PublishOutcome::RateLimited);
        }
        let (reply, answer) = oneshot::channel();
        let command = BnCommand::Publish {
            topic: item.topic.to_string(),
            data: item.payload.to_vec(),
            reply,
        };
        self.commands.send(command).await.ok()?;
        let outcome = match answer.await.ok()? {
            Ok(_) => {
                self.stats.published(class);
                PublishOutcome::Published
            }
            Err(PublishError::Duplicate) => {
                tracing::debug!(id = %item.id, topic = %item.topic, "gossipsub already had it");
                self.stats.error(class, "duplicate");
                PublishOutcome::Duplicate
            }
            Err(PublishError::NoPeersSubscribedToTopic) => {
                tracing::debug!(id = %item.id, topic = %item.topic, "no longer subscribed");
                self.stats.error(class, "no_subscribers");
                PublishOutcome::NoSubscribers
            }
            Err(err) => {
                let reason = reason(&err);
                tracing::warn!(%err, id = %item.id, topic = %item.topic, "publish refused");
                self.stats.error(class, reason);
                PublishOutcome::Error(reason)
            }
        };
        Some(outcome)
    }

    /// Rebuilds the token buckets when an operator changed `bn.publish_rate_limit`. The new
    /// buckets start full rather than carrying the old level across: a raised ceiling should
    /// take effect at once instead of waiting out a bucket sized for the old one, and a
    /// lowered ceiling holds from the next message.
    fn refresh_limits(&mut self) {
        if self.rates.has_changed().unwrap_or(false) {
            let now = self.queue.clock.now();
            self.limits = PublishLimits::new(&self.rates.borrow_and_update(), now);
        }
    }
}

/// The `reason` label for a gossipsub refusal.
fn reason(err: &PublishError) -> &'static str {
    match err {
        PublishError::Duplicate => "duplicate",
        PublishError::NoPeersSubscribedToTopic => "no_subscribers",
        PublishError::MessageTooLarge => "message_too_large",
        PublishError::SigningError(_) => "signing_error",
        PublishError::TransformFailed(_) => "transform_failed",
        PublishError::AllQueuesFull(_) => "all_queues_full",
        PublishError::Partial(_) => "partial",
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use libp2p::gossipsub::{self, PublishError};
    use overlay_core::config::PublishRateLimit;
    use overlay_core::lanes::ClassLanes;
    use overlay_core::msgid::{self, MessageId};
    use overlay_core::pubqueue::{PublishItem, PublishSink};
    use overlay_core::time::FakeClock;
    use overlay_core::topic::{Class, SubscriptionSets, Topic};
    use prometheus_client::registry::Registry;
    use tokio::sync::{mpsc, watch};
    use tokio::task::JoinHandle;

    use super::*;
    use crate::bn_http::BnClient;
    use crate::gossip::wire;
    use crate::link::{BnCommand, BnEvent, BnLink};
    use crate::spec::spec_watch;
    use crate::testutil::{FakeBn, FakeBnEvent, link_config, node_key};

    /// Long enough for a dial and a gossipsub exchange on a loaded CI box.
    const WAIT: Duration = Duration::from_secs(3);

    const ATTESTATION_3: &str = "/eth2/00000000/beacon_attestation_3/ssz_snappy";
    const BLOCK: &str = "/eth2/00000000/beacon_block/ssz_snappy";

    /// The overlay receive path (T-032) cannot name [`PublishHandle`] without pulling libp2p
    /// into a crate that must never link it, so it holds the trait `overlay-core` defines beside
    /// [`PublishItem`] and this is the implementation behind it. What goes in through the trait
    /// is what the drain task pops.
    #[test]
    fn enqueue_through_the_publish_sink_queues_the_item() {
        let harness = Harness::new();
        let queued = item(Class::Large, 1);

        PublishSink::enqueue(&harness.handle, queued.clone());

        assert_eq!(harness.handle.pop(), Some(queued));
    }

    /// An item numbered `n` on the topic its class suggests, with `payload_len` bytes.
    fn sized_item(class: Class, n: usize, payload_len: usize) -> PublishItem {
        let mut id = [0; 20];
        id[..8].copy_from_slice(&(n as u64).to_le_bytes());
        let topic = match class {
            Class::Small => ATTESTATION_3,
            Class::Large => BLOCK,
        };
        PublishItem {
            topic: Topic::parse(topic).unwrap(),
            id: MessageId(id),
            payload: vec![n as u8; payload_len].into(),
            class,
        }
    }

    fn item(class: Class, n: usize) -> PublishItem {
        sized_item(class, n, 100)
    }

    /// Every stats call in the order it was made, keyed by method and, for errors and queue
    /// drops, the reason.
    #[derive(Default)]
    struct Recorded(Mutex<Vec<(String, Class)>>);

    impl Recorded {
        fn record(&self, what: impl Into<String>, class: Class) {
            self.0.lock().unwrap().push((what.into(), class));
        }

        fn count(&self, what: &str, class: Class) -> usize {
            self.0
                .lock()
                .unwrap()
                .iter()
                .filter(|(w, c)| w == what && *c == class)
                .count()
        }

        fn total(&self) -> usize {
            self.0.lock().unwrap().len()
        }
    }

    impl PublishStats for Recorded {
        fn published(&self, class: Class) {
            self.record("published", class);
        }

        fn suppressed_inject_off(&self, class: Class) {
            self.record("suppressed_inject_off", class);
        }

        fn rate_limited(&self, class: Class) {
            self.record("rate_limited", class);
        }

        fn error(&self, class: Class, reason: &'static str) {
            self.record(format!("error:{reason}"), class);
        }

        fn queue_drop(&self, class: Class, reason: DropReason) {
            self.record(format!("queue_drop:{reason:?}"), class);
        }
    }

    /// The publisher's surroundings, with the command receiver the link would own held by
    /// the test. [`spawn`](Self::spawn) runs the drain task; a test that wants one outcome
    /// at a time calls [`step`](Self::step) instead and answers the command itself.
    struct Harness {
        handle: PublishHandle,
        publisher: Option<Publisher>,
        commands: mpsc::Receiver<BnCommand>,
        inject: Arc<AtomicBool>,
        rates: watch::Sender<PublishRateLimit>,
        clock: FakeClock,
        stats: Arc<Recorded>,
    }

    impl Harness {
        /// The production limits, so the tests assert the DX-N3 numbers themselves.
        fn new() -> Self {
            let (commands_tx, commands) = mpsc::channel(64);
            let clock = FakeClock::new();
            let stats = Arc::new(Recorded::default());
            let inject = Arc::new(AtomicBool::new(true));
            let (rates, rates_rx) = watch::channel(PublishRateLimit::default());
            let (handle, publisher) = Publisher::new(
                commands_tx,
                inject.clone(),
                rates_rx,
                stats.clone(),
                Arc::new(clock.clone()),
            );
            Self {
                handle,
                publisher: Some(publisher),
                commands,
                inject,
                rates,
                clock,
                stats,
            }
        }

        fn spawn(&mut self) -> JoinHandle<()> {
            tokio::spawn(
                self.publisher
                    .take()
                    .expect("spawn() is called once")
                    .run(Arc::default()),
            )
        }

        fn publisher(&mut self) -> &mut Publisher {
            self.publisher
                .as_mut()
                .expect("the publisher was not spawned")
        }

        /// One step with its command, if it sends one, answered with `result`. Only the step
        /// can finish the select: a step that sends nothing must not wait for a command.
        async fn step_answered(
            &mut self,
            item: PublishItem,
            result: Result<gossipsub::MessageId, PublishError>,
        ) -> Option<PublishOutcome> {
            let publisher = self
                .publisher
                .as_mut()
                .expect("the publisher was not spawned");
            let commands = &mut self.commands;
            tokio::select! {
                outcome = publisher.step(item) => outcome,
                () = async {
                    answer(commands, result).await;
                    std::future::pending().await
                } => unreachable!("only the step completes"),
            }
        }

        async fn step_accepted(&mut self, item: PublishItem) -> Option<PublishOutcome> {
            self.step_answered(item, Ok(accepted())).await
        }

        fn queued(&self) -> usize {
            self.handle.queue.lock().unwrap().len()
        }
    }

    /// Any id: the publisher only looks at whether the reply is `Ok`.
    fn accepted() -> gossipsub::MessageId {
        gossipsub::MessageId::from(&[0u8; 20][..])
    }

    #[tokio::test]
    async fn enqueue_returns_immediately_while_the_drain_task_is_blocked_on_gossipsub() {
        let mut h = Harness::new();
        h.spawn();
        h.handle.enqueue(item(Class::Small, 0));
        let BnCommand::Publish { reply: _held, .. } = h.commands.recv().await.unwrap() else {
            panic!("expected a Publish command");
        };

        let started = Instant::now();
        let outcomes: Vec<_> = (1..=100)
            .map(|n| h.handle.enqueue(item(Class::Small, n)))
            .collect();
        let elapsed = started.elapsed();

        assert!(elapsed < Duration::from_millis(20), "{elapsed:?}");
        assert!(outcomes.iter().all(|o| *o == EnqueueOutcome::Enqueued));
        assert_eq!(h.queued(), 100);
        assert_eq!(h.stats.total(), 0);
    }

    #[tokio::test]
    async fn inject_off_suppresses_and_counts_without_sending_a_command() {
        let mut h = Harness::new();
        h.inject.store(false, Ordering::Relaxed);

        let outcome = h.publisher().step(item(Class::Small, 0)).await;

        assert_eq!(outcome, Some(PublishOutcome::SuppressedInjectOff));
        assert_eq!(h.stats.count("suppressed_inject_off", Class::Small), 1);
        assert_eq!(h.stats.total(), 1);
        assert!(h.commands.try_recv().is_err());
    }

    /// The next command, which has to be a `Publish`, answered with `result`; returns the
    /// topic and payload it carried.
    async fn answer(
        commands: &mut mpsc::Receiver<BnCommand>,
        result: Result<gossipsub::MessageId, PublishError>,
    ) -> (String, Vec<u8>) {
        match commands.recv().await.unwrap() {
            BnCommand::Publish { topic, data, reply } => {
                reply.send(result).unwrap();
                (topic, data)
            }
            other => panic!("expected Publish, got {other:?}"),
        }
    }

    /// Yields to the drain task until `done` holds. No sleep: on the test runtime a yield is
    /// enough for the task to take its turn.
    async fn until(mut done: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while !done() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the drain task never got there");
    }

    #[tokio::test]
    async fn flipping_inject_on_at_runtime_resumes_publishing() {
        let mut h = Harness::new();
        h.inject.store(false, Ordering::Relaxed);
        h.spawn();
        h.handle.enqueue(item(Class::Small, 0));
        until(|| h.stats.count("suppressed_inject_off", Class::Small) == 1).await;

        h.inject.store(true, Ordering::Relaxed);
        h.handle.enqueue(item(Class::Small, 1));

        let (_, data) = answer(
            &mut h.commands,
            Ok(gossipsub::MessageId::from(&[0u8; 20][..])),
        )
        .await;
        assert_eq!(data, item(Class::Small, 1).payload);
        assert_eq!(h.stats.count("suppressed_inject_off", Class::Small), 1);
        assert!(h.commands.try_recv().is_err());
    }

    #[tokio::test]
    async fn small_beyond_8000_per_s_is_rate_limited_and_counted() {
        let mut h = Harness::new();
        for n in 0..8000 {
            let outcome = h.step_accepted(item(Class::Small, n)).await;
            assert_eq!(outcome, Some(PublishOutcome::Published), "item {n}");
        }

        let outcome = h.step_accepted(item(Class::Small, 8000)).await;

        assert_eq!(outcome, Some(PublishOutcome::RateLimited));
        assert_eq!(h.stats.count("rate_limited", Class::Small), 1);
        assert_eq!(h.stats.count("published", Class::Small), 8000);
        assert!(h.commands.try_recv().is_err());
        h.clock.advance(Duration::from_secs(1));
        let refilled = h.step_accepted(item(Class::Small, 8001)).await;
        assert_eq!(refilled, Some(PublishOutcome::Published));
    }

    #[tokio::test]
    async fn large_beyond_300_per_s_is_rate_limited_and_counted() {
        let mut h = Harness::new();
        for n in 0..300 {
            let outcome = h.step_accepted(item(Class::Large, n)).await;
            assert_eq!(outcome, Some(PublishOutcome::Published), "item {n}");
        }

        let outcome = h.step_accepted(item(Class::Large, 300)).await;

        assert_eq!(outcome, Some(PublishOutcome::RateLimited));
        assert_eq!(h.stats.count("rate_limited", Class::Large), 1);
        assert_eq!(h.stats.count("published", Class::Large), 300);
        assert!(h.commands.try_recv().is_err());
        // The small bucket is untouched.
        let small = h.step_accepted(item(Class::Small, 301)).await;
        assert_eq!(small, Some(PublishOutcome::Published));
    }

    const MIB: usize = 1024 * 1024;

    #[tokio::test]
    async fn bytes_bucket_limits_regardless_of_class() {
        let mut h = Harness::new();
        for n in 0..32 {
            let outcome = h.step_accepted(sized_item(Class::Large, n, MIB)).await;
            assert_eq!(outcome, Some(PublishOutcome::Published), "block {n}");
        }

        let outcome = h.step_accepted(sized_item(Class::Large, 32, MIB)).await;

        assert_eq!(outcome, Some(PublishOutcome::RateLimited));
        assert_eq!(h.stats.count("rate_limited", Class::Large), 1);
        // The large bucket still has tokens: a payload that costs no bytes goes through, and
        // the small class shares the empty bytes bucket.
        let free = h.step_accepted(sized_item(Class::Large, 33, 0)).await;
        assert_eq!(free, Some(PublishOutcome::Published));
        let small = h.step_accepted(sized_item(Class::Small, 34, 1)).await;
        assert_eq!(small, Some(PublishOutcome::RateLimited));
        assert_eq!(h.stats.count("rate_limited", Class::Small), 1);
    }

    #[tokio::test]
    async fn successful_publish_sends_publish_command_and_counts_bn_out() {
        let mut h = Harness::new();
        h.spawn();
        let block = item(Class::Large, 7);

        h.handle.enqueue(block.clone());

        let (topic, data) = answer(&mut h.commands, Ok(accepted())).await;
        assert_eq!(topic, BLOCK);
        assert_eq!(data, block.payload);
        until(|| h.stats.count("published", Class::Large) == 1).await;
        assert_eq!(h.stats.total(), 1);
        assert_eq!(h.queued(), 0);
    }

    /// The level of the log line is not asserted: the crate's shared subscriber captures
    /// INFO and up, so a debug line is invisible to it and an error line from a parallel
    /// test would be indistinguishable. The outcome and the counter say which path ran.
    #[tokio::test]
    async fn duplicate_error_from_gossipsub_is_counted_as_duplicate_not_error() {
        let mut h = Harness::new();

        let outcome = h
            .step_answered(item(Class::Small, 0), Err(PublishError::Duplicate))
            .await;

        assert_eq!(outcome, Some(PublishOutcome::Duplicate));
        assert_eq!(h.stats.count("error:duplicate", Class::Small), 1);
        assert_eq!(h.stats.total(), 1);
    }

    /// The `SUBS` race: a sibling routed on a subscription the beacon node has dropped. The
    /// log level is not asserted, for the reason given on the duplicate test.
    #[tokio::test]
    async fn no_subscribers_error_is_counted_under_reason_no_subscribers_and_logged_at_debug() {
        let mut h = Harness::new();

        let outcome = h
            .step_answered(
                item(Class::Small, 0),
                Err(PublishError::NoPeersSubscribedToTopic),
            )
            .await;

        assert_eq!(outcome, Some(PublishOutcome::NoSubscribers));
        assert_eq!(h.stats.count("error:no_subscribers", Class::Small), 1);
        assert_eq!(h.stats.total(), 1);
    }

    #[tokio::test]
    async fn other_gossipsub_errors_are_counted_by_reason() {
        let mut h = Harness::new();
        let refusals = [
            (PublishError::MessageTooLarge, "message_too_large"),
            (PublishError::AllQueuesFull(3), "all_queues_full"),
            (
                PublishError::TransformFailed(std::io::Error::other("bad snappy")),
                "transform_failed",
            ),
        ];

        for (n, (err, reason)) in refusals.into_iter().enumerate() {
            let outcome = h.step_answered(item(Class::Large, n), Err(err)).await;

            assert_eq!(outcome, Some(PublishOutcome::Error(reason)));
            assert_eq!(h.stats.count(&format!("error:{reason}"), Class::Large), 1);
        }
        assert_eq!(h.stats.total(), 3);
    }

    /// The whole path: an item enqueued on the handle reaches the fake beacon node through a
    /// real link. The fake's snappy transform decompresses it, so the bytes are compared
    /// after decompression and the id against T-012's function over the compressed form.
    #[tokio::test(flavor = "multi_thread")]
    async fn publish_reaches_fake_bn_with_identical_bytes() {
        let mut bn = FakeBn::start().await;
        let (commands, commands_rx) = mpsc::channel(64);
        let (spec, _) = spec_watch();
        let (_sets, sets) = watch::channel(SubscriptionSets::default());
        let lanes = ClassLanes::new(Arc::new(()));
        let mut link = BnLink::spawn(
            link_config(&bn),
            &node_key(&tempfile::tempdir().unwrap()),
            BnClient::new(bn.http_addr(), Duration::from_secs(2)),
            &mut Registry::default(),
            lanes.pusher(),
            spec,
            sets,
            commands_rx,
            Arc::default(),
        );
        let mut received = bn.received();
        bn.subscribe(BLOCK).await;
        tokio::time::timeout(WAIT, async {
            loop {
                match link.events.recv().await {
                    Some(BnEvent::Subscribed { topic, .. }) if topic == BLOCK => break,
                    Some(_) => {}
                    None => panic!("the link ended"),
                }
            }
        })
        .await
        .expect("the link never saw the fake subscribe");
        commands
            .send(BnCommand::Subscribe(BLOCK.to_owned()))
            .await
            .unwrap();
        bn.wait_for(|e| matches!(e, FakeBnEvent::Subscribed { topic, .. } if topic == BLOCK))
            .await;
        let clock = FakeClock::new();
        let (_rates, rates) = watch::channel(PublishRateLimit::default());
        let (handle, _task) = Publisher::spawn(
            commands,
            Arc::new(AtomicBool::new(true)),
            rates,
            Arc::new(()),
            Arc::new(clock),
            Arc::default(),
        );
        let compressed = snap::raw::Encoder::new().compress_vec(b"a block").unwrap();
        let id = msgid::compute(BLOCK, &compressed, wire::MAX_PAYLOAD_SIZE as usize).id;

        let outcome = handle.enqueue(PublishItem {
            topic: Topic::parse(BLOCK).unwrap(),
            id,
            payload: compressed.into(),
            class: Class::Large,
        });

        assert_eq!(outcome, EnqueueOutcome::Enqueued);
        let (topic, data, bn_id) = tokio::time::timeout(WAIT, received.recv())
            .await
            .expect("the fake never received the publish")
            .unwrap();
        assert_eq!(topic, BLOCK);
        assert_eq!(data, b"a block");
        assert_eq!(bn_id.0[..], id.0[..]);
    }

    /// An operator raises or lowers `bn.publish_rate_limit` and SIGHUPs; the new ceiling is
    /// what the next message is judged against.
    #[tokio::test]
    async fn a_changed_rate_limit_rebuilds_the_buckets() {
        let mut h = Harness::new();
        h.rates.send_replace(PublishRateLimit {
            small_per_s: 1,
            large_per_s: 1,
            bytes_per_s: 1024,
        });

        let first = h.step_accepted(item(Class::Small, 0)).await;
        let second = h.step_accepted(item(Class::Small, 1)).await;

        assert_eq!(first, Some(PublishOutcome::Published));
        assert_eq!(second, Some(PublishOutcome::RateLimited));
        assert_eq!(h.stats.count("rate_limited", Class::Small), 1);
    }
}
