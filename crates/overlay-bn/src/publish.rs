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

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use libp2p::gossipsub::PublishError;
use overlay_core::pubqueue::{DropReason, PublishItem, PublishQueue, Pushed, QueueStats};
use overlay_core::ratelimit::PublishLimits;
use overlay_core::time::Clock;
use overlay_core::topic::Class;
use tokio::sync::{Notify, mpsc, oneshot};
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

/// The drain task. [`spawn`](Self::spawn) starts it; it ends when the link's command channel
/// closes, because a publish can then never be answered.
pub struct Publisher {
    queue: PublishHandle,
    commands: mpsc::Sender<BnCommand>,
    inject: Arc<AtomicBool>,
    limits: PublishLimits,
    stats: Arc<dyn PublishStats>,
}

impl Publisher {
    /// Builds the queue and starts draining it into `commands`. The handle is what T-032,
    /// T-062 and T-074 hold; the task keeps going until the link is gone. `inject` is the
    /// kill switch, shared with whoever flips it (config, SIGHUP, `fleet-overlayctl`); it is
    /// read per item, so flipping it back on resumes without a restart. `limits` are
    /// [`PublishLimits::new`] from `bn.publish_rate_limit`.
    pub fn spawn(
        commands: mpsc::Sender<BnCommand>,
        inject: Arc<AtomicBool>,
        limits: PublishLimits,
        stats: Arc<dyn PublishStats>,
        clock: Arc<dyn Clock>,
    ) -> (PublishHandle, JoinHandle<()>) {
        let (handle, publisher) = Self::new(commands, inject, limits, stats, clock);
        (handle, tokio::spawn(publisher.run()))
    }

    fn new(
        commands: mpsc::Sender<BnCommand>,
        inject: Arc<AtomicBool>,
        limits: PublishLimits,
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
        let publisher = Self {
            queue: handle.clone(),
            commands,
            inject,
            limits,
            stats,
        };
        (handle, publisher)
    }

    async fn run(mut self) {
        loop {
            match self.queue.pop() {
                Some(item) => {
                    if self.step(item).await.is_none() {
                        return;
                    }
                }
                None => self.queue.wake.notified().await,
            }
        }
    }

    /// Publishes one item and reports what became of it. `None` means the link is gone:
    /// the command could not be delivered or its reply was dropped.
    async fn step(&mut self, item: PublishItem) -> Option<PublishOutcome> {
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
            Err(err) => {
                let reason = reason(&err);
                tracing::warn!(%err, id = %item.id, topic = %item.topic, "publish refused");
                self.stats.error(class, reason);
                PublishOutcome::Error(reason)
            }
        };
        Some(outcome)
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
    use overlay_core::msgid::MessageId;
    use overlay_core::pubqueue::PublishItem;
    use overlay_core::ratelimit::PublishLimits;
    use overlay_core::time::FakeClock;
    use overlay_core::topic::{Class, Topic};
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;

    use super::*;
    use crate::link::BnCommand;

    const ATTESTATION_3: &str = "/eth2/00000000/beacon_attestation_3/ssz_snappy";
    const BLOCK: &str = "/eth2/00000000/beacon_block/ssz_snappy";

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
            let limits = PublishLimits::new(&PublishRateLimit::default(), clock.now());
            let (handle, publisher) = Publisher::new(
                commands_tx,
                inject.clone(),
                limits,
                stats.clone(),
                Arc::new(clock.clone()),
            );
            Self {
                handle,
                publisher: Some(publisher),
                commands,
                inject,
                clock,
                stats,
            }
        }

        fn spawn(&mut self) -> JoinHandle<()> {
            tokio::spawn(self.publisher.take().expect("spawn() is called once").run())
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
}
