//! What this host sends a peer, and the queue it waits in.
//!
//! Fanout (T-032) hands a frame to every target and moves on. Each peer has a task of its own
//! that opens a unidirectional stream per frame and writes it, so the sibling with the worst
//! congestion window delays nobody else (D17). Datagrams are T-062's.
//!
//! # Nothing on the send path waits for a peer
//!
//! [`SenderHandle::push`] takes a lock, moves a frame into a queue and returns. The only awaits
//! are in the drain task: the next frame, and the write it is making.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};
use std::time::{Duration, Instant};

use bytes::Bytes;
use overlay_core::roster::Hostname;
use overlay_core::topic::Class;
use tokio::sync::Notify;
use tokio::task::AbortHandle;

/// Frames one peer's small lane holds before the oldest one goes. Two seconds of batches at the
/// 300 a second §5.7 budgets for the small class, which covers a congestion event without
/// holding anything worth sending: a batch is stale after 1 s (T-061), and public gossip
/// carries what this lane drops.
pub const SMALL_LANE_FRAMES: usize = 600;

/// Bytes one peer's large lane holds before the oldest one goes. About five blocks, or the
/// columns of one slot for a single peer, which is as far behind as a peer that is still
/// keeping up can be: past that the frames at the back are for a slot that has moved on and
/// the beacon node has public gossip for them.
pub const LARGE_LANE_BYTES: usize = 1024 * 1024;

/// How old a large frame may be when the drain task reaches it. A block that has waited three
/// seconds is past the point where the beacon node can use it: the slot is over, and public
/// gossip has had that whole time to deliver the same block. Deliberately a constant and not a
/// config key; if the canary shows it needs tuning, the recorded fallback is a reloadable
/// `classes.large.stale_after_ms` mirroring the small class (D17).
pub const LARGE_STALE_AFTER: Duration = Duration::from_secs(3);

/// Large bytes queued across every peer before the oldest frame anywhere goes. Sixty-four peers
/// at the per-peer bound: a handful of slow siblings can each hold a full lane, and a fleet that
/// stalls all at once costs a bounded 64 MiB instead of growing until the cgroup kills the
/// sidecar (§5.7).
pub const LARGE_QUEUED_BYTES_MAX: usize = 64 * 1024 * 1024;

/// Why a frame never went out: the `reason` label of
/// `peer_queue_drops_total{peer, class, reason}` (§12).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DropReason {
    /// A bound was reached and this was the oldest frame under it.
    Full,
    /// A large frame was too old to be worth sending by the time the task reached it.
    Stale,
    /// The peer left the live set with the frame still queued.
    PeerDown,
}

impl DropReason {
    /// The label value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Stale => "stale",
            Self::PeerDown => "peer_down",
        }
    }
}

/// Where the send queues count, until T-041's registry exists. Every call happens with a lane
/// locked, so an implementation is a counter or a gauge and nothing slower. `()` counts nothing.
pub trait SenderStats: Send + Sync {
    /// `peer_queue_depth{peer, class, unit}`: what the lane holds now, in both units the gauge
    /// carries.
    fn queue_depth(&self, peer: &Hostname, class: Class, frames: usize, bytes: usize);

    /// `peer_queue_drops_total{peer, class, reason}`: one frame that will never be written.
    fn queue_drop(&self, peer: &Hostname, class: Class, reason: DropReason);
}

impl SenderStats for () {
    fn queue_depth(&self, _: &Hostname, _: Class, _: usize, _: usize) {}
    fn queue_drop(&self, _: &Hostname, _: Class, _: DropReason) {}
}

/// What one peer's sender writes on. The connection is behind a trait so a test can hold the
/// drain and let it go again; [`quinn::Connection`] is what the sidecar runs. One method,
/// because a stream per frame is all v1 sends (§7).
pub trait Transport: Send + Sync + 'static {
    /// Writes one encoded frame on a stream of its own. An error means the connection can carry
    /// nothing more and the sender stops.
    fn send(&self, frame: Bytes) -> impl Future<Output = std::io::Result<()>> + Send;
}

impl Transport for quinn::Connection {
    async fn send(&self, frame: Bytes) -> std::io::Result<()> {
        let mut stream = self.open_uni().await.map_err(std::io::Error::other)?;
        stream.write_all(&frame).await?;
        // `finish` only marks the end of the stream. Waiting for the peer to read it is what
        // this whole module exists to avoid.
        let _ = stream.finish();
        Ok(())
    }
}

/// The push found no queue to put the frame in, because the peer's task has gone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dropped;

/// A frame waiting its turn, in the bytes it will be written as: fanout encodes once for every
/// peer a message goes to, and what a lane bounds is what its queue costs in memory.
struct Queued {
    frame: Bytes,
    enqueued_at: Instant,
}

/// One lane of one peer: the frames and the bytes they add up to, which the byte bound and the
/// `unit="bytes"` gauge both read.
#[derive(Default)]
struct Lane {
    frames: VecDeque<Queued>,
    bytes: usize,
}

impl Lane {
    fn push(&mut self, queued: Queued) {
        self.bytes += queued.frame.len();
        self.frames.push_back(queued);
    }

    fn pop(&mut self) -> Option<Queued> {
        let queued = self.frames.pop_front()?;
        self.bytes -= queued.frame.len();
        Some(queued)
    }
}

/// The process-wide budget for queued large bytes, shared by every peer's large lane.
pub struct LargeLedger {
    cap: usize,
    registry: Mutex<Registry>,
}

/// What the ledger knows: the bytes queued across every peer, and the lanes holding them.
#[derive(Default)]
struct Registry {
    queued: usize,
    lanes: Vec<Weak<Queues>>,
}

impl Registry {
    /// Drops the frame that has waited longest anywhere in the fleet, and says whether there
    /// was one. A scan of every lane rather than a heap: it runs only when the process is at
    /// its budget, and a few hundred lanes is a few hundred comparisons.
    fn evict_oldest(&mut self) -> bool {
        let mut oldest: Option<(Arc<Queues>, Instant)> = None;
        for weak in &self.lanes {
            let Some(queues) = weak.upgrade() else {
                continue;
            };
            let front = queues
                .lane(Class::Large)
                .frames
                .front()
                .map(|queued| queued.enqueued_at);
            let Some(front) = front else { continue };
            if oldest.as_ref().is_none_or(|(_, best)| front < *best) {
                oldest = Some((queues, front));
            }
        }
        let Some((queues, _)) = oldest else {
            return false;
        };
        let mut lane = queues.lane(Class::Large);
        let Some(dropped) = lane.pop() else {
            return false;
        };
        self.queued -= dropped.frame.len();
        queues
            .stats
            .queue_drop(&queues.peer, Class::Large, DropReason::Full);
        queues.depth(Class::Large, &lane);
        true
    }
}

impl LargeLedger {
    /// An empty ledger holding `cap` bytes across every peer. The sidecar passes
    /// [`LARGE_QUEUED_BYTES_MAX`]; a test passes less, so the eviction is reachable without
    /// queueing 64 MiB of frames.
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            registry: Mutex::new(Registry::default()),
        }
    }

    /// The registry, recovering the guard from a poisoned lock: nothing between the lock and
    /// its release can panic, so the accounting is whole, and refusing to queue afterwards
    /// would stop the overlay sending for a reason unrelated to it.
    fn registry(&self) -> MutexGuard<'_, Registry> {
        self.registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Remembers `queues` so its lane can be drawn on when the budget is reached, and forgets
    /// the peers that have gone since the last one connected.
    fn register(&self, queues: &Arc<Queues>) {
        let mut registry = self.registry();
        registry
            .lanes
            .retain(|lane| lane.upgrade().is_some_and(|queues| !queues.gone()));
        registry.lanes.push(Arc::downgrade(queues));
    }

    /// Queues `queued` on `queues`' large lane. The ledger's lock is taken before the lane's,
    /// everywhere, which is what keeps two peers queueing at once from deadlocking.
    fn push(&self, queues: &Queues, queued: Queued) {
        let mut registry = self.registry();
        let mut lane = queues.lane(Class::Large);
        while lane.bytes + queued.frame.len() > LARGE_LANE_BYTES {
            let Some(dropped) = lane.pop() else { break };
            registry.queued -= dropped.frame.len();
            queues
                .stats
                .queue_drop(&queues.peer, Class::Large, DropReason::Full);
        }
        registry.queued += queued.frame.len();
        lane.push(queued);
        queues.depth(Class::Large, &lane);
        drop(lane);
        while registry.queued > self.cap && registry.evict_oldest() {}
    }

    /// Takes the oldest frame off `queues`' large lane.
    fn pop(&self, queues: &Queues) -> Option<Queued> {
        let mut registry = self.registry();
        let mut lane = queues.lane(Class::Large);
        let queued = lane.pop()?;
        registry.queued -= queued.frame.len();
        queues.depth(Class::Large, &lane);
        Some(queued)
    }
}

/// What every peer's sender shares.
#[derive(Clone)]
pub struct Deps {
    /// The process-wide budget for what every peer's large lane holds (D17).
    pub ledger: Arc<LargeLedger>,
    /// Where `peer_queue_depth` and `peer_queue_drops_total` land.
    pub stats: Arc<dyn SenderStats>,
}

/// One peer's two lanes and everything the task draining them holds.
struct Queues {
    peer: Hostname,
    small: Mutex<Lane>,
    large: Mutex<Lane>,
    ledger: Arc<LargeLedger>,
    stats: Arc<dyn SenderStats>,
    /// Woken by every push, awaited by the task whenever both lanes are empty.
    waiting: Notify,
    closed: AtomicBool,
    /// Set once, in [`PeerSender::spawn`], as soon as there is a task to name.
    task: OnceLock<AbortHandle>,
}

impl Queues {
    /// The lane for `class`, recovering the guard from a poisoned lock for the reason
    /// [`LargeLedger::registry`] gives.
    fn lane(&self, class: Class) -> MutexGuard<'_, Lane> {
        let lane = match class {
            Class::Small => &self.small,
            Class::Large => &self.large,
        };
        lane.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Sets `peer_queue_depth` for one lane, in both units the gauge carries. Called with the
    /// lane still locked, so what it reports is what the lane held at that moment.
    fn depth(&self, class: Class, lane: &Lane) {
        self.stats
            .queue_depth(&self.peer, class, lane.frames.len(), lane.bytes);
    }

    /// Whether this peer's task has stopped, so a push has nowhere to go.
    fn gone(&self) -> bool {
        self.closed.load(Ordering::Relaxed) || self.task.get().is_some_and(AbortHandle::is_finished)
    }

    fn push(&self, class: Class, frame: Bytes, now: Instant) {
        let queued = Queued {
            frame,
            enqueued_at: now,
        };
        match class {
            Class::Small => {
                let mut lane = self.lane(Class::Small);
                while lane.frames.len() >= SMALL_LANE_FRAMES && lane.pop().is_some() {
                    self.stats
                        .queue_drop(&self.peer, Class::Small, DropReason::Full);
                }
                lane.push(queued);
                self.depth(Class::Small, &lane);
            }
            Class::Large => self.ledger.push(self, queued),
        }
        self.waiting.notify_one();
    }

    /// The next frame to write: from the large lane while it has one that is still worth
    /// sending at `now`, then from the small lane. Large first, because a block waiting behind
    /// a second of attestations is a block that arrives after the slot it belongs to (D17).
    fn next(&self, now: Instant) -> Option<Bytes> {
        while let Some(queued) = self.ledger.pop(self) {
            if now.saturating_duration_since(queued.enqueued_at) <= LARGE_STALE_AFTER {
                return Some(queued.frame);
            }
            self.stats
                .queue_drop(&self.peer, Class::Large, DropReason::Stale);
        }
        let mut lane = self.lane(Class::Small);
        let queued = lane.pop()?;
        self.depth(Class::Small, &lane);
        Some(queued.frame)
    }
}

/// One peer's send queues, as the live view hands them out. Cloning one is an `Arc` clone,
/// because every snapshot of the live view carries it.
///
/// The task's life is the peers table's, not the last clone's: a route plan holding a snapshot
/// of a peer that has gone keeps this handle alive, and every push to it is [`Dropped`].
#[derive(Clone)]
pub struct SenderHandle(Arc<Queues>);

impl SenderHandle {
    /// Queues `frame` for `class`'s lane, without waiting for anything. `now` is when the frame
    /// entered, which the age bound reads back when the task reaches it.
    pub fn push(&self, class: Class, frame: Bytes, now: Instant) -> Result<(), Dropped> {
        if self.0.gone() {
            return Err(Dropped);
        }
        self.0.push(class, frame, now);
        Ok(())
    }

    /// Stops the peer's task and refuses every later push. The manager calls it where the peer
    /// leaves the live set, which is the one place that knows it has.
    pub fn stop(&self) {
        if self.0.closed.swap(true, Ordering::Relaxed) {
            return;
        }
        if let Some(task) = self.0.task.get() {
            task.abort();
        }
    }
}

impl std::fmt::Debug for SenderHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SenderHandle")
            .field("peer", &self.0.peer)
            .field("running", &!self.0.gone())
            .finish()
    }
}

/// One peer's sender: the lanes and the task that drains them.
pub struct PeerSender;

impl PeerSender {
    /// Starts writing what is queued for `peer` on `transport`.
    pub fn spawn<T: Transport>(peer: Hostname, transport: T, deps: Deps) -> SenderHandle {
        let queues = Arc::new(Queues {
            peer,
            small: Mutex::new(Lane::default()),
            large: Mutex::new(Lane::default()),
            ledger: deps.ledger.clone(),
            stats: deps.stats,
            waiting: Notify::new(),
            closed: AtomicBool::new(false),
            task: OnceLock::new(),
        });
        deps.ledger.register(&queues);
        let task = tokio::spawn(drain(queues.clone(), transport));
        let _ = queues.task.set(task.abort_handle());
        SenderHandle(queues)
    }
}

/// One peer's writer. The two awaits are the next frame and the write in flight, so a peer that
/// has stopped reading holds up its own queue and nothing else.
async fn drain<T: Transport>(queues: Arc<Queues>, transport: T) {
    loop {
        // The runtime's clock rather than the system's, so a test can put a frame past the age
        // bound without waiting three seconds for it.
        let now = tokio::time::Instant::now().into_std();
        let Some(frame) = queues.next(now) else {
            queues.waiting.notified().await;
            continue;
        };
        if let Err(error) = transport.send(frame).await {
            tracing::debug!(peer = %queues.peer, %error, "connection carries no more frames");
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use overlay_core::roster::Hostname;

    use super::*;
    use crate::testutil::{CountingStats, eventually};

    /// A frame numbered `n`, so a test can tell which ones survived and in what order.
    fn frame(n: usize) -> Bytes {
        frame_of(n, size_of::<usize>())
    }

    /// The same, of a size a byte bound notices.
    fn frame_of(n: usize, bytes: usize) -> Bytes {
        let mut frame = vec![0; bytes];
        frame[..size_of::<usize>()].copy_from_slice(&n.to_le_bytes());
        Bytes::from(frame)
    }

    fn number(frame: &Bytes) -> usize {
        let mut bytes = [0; size_of::<usize>()];
        bytes.copy_from_slice(&frame[..size_of::<usize>()]);
        usize::from_le_bytes(bytes)
    }

    /// A transport a test holds and lets go: `send` waits for a permit, so a sender built on
    /// [`Link::stalled`] queues everything and writes nothing until the test says otherwise.
    #[derive(Clone)]
    struct Link(Arc<LinkState>);

    struct LinkState {
        permits: tokio::sync::Semaphore,
        sent: Mutex<Vec<Bytes>>,
    }

    impl Link {
        fn open() -> Self {
            Self::with_permits(tokio::sync::Semaphore::MAX_PERMITS)
        }

        /// A transport that writes nothing until [`release`](Self::release), which is a peer
        /// whose congestion window has closed.
        fn stalled() -> Self {
            Self::with_permits(0)
        }

        fn release(&self) {
            self.0
                .permits
                .add_permits(tokio::sync::Semaphore::MAX_PERMITS);
        }

        fn with_permits(permits: usize) -> Self {
            Self(Arc::new(LinkState {
                permits: tokio::sync::Semaphore::new(permits),
                sent: Mutex::new(Vec::new()),
            }))
        }

        fn sent(&self) -> Vec<Bytes> {
            self.0
                .sent
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }

        fn numbers(&self) -> Vec<usize> {
            self.sent().iter().map(number).collect()
        }
    }

    impl Transport for Link {
        async fn send(&self, frame: Bytes) -> std::io::Result<()> {
            self.0
                .permits
                .acquire()
                .await
                .map_err(std::io::Error::other)?
                .forget();
            self.0
                .sent
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(frame);
            Ok(())
        }
    }

    fn peer() -> Hostname {
        host("bn-01")
    }

    fn host(name: &str) -> Hostname {
        Hostname(name.to_owned())
    }

    /// A sender on `link`, with the counters a test reads its drops and depths from.
    fn sender(link: &Link) -> (SenderHandle, Arc<CountingStats>) {
        let stats = Arc::new(CountingStats::default());
        let ledger = Arc::new(LargeLedger::new(LARGE_QUEUED_BYTES_MAX));
        (sender_on(&ledger, &stats, peer(), link), stats)
    }

    /// Waits for `ready` and fails rather than hanging, and never later than `bound`: the two
    /// tests about a stalled peer assert wall-clock times, so this one polls the real clock
    /// tightly enough that the polling is not what they measure.
    async fn within(bound: Duration, what: &str, mut ready: impl FnMut() -> bool) {
        let poll = async {
            while !ready() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        };
        tokio::time::timeout(bound, poll)
            .await
            .unwrap_or_else(|_| panic!("{what} did not happen within {bound:?}"));
    }

    /// One more sender under the same ledger and counters, for the bounds that span peers.
    fn sender_on(
        ledger: &Arc<LargeLedger>,
        stats: &Arc<CountingStats>,
        peer: Hostname,
        link: &Link,
    ) -> SenderHandle {
        let deps = Deps {
            ledger: ledger.clone(),
            stats: stats.clone(),
        };
        PeerSender::spawn(peer, link.clone(), deps)
    }

    /// The small lane is bounded by frames, and what goes when it is full is the oldest one: an
    /// attestation the peer has not taken in two seconds is worth less than the one that just
    /// arrived (D17).
    #[tokio::test]
    async fn small_lane_drops_the_oldest_frame_when_full_and_counts_full() {
        let link = Link::open();
        let (sender, stats) = sender(&link);
        let now = Instant::now();

        // Nothing between the pushes awaits, so the drain task cannot take a frame out from
        // under them: the lane really holds every one of these at once.
        for n in 0..=SMALL_LANE_FRAMES {
            sender.push(Class::Small, frame(n), now).unwrap();
        }

        assert_eq!(
            stats.queue_drops(&peer(), Class::Small, DropReason::Full),
            1
        );
        eventually("the lane to drain", || {
            link.sent().len() == SMALL_LANE_FRAMES
        })
        .await;
        assert_eq!(link.numbers(), (1..=SMALL_LANE_FRAMES).collect::<Vec<_>>());
    }

    /// The large lane is bounded by bytes rather than frames, because one block is worth six
    /// hundred attestations, and the oldest goes first for the same reason the small lane's
    /// does (D17).
    #[tokio::test]
    async fn large_lane_drops_the_oldest_when_bytes_exceed_1mib_and_counts_full() {
        let link = Link::open();
        let (sender, stats) = sender(&link);
        let now = Instant::now();
        let quarter = LARGE_LANE_BYTES / 4;

        for n in 0..5 {
            sender
                .push(Class::Large, frame_of(n, quarter), now)
                .unwrap();
        }

        assert_eq!(
            stats.queue_drops(&peer(), Class::Large, DropReason::Full),
            1
        );
        eventually("the lane to drain", || link.sent().len() == 4).await;
        assert_eq!(link.numbers(), vec![1, 2, 3, 4]);
    }

    /// The age bound is read at dequeue and not at push, because what matters is how old the
    /// frame is when it would go on the wire (D17). The frame behind it is younger and goes.
    #[tokio::test(start_paused = true)]
    async fn large_frame_older_than_3s_at_dequeue_is_dropped_and_counted_stale() {
        let link = Link::open();
        let (sender, stats) = sender(&link);
        let start = tokio::time::Instant::now().into_std();

        sender.push(Class::Large, frame(0), start).unwrap();
        sender
            .push(Class::Large, frame(1), start + Duration::from_secs(2))
            .unwrap();
        tokio::time::advance(LARGE_STALE_AFTER + Duration::from_millis(1)).await;

        eventually("both frames to be dealt with", || {
            link.sent().len() as u64 + stats.queue_drops(&peer(), Class::Large, DropReason::Stale)
                == 2
        })
        .await;
        assert_eq!(link.numbers(), vec![1]);
        assert_eq!(
            stats.queue_drops(&peer(), Class::Large, DropReason::Stale),
            1
        );
    }

    /// One peer's lane is not the bound that matters when a hundred of them are slow at once:
    /// the process holds 64 MiB across every large lane, and the frame that goes to make room
    /// is the oldest anywhere, not the oldest on the lane being pushed to (D17).
    #[tokio::test(start_paused = true)]
    async fn process_wide_large_cap_evicts_the_oldest_frame_across_peers() {
        let size = LARGE_LANE_BYTES / 4;
        let ledger = Arc::new(LargeLedger::new(2 * size));
        let stats = Arc::new(CountingStats::default());
        let (slow, fast) = (host("bn-01"), host("bn-02"));
        let (slow_link, fast_link) = (Link::stalled(), Link::stalled());
        let slow_sender = sender_on(&ledger, &stats, slow.clone(), &slow_link);
        let fast_sender = sender_on(&ledger, &stats, fast.clone(), &fast_link);
        let start = tokio::time::Instant::now().into_std();

        slow_sender
            .push(Class::Large, frame_of(0, size), start)
            .unwrap();
        fast_sender
            .push(
                Class::Large,
                frame_of(1, size),
                start + Duration::from_millis(1),
            )
            .unwrap();
        fast_sender
            .push(
                Class::Large,
                frame_of(2, size),
                start + Duration::from_millis(2),
            )
            .unwrap();

        assert_eq!(stats.queue_drops(&slow, Class::Large, DropReason::Full), 1);
        assert_eq!(stats.queue_drops(&fast, Class::Large, DropReason::Full), 0);
        slow_link.release();
        fast_link.release();
        eventually("what is left to go out", || fast_link.sent().len() == 2).await;
        assert_eq!(fast_link.numbers(), vec![1, 2]);
        assert!(slow_link.sent().is_empty());
    }

    /// The point of a queue per peer: the sibling that has stopped reading holds up its own
    /// frames and nobody else's, where one shared writer would have every peer waiting on the
    /// slowest congestion window (§5.7).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stalled_peer_does_not_delay_delivery_to_a_fast_peer() {
        let ledger = Arc::new(LargeLedger::new(LARGE_QUEUED_BYTES_MAX));
        let stats = Arc::new(CountingStats::default());
        let (stalled_link, fast_link) = (Link::stalled(), Link::open());
        let stalled = sender_on(&ledger, &stats, host("bn-01"), &stalled_link);
        let fast = sender_on(&ledger, &stats, host("bn-02"), &fast_link);
        let now = Instant::now();

        for n in 0..10 {
            stalled.push(Class::Large, frame(n), now).unwrap();
            fast.push(Class::Large, frame(n), now).unwrap();
        }

        within(
            Duration::from_millis(50),
            "the fast peer to get them all",
            || fast_link.sent().len() == 10,
        )
        .await;
        assert!(stalled_link.sent().is_empty());
    }

    /// Large before small whenever both are waiting (D17): a block queued behind a second of
    /// attestations arrives after the slot it belongs to, and the attestations lose nothing by
    /// going second.
    #[tokio::test]
    async fn large_lane_is_drained_before_small_when_both_are_pending() {
        let link = Link::stalled();
        let (sender, _) = sender(&link);
        let now = Instant::now();

        sender.push(Class::Small, frame(0), now).unwrap();
        sender.push(Class::Large, frame(1), now).unwrap();
        sender.push(Class::Small, frame(2), now).unwrap();
        link.release();

        eventually("all three to go out", || link.sent().len() == 3).await;
        assert_eq!(link.numbers(), vec![1, 0, 2]);
    }

    /// `peer_queue_depth` is how a slow sibling is spotted in production (§12), so it has to
    /// follow both lanes in both units, and come back down as the queue drains.
    #[tokio::test]
    async fn depth_gauges_track_frames_and_bytes() {
        let link = Link::stalled();
        let (sender, stats) = sender(&link);
        let now = Instant::now();

        sender.push(Class::Small, frame_of(0, 100), now).unwrap();
        sender.push(Class::Small, frame_of(1, 100), now).unwrap();
        sender.push(Class::Large, frame_of(2, 4096), now).unwrap();

        assert_eq!(stats.queue_depth(&peer(), Class::Small), (2, 200));
        assert_eq!(stats.queue_depth(&peer(), Class::Large), (1, 4096));

        link.release();
        eventually("the lanes to drain", || link.sent().len() == 3).await;
        assert_eq!(stats.queue_depth(&peer(), Class::Small), (0, 0));
        assert_eq!(stats.queue_depth(&peer(), Class::Large), (0, 0));
    }

    /// A peer that has gone takes its queue with it: the frames waiting for it are counted
    /// where an operator can see what the disconnection cost, rather than disappearing with
    /// the task (D15).
    #[tokio::test]
    async fn sender_task_exits_on_down_and_pending_frames_of_both_lanes_are_counted_peer_down() {
        let link = Link::stalled();
        let (sender, stats) = sender(&link);
        let now = Instant::now();
        sender.push(Class::Small, frame(0), now).unwrap();
        sender.push(Class::Small, frame(1), now).unwrap();
        sender.push(Class::Large, frame(2), now).unwrap();

        sender.stop();

        assert_eq!(
            stats.queue_drops(&peer(), Class::Small, DropReason::PeerDown),
            2
        );
        assert_eq!(
            stats.queue_drops(&peer(), Class::Large, DropReason::PeerDown),
            1
        );
        assert_eq!(sender.push(Class::Small, frame(3), now), Err(Dropped));
        link.release();
        eventually("the task to end", || {
            sender.0.task.get().is_some_and(AbortHandle::is_finished)
        })
        .await;
        assert!(link.sent().is_empty());
    }
}
