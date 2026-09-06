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
use std::time::Instant;

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
    registry: Mutex<Registry>,
}

/// What the ledger knows: the bytes queued across every peer, and the lanes holding them.
#[derive(Default)]
struct Registry {
    queued: usize,
    lanes: Vec<Weak<Queues>>,
}

impl LargeLedger {
    /// An empty ledger.
    pub fn new() -> Self {
        Self {
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
        registry.queued += queued.frame.len();
        lane.push(queued);
    }

    /// Takes the oldest frame off `queues`' large lane.
    fn pop(&self, queues: &Queues) -> Option<Queued> {
        let mut registry = self.registry();
        let mut lane = queues.lane(Class::Large);
        let queued = lane.pop()?;
        registry.queued -= queued.frame.len();
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

    /// Whether this peer's task has stopped, so a push has nowhere to go.
    fn gone(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
            || self.task.get().is_some_and(AbortHandle::is_finished)
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
            }
            Class::Large => self.ledger.push(self, queued),
        }
        self.waiting.notify_one();
    }

    /// The next frame to write: from the large lane while it has one, then from the small lane.
    /// Large first, because a block waiting behind a second of attestations is a block that
    /// arrives after the slot it belongs to (D17).
    fn next(&self) -> Option<Bytes> {
        if let Some(queued) = self.ledger.pop(self) {
            return Some(queued.frame);
        }
        Some(self.lane(Class::Small).pop()?.frame)
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
        let Some(frame) = queues.next() else {
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
        Hostname("bn-01".to_owned())
    }

    /// A sender on `link`, with the counters a test reads its drops and depths from.
    fn sender(link: &Link) -> (SenderHandle, Arc<CountingStats>) {
        let stats = Arc::new(CountingStats::default());
        let deps = Deps {
            ledger: Arc::new(LargeLedger::new()),
            stats: stats.clone(),
        };
        (PeerSender::spawn(peer(), link.clone(), deps), stats)
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

        assert_eq!(stats.queue_drops(&peer(), Class::Large, DropReason::Full), 1);
        eventually("the lane to drain", || link.sent().len() == 4).await;
        assert_eq!(link.numbers(), vec![1, 2, 3, 4]);
    }
}
