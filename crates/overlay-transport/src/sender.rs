//! What this host sends a peer, and the queue it waits in.
//!
//! Fanout (T-032) hands a frame to every target and moves on. Each peer has a task of its own
//! that opens a unidirectional stream per frame and writes it, so the sibling with the worst
//! congestion window delays nobody else (D17). A small-class batch goes out of the same task as
//! an unreliable datagram instead (§5.3), and falls back to a stream when the path turns out not
//! to hold it.
//!
//! # What a lane holds, and why the two carriers differ
//!
//! A stream frame is encoded once by whoever routed it, because the same bytes go to every
//! target, and each lane holds a refcounted clone of them ([`SenderHandle::push`]). A batch is
//! one destination's alone, so encoding it early would buy nothing and would cost the second
//! stale check its entries: D21 has the sender walk them again at dequeue, since a flush can
//! wait here long enough to age out on the way. So [`SenderHandle::push_batch`] queues the
//! entries and the drain task encodes them, as a datagram with no length prefix or, on a stream,
//! with one. Either way a lane's byte count is what its contents cost in memory.
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
use overlay_core::batch::{self, Carrier, Flush};
use overlay_core::roster::Hostname;
use overlay_core::topic::Class;
use overlay_core::wire::{
    BATCH_ENTRY_OVERHEAD_BYTES, BATCH_HEADER_BYTES, encode_datagram, encode_stream,
};
use quinn::SendDatagramError;
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

/// Which of D21's two age checks threw a batch entry away: the `reason` label of
/// `stale_dropped_total{class, reason}` (§12).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StaleReason {
    /// The batcher, on its way to closing the batch.
    Flush,
    /// The peer's sender, when it finally reached the batch.
    Dequeue,
}

impl StaleReason {
    /// The label value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Flush => "flush",
            Self::Dequeue => "dequeue",
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

    /// `stale_dropped_total{class="small", reason}`: batch entries too old to be worth
    /// delivering (D21). The class is always the small one, because batching is the small
    /// class's alone (§5.4), and the count is per check rather than per entry so a batch that
    /// aged out whole costs one call.
    fn stale_dropped(&self, reason: StaleReason, entries: usize);
}

impl SenderStats for () {
    fn queue_depth(&self, _: &Hostname, _: Class, _: usize, _: usize) {}
    fn queue_drop(&self, _: &Hostname, _: Class, _: DropReason) {}
    fn stale_dropped(&self, _: StaleReason, _: usize) {}
}

/// What one peer's sender writes on. The connection is behind a trait so a test can hold the
/// drain and let it go again; [`quinn::Connection`] is what the sidecar runs.
pub trait Transport: Send + Sync + 'static {
    /// Writes one encoded frame on a stream of its own. An error means the connection can carry
    /// nothing more and the sender stops.
    fn send(&self, frame: Bytes) -> impl Future<Output = std::io::Result<()>> + Send;

    /// Hands one encoded frame to the path as an unreliable datagram. Not a future: a datagram
    /// is taken or refused there and then, with no window to wait behind, which is the property
    /// the small class travels this way for (§5.3).
    fn send_datagram(&self, frame: Bytes) -> Result<(), SendDatagramError>;
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

    fn send_datagram(&self, frame: Bytes) -> Result<(), SendDatagramError> {
        quinn::Connection::send_datagram(self, frame)
    }
}

/// The push found no queue to put the frame in, because the peer's task has gone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dropped;

/// Something waiting its turn on a lane, and when it started waiting.
struct Queued {
    waiting: Waiting,
    enqueued_at: Instant,
}

/// What a lane holds: a frame already encoded for every peer it goes to, or one destination's
/// batch, still as entries so the second stale check has something to walk (D21).
enum Waiting {
    /// The bytes a stream carries, length prefix included.
    Frame(Bytes),
    /// A flushed batch and the age bound it was collected under.
    Batch { flush: Flush, stale_after: Duration },
}

impl Waiting {
    /// What it costs in memory, which is what a lane's byte bound and the `unit="bytes"` gauge
    /// are against. A batch counts what it will encode to, so the two carriers are comparable.
    fn bytes(&self) -> usize {
        match self {
            Self::Frame(frame) => frame.len(),
            Self::Batch { flush, .. } => flush
                .entries
                .iter()
                .map(|entry| BATCH_ENTRY_OVERHEAD_BYTES + entry.payload.len())
                .sum::<usize>()
                .saturating_add(BATCH_HEADER_BYTES),
        }
    }
}

/// What one lane holds, in both units `peer_queue_depth{unit}` carries. The gauge and
/// [`SenderHandle::depth`] are the two readers and both take it from the same lane, so
/// `eth-gossip-overlayctl status` and the dashboard cannot disagree about a peer (T-042).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Depth {
    /// Whole frames waiting.
    pub frames: usize,
    /// What they add up to, which is what the lane's byte bound is against.
    pub bytes: usize,
}

/// One lane of one peer: the frames and the bytes they add up to, which the byte bound and the
/// `unit="bytes"` gauge both read.
#[derive(Default)]
struct Lane {
    frames: VecDeque<Queued>,
    bytes: usize,
}

impl Lane {
    fn depth(&self) -> Depth {
        Depth {
            frames: self.frames.len(),
            bytes: self.bytes,
        }
    }

    fn push(&mut self, queued: Queued) {
        self.bytes += queued.waiting.bytes();
        self.frames.push_back(queued);
    }

    fn pop(&mut self) -> Option<Queued> {
        let queued = self.frames.pop_front()?;
        self.bytes -= queued.waiting.bytes();
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
    /// The lane holding the frame that has waited longest anywhere in the fleet. A scan of
    /// every lane rather than a heap: it runs only when the process is at its budget, and a few
    /// hundred lanes is a few hundred comparisons.
    fn oldest_lane(&self) -> Option<Arc<Queues>> {
        self.lanes
            .iter()
            .filter_map(|weak| {
                let queues = weak.upgrade()?;
                let front = queues.lane(Class::Large).frames.front()?.enqueued_at;
                Some((queues, front))
            })
            .min_by_key(|(_, front)| *front)
            .map(|(queues, _)| queues)
    }

    /// Drops that frame, and says whether there was one.
    // mutants::skip: the `-> true` mutant spins the caller forever, because the loop asks this
    // to free bytes and takes the answer for it; a hang is the one outcome no test can tell
    // from a slow suite (MD-02). The scan it delegates to is mutated and under test.
    #[cfg_attr(test, mutants::skip)]
    fn evict_oldest(&mut self) -> bool {
        let Some(queues) = self.oldest_lane() else {
            return false;
        };
        let mut lane = queues.lane(Class::Large);
        let Some(dropped) = lane.pop() else {
            return false;
        };
        self.queued -= dropped.waiting.bytes();
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
        while lane.bytes + queued.waiting.bytes() > LARGE_LANE_BYTES {
            let Some(dropped) = lane.pop() else { break };
            registry.queued -= dropped.waiting.bytes();
            queues
                .stats
                .queue_drop(&queues.peer, Class::Large, DropReason::Full);
        }
        registry.queued += queued.waiting.bytes();
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
        registry.queued -= queued.waiting.bytes();
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
    /// Whether this connection has already had its line about a peer that takes no datagrams.
    /// A misconfigured transport at the other end is one log line, not one per batch.
    warned_no_datagrams: AtomicBool,
    /// Set once, in [`PeerSender::spawn`], as soon as there is a task to name.
    task: OnceLock<AbortHandle>,
}

impl Queues {
    fn new(peer: Hostname, deps: Deps) -> Self {
        Self {
            peer,
            small: Mutex::new(Lane::default()),
            large: Mutex::new(Lane::default()),
            ledger: deps.ledger,
            stats: deps.stats,
            waiting: Notify::new(),
            closed: AtomicBool::new(false),
            warned_no_datagrams: AtomicBool::new(false),
            task: OnceLock::new(),
        }
    }

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
        let depth = lane.depth();
        self.stats
            .queue_depth(&self.peer, class, depth.frames, depth.bytes);
    }

    /// Whether this peer's task has stopped, so a push has nowhere to go.
    fn gone(&self) -> bool {
        self.closed.load(Ordering::Relaxed) || self.task.get().is_some_and(AbortHandle::is_finished)
    }

    fn enqueue(&self, class: Class, waiting: Waiting, now: Instant) {
        let queued = Queued {
            waiting,
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

    /// Throws away everything queued, counting each frame under the peer that will never get
    /// it. What was already handed to the transport is gone with the connection and is not
    /// counted here: it left this queue.
    fn discard(&self) {
        while self.ledger.pop(self).is_some() {
            self.stats
                .queue_drop(&self.peer, Class::Large, DropReason::PeerDown);
        }
        let mut lane = self.lane(Class::Small);
        while lane.pop().is_some() {
            self.stats
                .queue_drop(&self.peer, Class::Small, DropReason::PeerDown);
        }
        self.depth(Class::Small, &lane);
    }

    /// The next frame to write: from the large lane while it has one that is still worth
    /// sending at `now`, then from the small lane. Large first, because a block waiting behind
    /// a second of attestations is a block that arrives after the slot it belongs to (D17).
    fn next(&self, now: Instant) -> Option<Queued> {
        while let Some(queued) = self.ledger.pop(self) {
            if now.saturating_duration_since(queued.enqueued_at) <= LARGE_STALE_AFTER {
                return Some(queued);
            }
            self.stats
                .queue_drop(&self.peer, Class::Large, DropReason::Stale);
        }
        let mut lane = self.lane(Class::Small);
        let queued = lane.pop()?;
        self.depth(Class::Small, &lane);
        Some(queued)
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
    ///
    /// The frame arrives encoded, so the fanout encodes once whoever a message is going to and
    /// every target's lane holds a clone of the same bytes.
    pub fn push(&self, class: Class, frame: Bytes, now: Instant) -> Result<(), Dropped> {
        self.queue(class, Waiting::Frame(frame), now)
    }

    /// Queues one flushed batch on the small lane, to go as a datagram when the task reaches it
    /// (§5.3). `stale_after` is the bound its entries were collected under, which the task
    /// checks them against again before it sends (D21).
    ///
    /// Not encoded here, unlike [`push`](Self::push): a batch goes to the one destination it was
    /// collected for, so there is nothing to share the bytes with, and the second stale check
    /// needs the entries.
    pub fn push_batch(
        &self,
        flush: Flush,
        stale_after: Duration,
        now: Instant,
    ) -> Result<(), Dropped> {
        self.queue(Class::Small, Waiting::Batch { flush, stale_after }, now)
    }

    fn queue(&self, class: Class, waiting: Waiting, now: Instant) -> Result<(), Dropped> {
        if self.0.gone() {
            return Err(Dropped);
        }
        self.0.enqueue(class, waiting, now);
        Ok(())
    }

    /// What `class`'s lane holds now, the numbers `peer_queue_depth` last reported for it.
    /// `eth-gossip-overlayctl status` shows them per peer, so an operator can see which sibling is
    /// behind before the drops start (T-042).
    pub fn depth(&self, class: Class) -> Depth {
        self.0.lane(class).depth()
    }

    /// A handle with no task behind it, for a live view a test builds by hand: every push is
    /// [`Dropped`]. The peers in such a view are there to be routed to; a test that sends to one
    /// replaces its handle with what [`PeerSender::spawn`] returned.
    #[cfg(any(test, feature = "test-util"))]
    pub fn stopped(peer: Hostname) -> Self {
        let queues = Queues::new(
            peer,
            Deps {
                ledger: Arc::new(LargeLedger::new(0)),
                stats: Arc::new(()),
            },
        );
        queues.closed.store(true, Ordering::Relaxed);
        Self(Arc::new(queues))
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
        self.0.discard();
    }
}

impl std::fmt::Debug for SenderHandle {
    // mutants::skip: `LivePeer` derives `Debug` and this is what lets it. Nothing in the sidecar
    // renders a handle, so no test can tell one rendering from another as behaviour, and a test
    // written to kill the mutant would be asserting a format string nobody reads.
    #[cfg_attr(test, mutants::skip)]
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
        let ledger = deps.ledger.clone();
        let queues = Arc::new(Queues::new(peer, deps));
        ledger.register(&queues);
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
        let Some(queued) = queues.next(now) else {
            queues.waiting.notified().await;
            continue;
        };
        let written = match queued.waiting {
            Waiting::Frame(frame) => transport.send(frame).await,
            Waiting::Batch { flush, stale_after } => {
                send_batch(&transport, &queues, flush, stale_after, now).await
            }
        };
        if let Err(error) = written {
            tracing::debug!(peer = %queues.peer, %error, "connection carries no more frames");
            return;
        }
    }
}

/// One batch, aged again and then written on the carrier it asked for.
///
/// The datagram is what the small class is for, and the two ways it can be refused read
/// differently. `TooLarge` means path MTU dropped between the batcher's check and this send, so
/// this batch goes on a stream and the next is built against the smaller limit. `Disabled` and
/// `UnsupportedByPeer` mean a peer whose transport takes no datagram at all: the batch still
/// goes on a stream, because the payloads are worth as much either way, and the operator gets
/// one line per connection about a transport that is not configured for what its HELLO
/// advertised.
async fn send_batch<T: Transport>(
    transport: &T,
    queues: &Queues,
    mut flush: Flush,
    stale_after: Duration,
    now: Instant,
) -> std::io::Result<()> {
    let dropped = batch::drop_stale(&mut flush.entries, stale_after, now);
    if dropped > 0 {
        queues.stats.stale_dropped(StaleReason::Dequeue, dropped);
    }
    if flush.entries.is_empty() {
        return Ok(());
    }
    let carrier = flush.carrier;
    let frame = flush.into_frame();
    if carrier == Carrier::Stream {
        return transport.send(encode_stream(&frame)).await;
    }
    match transport.send_datagram(encode_datagram(&frame)) {
        Ok(()) => Ok(()),
        Err(SendDatagramError::TooLarge) => transport.send(encode_stream(&frame)).await,
        Err(SendDatagramError::ConnectionLost(error)) => Err(std::io::Error::other(error)),
        Err(error) => {
            if !queues.warned_no_datagrams.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    peer = %queues.peer,
                    %error,
                    "peer takes no datagrams; the small class goes to it on streams"
                );
            }
            transport.send(encode_stream(&frame)).await
        }
    }
}

#[cfg(test)]
mod tests {
    use overlay_core::batch::Entry;
    use overlay_core::roster::Hostname;
    use overlay_core::topic::table::TopicId;

    use super::*;
    use crate::testutil::{CountingStats, SendSpy, eventually, within};

    /// A batch of two entries for the peer, pushed at `at`, as the batcher would have flushed
    /// it.
    fn flush_of(at: Instant) -> Flush {
        Flush {
            dest: peer(),
            entries: ["the first attestation", "the second"]
                .into_iter()
                .map(|payload| Entry {
                    topic_id: TopicId::new(1),
                    payload: Bytes::from_static(payload.as_bytes()),
                    pushed_at: at,
                })
                .collect(),
            carrier: Carrier::Datagram,
            stale_dropped: 0,
        }
    }

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

    /// The numbers of the frames a spy was given, in order.
    fn numbers(link: &SendSpy) -> Vec<usize> {
        link.sent().iter().map(number).collect()
    }

    fn number(frame: &Bytes) -> usize {
        let mut bytes = [0; size_of::<usize>()];
        bytes.copy_from_slice(&frame[..size_of::<usize>()]);
        usize::from_le_bytes(bytes)
    }

    fn peer() -> Hostname {
        host("bn-01")
    }

    fn host(name: &str) -> Hostname {
        Hostname(name.to_owned())
    }

    /// A sender on `link`, with the counters a test reads its drops and depths from.
    fn sender(link: &SendSpy) -> (SenderHandle, Arc<CountingStats>) {
        let stats = Arc::new(CountingStats::default());
        let ledger = Arc::new(LargeLedger::new(LARGE_QUEUED_BYTES_MAX));
        (sender_on(&ledger, &stats, peer(), link), stats)
    }

    /// One more sender under the same ledger and counters, for the bounds that span peers.
    fn sender_on(
        ledger: &Arc<LargeLedger>,
        stats: &Arc<CountingStats>,
        peer: Hostname,
        link: &SendSpy,
    ) -> SenderHandle {
        let deps = Deps {
            ledger: ledger.clone(),
            stats: stats.clone(),
        };
        PeerSender::spawn(peer, link.clone(), deps)
    }

    /// The four bounds are the decision, not an implementation detail: D17 and §5.7 name these
    /// numbers, and what an operator reads off `peer_queue_depth` means what it means because
    /// of them.
    #[test]
    fn the_bounds_are_the_numbers_the_design_names() {
        assert_eq!(SMALL_LANE_FRAMES, 600);
        assert_eq!(LARGE_LANE_BYTES, 1024 * 1024);
        assert_eq!(LARGE_STALE_AFTER, Duration::from_secs(3));
        assert_eq!(LARGE_QUEUED_BYTES_MAX, 64 * 1024 * 1024);
    }

    /// The `reason` label of `peer_queue_drops_total`, which an alert and a dashboard are keyed
    /// on (§12), so the strings are pinned rather than derived.
    #[test]
    fn drop_reasons_are_the_labels_they_are_counted_under() {
        assert_eq!(DropReason::Full.as_str(), "full");
        assert_eq!(DropReason::Stale.as_str(), "stale");
        assert_eq!(DropReason::PeerDown.as_str(), "peer_down");
    }

    /// `eth-gossip-overlayctl status` reads a peer's queue depth off the handle and
    /// `peer_queue_depth` is set from the same lane, so the two can never disagree about a peer
    /// (T-042). Nothing is awaited between the pushes and the reads, so the drain task has not
    /// run and what the lanes hold is what was put in them.
    #[tokio::test]
    async fn depth_reports_what_the_gauge_reports_for_each_lane() {
        let link = SendSpy::stalled();
        let (sender, stats) = sender(&link);
        let now = Instant::now();

        sender.push(Class::Large, frame_of(1, 4096), now).unwrap();
        sender.push(Class::Large, frame_of(2, 2048), now).unwrap();
        sender.push(Class::Small, frame_of(3, 128), now).unwrap();

        let large = sender.depth(Class::Large);
        let small = sender.depth(Class::Small);
        assert_eq!((large.frames, large.bytes), (2, 6144));
        assert_eq!((small.frames, small.bytes), (1, 128));
        assert_eq!(
            stats.queue_depth(&peer(), Class::Large),
            (large.frames, large.bytes)
        );
        assert_eq!(
            stats.queue_depth(&peer(), Class::Small),
            (small.frames, small.bytes)
        );
    }

    /// A frame the per-peer bound threw away is not still charged to the process budget. One
    /// peer overflowing its own lane must not squeeze every other peer out of the ledger.
    #[tokio::test]
    async fn a_frame_the_lane_evicted_is_given_back_to_the_process_budget() {
        let size = LARGE_LANE_BYTES / 4;
        // Room for the peer's whole lane and half as much again, so a ledger that kept the
        // bytes of evicted frames would be over budget while the lane itself is not.
        let ledger = Arc::new(LargeLedger::new(LARGE_LANE_BYTES + 2 * size));
        let stats = Arc::new(CountingStats::default());
        let link = SendSpy::stalled();
        let sender = sender_on(&ledger, &stats, peer(), &link);
        let now = Instant::now();

        for n in 0..8 {
            sender.push(Class::Large, frame_of(n, size), now).unwrap();
        }

        // Four frames fill the lane, so the four before them went and nothing else did.
        assert_eq!(
            stats.queue_drops(&peer(), Class::Large, DropReason::Full),
            4
        );
        link.release();
        eventually("what the lane kept to go out", || link.sent().len() == 4).await;
        assert_eq!(numbers(&link), vec![4, 5, 6, 7]);
    }

    /// The budget is on what is queued, not on what has been through. Here the sender has
    /// written one frame and is blocked writing a second, so the ledger owes the process only
    /// what is still in the lane, and the cap falls where that says rather than where the
    /// traffic since the peer connected would say.
    #[tokio::test]
    async fn the_budget_counts_what_is_queued_and_not_what_has_gone() {
        let size = LARGE_LANE_BYTES / 4;
        let ledger = Arc::new(LargeLedger::new(3 * size));
        let stats = Arc::new(CountingStats::default());
        let link = SendSpy::taking(1);
        let sender = sender_on(&ledger, &stats, peer(), &link);
        let now = Instant::now();
        for n in 0..3 {
            sender.push(Class::Large, frame_of(n, size), now).unwrap();
        }
        // One frame written and one held in the write that follows it, which is the state the
        // lane's own depth reports and the point of the test.
        eventually("the sender to take what it can", || {
            stats.queue_depth(&peer(), Class::Large) == (1, size)
        })
        .await;

        for n in 3..6 {
            sender.push(Class::Large, frame_of(n, size), now).unwrap();
        }

        assert_eq!(
            stats.queue_drops(&peer(), Class::Large, DropReason::Full),
            1
        );
        link.release();
        eventually("the rest to go out", || link.sent().len() == 5).await;
        assert_eq!(numbers(&link), vec![0, 1, 3, 4, 5]);
    }

    /// The small lane is bounded by frames, and what goes when it is full is the oldest one: an
    /// attestation the peer has not taken in two seconds is worth less than the one that just
    /// arrived (D17).
    #[tokio::test]
    async fn small_lane_drops_the_oldest_frame_when_full_and_counts_full() {
        let link = SendSpy::open();
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
        assert_eq!(numbers(&link), (1..=SMALL_LANE_FRAMES).collect::<Vec<_>>());
    }

    /// The large lane is bounded by bytes rather than frames, because one block is worth six
    /// hundred attestations, and the oldest goes first for the same reason the small lane's
    /// does (D17).
    #[tokio::test]
    async fn large_lane_drops_the_oldest_when_bytes_exceed_1mib_and_counts_full() {
        let link = SendSpy::open();
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
        assert_eq!(numbers(&link), vec![1, 2, 3, 4]);
    }

    /// The age bound is read at dequeue and not at push, because what matters is how old the
    /// frame is when it would go on the wire (D17). The frame behind it is younger and goes.
    #[tokio::test(start_paused = true)]
    async fn large_frame_older_than_3s_at_dequeue_is_dropped_and_counted_stale() {
        let link = SendSpy::open();
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
        assert_eq!(numbers(&link), vec![1]);
        assert_eq!(
            stats.queue_drops(&peer(), Class::Large, DropReason::Stale),
            1
        );
    }

    /// The second of D21's two age checks. A flush is checked on its way out of the batcher and
    /// again here, because it can wait in this lane long enough to age out on the way, and an
    /// attestation that late is worth nothing to the beacon node while still costing it the
    /// validation. Nothing goes, and every entry the batch held is counted.
    #[tokio::test(start_paused = true)]
    async fn stale_batch_is_dropped_at_dequeue_and_never_sent() {
        let link = SendSpy::stalled();
        let (sender, stats) = sender(&link);
        let start = tokio::time::Instant::now().into_std();
        let stale_after = Duration::from_secs(1);

        // A large frame the stalled spy will not take is what holds the drain: the batch waits
        // behind it, which is the case the second check exists for.
        sender.push(Class::Large, frame(0), start).unwrap();
        sender
            .push_batch(flush_of(start), stale_after, start)
            .unwrap();
        tokio::time::advance(stale_after + Duration::from_millis(1)).await;
        link.release();

        eventually("the batch to be given up on", || {
            stats.stale_dropped(StaleReason::Dequeue) == 2
        })
        .await;
        assert_eq!(numbers(&link), vec![0]);
        assert!(link.datagrams().is_empty());
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
        let (slow_link, fast_link) = (SendSpy::stalled(), SendSpy::stalled());
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
        assert_eq!(numbers(&fast_link), vec![1, 2]);
        assert!(slow_link.sent().is_empty());
    }

    /// The point of a queue per peer: the sibling that has stopped reading holds up its own
    /// frames and nobody else's, where one shared writer would have every peer waiting on the
    /// slowest congestion window (§5.7).
    #[tokio::test(flavor = "multi_thread")]
    async fn a_stalled_peer_does_not_delay_delivery_to_a_fast_peer() {
        let ledger = Arc::new(LargeLedger::new(LARGE_QUEUED_BYTES_MAX));
        let stats = Arc::new(CountingStats::default());
        let (stalled_link, fast_link) = (SendSpy::stalled(), SendSpy::open());
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
        let link = SendSpy::stalled();
        let (sender, _) = sender(&link);
        let now = Instant::now();

        sender.push(Class::Small, frame(0), now).unwrap();
        sender.push(Class::Large, frame(1), now).unwrap();
        sender.push(Class::Small, frame(2), now).unwrap();
        link.release();

        eventually("all three to go out", || link.sent().len() == 3).await;
        assert_eq!(numbers(&link), vec![1, 0, 2]);
    }

    /// `peer_queue_depth` is how a slow sibling is spotted in production (§12), so it has to
    /// follow both lanes in both units, and come back down as the queue drains.
    #[tokio::test]
    async fn depth_gauges_track_frames_and_bytes() {
        let link = SendSpy::stalled();
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
        let link = SendSpy::stalled();
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
