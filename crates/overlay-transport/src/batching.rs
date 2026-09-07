//! The task that turns small-class payloads into batches on their way to a peer (§5.4, D21).
//!
//! T-061's [`Batcher`] is pure and driven by whoever holds it. This is what holds it: one task
//! per sidecar that takes what the fanout routed, pushes it into the open batch for its
//! destination, and hands every batch the push or the tick closed to that destination's send
//! queue (T-033). Nothing else touches the batcher, so it needs no lock.
//!
//! # Why the fanout does not batch inline
//!
//! A batch closes on time as well as on size: a destination that has gone quiet still owes what
//! it collected, and the window is [`BATCH_TICK`] short of a timer nobody drives. The fanout
//! loop awaits nothing (D17), so the timer belongs to a task of its own, and the channel between
//! them is what keeps the fanout free of it. That channel is bounded and pushed to with
//! `try_send`: a payload that will not fit is counted under the peer it was for and dropped,
//! which is what its lane would do a moment later anyway.
//!
//! # What arrives with each payload
//!
//! The destination's datagram limit and its send queue both come with the payload rather than
//! being looked up here, because the fanout already had the live view in its hand when it routed
//! it. The limit moves with path MTU discovery, so it is read per payload and not per peer
//! (T-061), and the queue is remembered per destination so a batch closed by the timer, long
//! after the payload that opened it, still has somewhere to go. A destination is forgotten again
//! when its queue refuses a batch, which is what a peer that has left the live set does.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use overlay_core::batch::{Batcher, Flush};
use overlay_core::config;
use overlay_core::roster::Hostname;
use overlay_core::topic::Class;
use overlay_core::topic::table::TopicId;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::sender::{DropReason, Dropped, SenderHandle, SenderStats, StaleReason};

/// How often the open batches are asked whether their window has run out. A few times per
/// window at the shipped 10 ms, which is what T-061 asks for: a batch is late by at most this
/// beyond its window, and a fleet with no small-class traffic wakes up 500 times a second to
/// find nothing open.
pub const BATCH_TICK: Duration = Duration::from_millis(2);

/// Payloads the batcher has not reached yet. One tick's worth of a busy slot several times
/// over: past this the task is not running, and a payload that waits for it is a payload the
/// destination's own lane would drop before it ever went out.
const WAITING_MAX: usize = 4096;

/// How many payloads one wake-up takes off the channel. What arrives between two ticks under
/// the fleet's own load, so the loop is one live view and one pass over what is waiting rather
/// than a round trip per attestation.
const DRAIN_MAX: usize = 512;

/// One small-class payload on its way to one destination, as the fanout hands it over.
pub struct Small {
    /// The host it is for, which is the key the batcher opens a batch under.
    pub dest: Hostname,
    /// This host's id for the topic it arrived on, from this host's own table (D13).
    pub topic_id: TopicId,
    /// The gossipsub wire form.
    pub payload: Bytes,
    /// What a datagram to this destination currently holds, read off the connection when the
    /// message was routed.
    pub max_bytes: usize,
    /// The destination's send queue, so a batch closed later still has one.
    pub sender: SenderHandle,
}

/// How the fanout reaches the batcher. Cloneable, and every clone reaches the one task.
#[derive(Clone)]
pub struct BatchHandle {
    waiting: mpsc::Sender<Small>,
    stats: Arc<dyn SenderStats>,
}

impl BatchHandle {
    /// Hands `item` to the batcher without waiting for it. A full channel means the batcher is
    /// not keeping up, which is counted as the peer's own queue drop: from the operator's side
    /// it is the same event, a small-class payload for that peer that will never be written.
    pub fn push(&self, item: Small) -> Result<(), Dropped> {
        self.waiting.try_send(item).map_err(|error| {
            let refused = error.into_inner();
            self.stats
                .queue_drop(&refused.dest, Class::Small, DropReason::Full);
            Dropped
        })
    }
}

/// The batcher and the task that drives it.
pub struct Batching;

impl Batching {
    /// Starts the task, and answers with what the fanout pushes into.
    ///
    /// `small` carries `classes.small.batch_window_ms` and `classes.small.stale_after_ms`, both
    /// reloadable (T-043). A change closes every open batch under the bounds it was collected
    /// under and builds the batcher again, so nothing already collected is re-aged or lost.
    pub fn spawn(
        small: watch::Receiver<config::SmallClass>,
        stats: Arc<dyn SenderStats>,
    ) -> (BatchHandle, JoinHandle<()>) {
        let (waiting, items) = mpsc::channel(WAITING_MAX);
        (
            BatchHandle {
                waiting,
                stats: stats.clone(),
            },
            tokio::spawn(run(items, small, stats)),
        )
    }
}

/// One pass per tick or per arrival: push what came in, close what is due, hand each closed
/// batch to its destination.
async fn run(
    mut items: mpsc::Receiver<Small>,
    mut small: watch::Receiver<config::SmallClass>,
    stats: Arc<dyn SenderStats>,
) {
    let mut cfg = small.borrow_and_update().clone();
    let mut batcher = Batcher::new(cfg.batch_window, cfg.stale_after);
    let mut senders: BTreeMap<Hostname, SenderHandle> = BTreeMap::new();
    let mut arrived = Vec::with_capacity(DRAIN_MAX);
    let mut tick = tokio::time::interval(BATCH_TICK);
    loop {
        tokio::select! {
            taken = items.recv_many(&mut arrived, DRAIN_MAX) => {
                if taken == 0 {
                    return;
                }
            }
            _ = tick.tick() => {}
        }
        let now = Instant::now();
        let mut flushes = Vec::new();
        if small.has_changed().unwrap_or(false) {
            // Past every open batch's window, so the batcher hands back everything it holds
            // before the bounds it was holding it under go.
            flushes.extend(batcher.tick(now + cfg.batch_window));
            cfg = small.borrow_and_update().clone();
            batcher = Batcher::new(cfg.batch_window, cfg.stale_after);
        }
        for item in arrived.drain(..) {
            flushes.extend(batcher.push(
                &item.dest,
                item.topic_id,
                item.payload,
                item.max_bytes,
                now,
            ));
            senders.insert(item.dest, item.sender);
        }
        flushes.extend(batcher.tick(now));
        for flush in flushes {
            send(&mut senders, stats.as_ref(), flush, cfg.stale_after, now);
        }
    }
}

/// Queues one closed batch on its destination's lane, counting what the flush aged out and what
/// the destination no longer has a task to take.
fn send(
    senders: &mut BTreeMap<Hostname, SenderHandle>,
    stats: &dyn SenderStats,
    flush: Flush,
    stale_after: Duration,
    now: Instant,
) {
    if flush.stale_dropped > 0 {
        stats.stale_dropped(StaleReason::Flush, flush.stale_dropped);
    }
    // A batch whose entries all aged out is still flushed, so that the count above reaches the
    // caller; there is nothing left to send.
    if flush.entries.is_empty() {
        return;
    }
    let Some(sender) = senders.get(&flush.dest) else {
        tracing::debug!(peer = %flush.dest, "no send queue for the batch collected for it");
        return;
    };
    let dest = flush.dest.clone();
    if sender.push_batch(flush, stale_after, now).is_err() {
        tracing::debug!(peer = %dest, "peer has no sender to queue the batch on");
        senders.remove(&dest);
    }
}
