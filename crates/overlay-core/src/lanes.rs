//! The hand-off from the BN link's swarm loop to whoever consumes what the beacon node sends
//! (D07): two bounded `mpsc` lanes, one per [`Class`], filled with `try_send` so the swarm
//! loop never waits on a consumer, and drained large-first so a block is never queued behind
//! attestations. MASTER.md keeps channels out of this crate; D07 put the lanes here anyway,
//! because the capacities, the drop policy and which class wins are the decision, and the
//! channels are only its carrier.

use std::sync::Arc;
use std::task::Poll;

use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;

use crate::topic::Class;

/// Slots in the small lane, fixed by D07 and the §7 row "Swarm control events". When it is
/// full the newest attestation is dropped and counted; the swarm loop never waits for room.
pub const SMALL_LANE_CAPACITY: usize = 4096;
/// Slots in the large lane (D07). Blocks and columns arrive at a rate that cannot fill 1,024
/// slots unless the consumer is dead, which is why a large drop is logged at error level.
pub const LARGE_LANE_CAPACITY: usize = 1024;

/// Where drops are counted. T-041 binds `bn_events_dropped_total{class}`; `()` counts
/// nothing, for tests and for wiring that has no registry yet.
pub trait LaneStats: Send + Sync {
    /// An item for `class` found its lane full and was dropped.
    fn dropped(&self, class: Class);
}

impl LaneStats for () {
    fn dropped(&self, _: Class) {}
}

/// The item that found its lane full, handed back so the caller decides what to say about it.
#[derive(Debug, PartialEq, Eq)]
pub struct Dropped<T>(pub T);

/// The sending side of both lanes. The swarm task holds one of these; the consumer owns the
/// [`ClassLanes`] it came from.
pub struct LanePusher<T> {
    small: mpsc::Sender<T>,
    large: mpsc::Sender<T>,
    stats: Arc<dyn LaneStats>,
}

impl<T> Clone for LanePusher<T> {
    fn clone(&self) -> Self {
        Self {
            small: self.small.clone(),
            large: self.large.clone(),
            stats: Arc::clone(&self.stats),
        }
    }
}

impl<T> LanePusher<T> {
    /// Queues `item` on the lane for `class` without waiting. A full lane hands the item back.
    pub fn push(&self, class: Class, item: T) -> Result<(), Dropped<T>> {
        let lane = match class {
            Class::Small => &self.small,
            Class::Large => &self.large,
        };
        match lane.try_send(item) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(item) | TrySendError::Closed(item)) => {
                self.stats.dropped(class);
                Err(Dropped(item))
            }
        }
    }
}

/// Both lanes with their receiving ends. The consumer owns this and calls [`recv`](Self::recv);
/// the swarm task gets a [`LanePusher`] from [`pusher`](Self::pusher).
pub struct ClassLanes<T> {
    pusher: LanePusher<T>,
    small: mpsc::Receiver<T>,
    large: mpsc::Receiver<T>,
}

impl<T> ClassLanes<T> {
    /// Two empty lanes reporting drops to `stats`.
    pub fn new(stats: Arc<dyn LaneStats>) -> Self {
        let (small_tx, small) = mpsc::channel(SMALL_LANE_CAPACITY);
        let (large_tx, large) = mpsc::channel(LARGE_LANE_CAPACITY);
        Self {
            pusher: LanePusher {
                small: small_tx,
                large: large_tx,
                stats,
            },
            small,
            large,
        }
    }

    /// See [`LanePusher::push`].
    pub fn push(&self, class: Class, item: T) -> Result<(), Dropped<T>> {
        self.pusher.push(class, item)
    }

    /// A sending handle for the task that fills the lanes.
    pub fn pusher(&self) -> LanePusher<T> {
        self.pusher.clone()
    }

    /// The next item, from the large lane whenever it has one and from the small lane
    /// otherwise. Never returns `None`: the lanes hold their own senders, so neither closes.
    pub async fn recv(&mut self) -> T {
        std::future::poll_fn(|cx| {
            if let Poll::Ready(Some(item)) = self.large.poll_recv(cx) {
                return Poll::Ready(item);
            }
            if let Poll::Ready(Some(item)) = self.small.poll_recv(cx) {
                return Poll::Ready(item);
            }
            Poll::Pending
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::topic::Class;

    #[derive(Default)]
    struct Counts {
        small: AtomicUsize,
        large: AtomicUsize,
    }

    impl LaneStats for Counts {
        fn dropped(&self, class: Class) {
            match class {
                Class::Small => &self.small,
                Class::Large => &self.large,
            }
            .fetch_add(1, Ordering::Relaxed);
        }
    }

    #[tokio::test]
    async fn lanes_recv_prefers_large_when_both_have_items() {
        let mut lanes = ClassLanes::new(Arc::new(()));
        lanes.push(Class::Small, "attestation").unwrap();
        lanes.push(Class::Large, "block").unwrap();

        assert_eq!(lanes.recv().await, "block");
        assert_eq!(lanes.recv().await, "attestation");
    }

    #[test]
    fn lanes_full_small_lane_drops_the_new_item_and_counts_small() {
        let counts = Arc::new(Counts::default());
        let lanes = ClassLanes::new(counts.clone());
        for i in 0..SMALL_LANE_CAPACITY {
            lanes.push(Class::Small, i).unwrap();
        }

        let overflow = lanes.push(Class::Small, usize::MAX);

        assert_eq!(overflow, Err(Dropped(usize::MAX)));
        assert_eq!(counts.small.load(Ordering::Relaxed), 1);
        assert_eq!(counts.large.load(Ordering::Relaxed), 0);
    }

    /// Collects everything a `tracing` subscriber writes, so a test can read it back.
    #[derive(Clone, Default)]
    struct Log(Arc<Mutex<Vec<u8>>>);

    impl Log {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl Write for Log {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn lanes_full_large_lane_drops_counts_large_and_logs_at_error() {
        let counts = Arc::new(Counts::default());
        let lanes = ClassLanes::new(counts.clone());
        let log = Log::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer({
                let log = log.clone();
                move || log.clone()
            })
            .finish();

        let overflow = tracing::subscriber::with_default(subscriber, || {
            for i in 0..LARGE_LANE_CAPACITY {
                lanes.push(Class::Large, i).unwrap();
            }
            lanes.push(Class::Large, usize::MAX)
        });

        assert_eq!(overflow, Err(Dropped(usize::MAX)));
        assert_eq!(counts.large.load(Ordering::Relaxed), 1);
        assert_eq!(counts.small.load(Ordering::Relaxed), 0);
        let text = log.text();
        assert!(text.contains("ERROR"), "{text:?}");
    }
}
