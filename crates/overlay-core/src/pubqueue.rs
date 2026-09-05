//! The bounded queue in front of the beacon node (§5.7, DX-N4). Ingress sites push without
//! waiting; one drain task (T-017's `Publisher`) pops and is the only code that awaits
//! gossipsub. Two lanes: the small lane is bounded by entries, the large lane by bytes and
//! age, and both evict their oldest entry to make room, because the newest attestation or
//! column is the one the beacon node is still waiting for.
//!
//! No seen cache here (D08). The three ingress sites insert immediately before they push:
//! T-016 for what the beacon node sent, T-032's receiver for whole messages and batch entries
//! from the overlay, T-074's completion for reassembled messages. Whatever reaches this queue
//! was already inserted, so a copy suppressed downstream is still remembered.
//!
//! [`ClassLanes`](crate::lanes::ClassLanes) looks similar and differs on purpose: the lanes
//! drop the new item and are shaped for the swarm loop; this queue drops the oldest and
//! tracks bytes and age. Do not merge them.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::msgid::MessageId;
use crate::topic::{Class, Topic};

/// Entries the small lane holds before it evicts the oldest (DX-N4).
pub const PUBLISH_SMALL_LANE_ENTRIES: usize = 4096;
/// Payload bytes the large lane holds before it evicts the oldest (DX-N4).
pub const PUBLISH_LARGE_LANE_BYTES: usize = 32 * 1024 * 1024;
/// A large entry older than this at dequeue is discarded: the slot has moved on and the
/// beacon node has other sources for it (DX-N4).
pub const PUBLISH_LARGE_STALE_AFTER: Duration = Duration::from_secs(3);

/// What an ingress site hands over for publishing: the payload in its compressed wire form
/// and the id the ingress site already inserted into the seen cache.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishItem {
    /// The topic to publish on.
    pub topic: Topic,
    /// The gossipsub message id, computed at the ingress site.
    pub id: MessageId,
    /// The snappy-compressed payload, sent to the beacon node untouched.
    pub payload: Bytes,
    /// The lane it queues in and the label its metrics carry.
    pub class: Class,
}

/// Why the queue threw an entry away: the `reason` label of
/// `publish_queue_drops_total{class, reason}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DropReason {
    /// The lane was full and this was its oldest entry.
    Full,
    /// A large entry was older than [`PUBLISH_LARGE_STALE_AFTER`] when the drain task reached
    /// it.
    Stale,
}

/// Where drops are counted, so `overlay-core` stays free of the metrics crate. `()` counts
/// nothing. The call runs while the caller holds whatever lock guards the queue, so an
/// implementation must be a counter increment and nothing slower.
pub trait QueueStats: Send + Sync {
    /// The queue discarded an entry of `class` for `reason`.
    fn dropped(&self, class: Class, reason: DropReason);
}

impl QueueStats for () {
    fn dropped(&self, _: Class, _: DropReason) {}
}

/// What a push did besides queueing the item, which it always does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pushed {
    /// The lane had room.
    Enqueued,
    /// The lane was full and made room by evicting its oldest entries, each counted on the
    /// queue's stats. `class` is the lane's; `reason` is always [`DropReason::Full`], carried
    /// so the caller reports it without knowing that.
    Dropped {
        /// The lane that overflowed.
        class: Class,
        /// Why the evicted entries went.
        reason: DropReason,
    },
}

/// The two lanes. Pure: callers pass the instant, so a test drives age by hand and the
/// drain task stamps it from the injected clock.
pub struct PublishQueue {
    small: VecDeque<PublishItem>,
    large: VecDeque<(Instant, PublishItem)>,
    large_bytes: usize,
    stats: Arc<dyn QueueStats>,
}

impl PublishQueue {
    /// Two empty lanes, reporting drops to `stats`.
    pub fn new(stats: Arc<dyn QueueStats>) -> Self {
        Self {
            small: VecDeque::new(),
            large: VecDeque::new(),
            large_bytes: 0,
            stats,
        }
    }

    /// Queues `item` on the lane for its class, evicting the lane's oldest entries if that
    /// is what it takes. `now` is when the item entered, which the large lane's age bound
    /// reads back at [`pop`](Self::pop). A payload larger than the whole large lane empties
    /// it and goes in alone; gossipsub refuses it later, and the bound holds again once the
    /// drain task takes it.
    pub fn push(&mut self, item: PublishItem, now: Instant) -> Pushed {
        let class = item.class;
        let mut evicted = 0;
        match class {
            Class::Small => {
                while self.small.len() >= PUBLISH_SMALL_LANE_ENTRIES {
                    self.small.pop_front();
                    evicted += 1;
                }
                self.small.push_back(item);
            }
            Class::Large => {
                while self.large_bytes + item.payload.len() > PUBLISH_LARGE_LANE_BYTES
                    && self.pop_large().is_some()
                {
                    evicted += 1;
                }
                self.large_bytes += item.payload.len();
                self.large.push_back((now, item));
            }
        }
        if evicted == 0 {
            return Pushed::Enqueued;
        }
        for _ in 0..evicted {
            self.stats.dropped(class, DropReason::Full);
        }
        Pushed::Dropped {
            class,
            reason: DropReason::Full,
        }
    }

    /// The next item to publish: from the large lane while it has one, else from the small
    /// lane.
    pub fn pop(&mut self, _now: Instant) -> Option<PublishItem> {
        if let Some((_, item)) = self.pop_large() {
            return Some(item);
        }
        self.small.pop_front()
    }

    fn pop_large(&mut self) -> Option<(Instant, PublishItem)> {
        let entry = self.large.pop_front()?;
        self.large_bytes -= entry.1.payload.len();
        Some(entry)
    }

    /// Entries waiting across both lanes.
    pub fn len(&self) -> usize {
        self.small.len() + self.large.len()
    }

    /// Whether nothing is waiting.
    pub fn is_empty(&self) -> bool {
        self.small.is_empty() && self.large.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use super::*;

    const TOPIC: &str = "/eth2/00000000/beacon_block/ssz_snappy";

    /// An item numbered `n`, so a test can tell which entries survived.
    fn item(class: Class, n: usize, payload_len: usize) -> PublishItem {
        let mut id = [0; 20];
        id[..8].copy_from_slice(&(n as u64).to_le_bytes());
        PublishItem {
            topic: Topic::parse(TOPIC).unwrap(),
            id: MessageId(id),
            payload: vec![0; payload_len].into(),
            class,
        }
    }

    fn number(item: &PublishItem) -> usize {
        u64::from_le_bytes(item.id.0[..8].try_into().unwrap()) as usize
    }

    #[derive(Default)]
    struct Recorded(Mutex<Vec<(Class, DropReason)>>);

    impl Recorded {
        fn drops(&self) -> Vec<(Class, DropReason)> {
            self.0.lock().unwrap().clone()
        }
    }

    impl QueueStats for Recorded {
        fn dropped(&self, class: Class, reason: DropReason) {
            self.0.lock().unwrap().push((class, reason));
        }
    }

    #[test]
    fn queue_small_lane_drops_oldest_past_4096_entries() {
        let stats = Arc::new(Recorded::default());
        let mut queue = PublishQueue::new(stats.clone());
        let now = Instant::now();
        for n in 0..PUBLISH_SMALL_LANE_ENTRIES {
            assert_eq!(
                queue.push(item(Class::Small, n, 100), now),
                Pushed::Enqueued
            );
        }

        let pushed = queue.push(item(Class::Small, PUBLISH_SMALL_LANE_ENTRIES, 100), now);

        assert_eq!(
            pushed,
            Pushed::Dropped {
                class: Class::Small,
                reason: DropReason::Full
            }
        );
        assert_eq!(stats.drops(), vec![(Class::Small, DropReason::Full)]);
        assert_eq!(queue.len(), PUBLISH_SMALL_LANE_ENTRIES);
        let survivors: Vec<usize> =
            std::iter::from_fn(|| queue.pop(now).as_ref().map(number)).collect();
        assert_eq!(
            survivors,
            (1..=PUBLISH_SMALL_LANE_ENTRIES).collect::<Vec<_>>()
        );
    }

    const MIB: usize = 1024 * 1024;

    #[test]
    fn queue_large_lane_drops_oldest_past_32_mib() {
        let stats = Arc::new(Recorded::default());
        let mut queue = PublishQueue::new(stats.clone());
        let now = Instant::now();
        for n in 0..4 {
            assert_eq!(
                queue.push(item(Class::Large, n, 8 * MIB), now),
                Pushed::Enqueued
            );
        }

        let fifth = queue.push(item(Class::Large, 4, 8 * MIB), now);
        let sixth = queue.push(item(Class::Large, 5, 16 * MIB), now);

        let full = Pushed::Dropped {
            class: Class::Large,
            reason: DropReason::Full,
        };
        assert_eq!((fifth, sixth), (full, full));
        assert_eq!(stats.drops(), vec![(Class::Large, DropReason::Full); 3]);
        let survivors: Vec<usize> =
            std::iter::from_fn(|| queue.pop(now).as_ref().map(number)).collect();
        assert_eq!(survivors, vec![3, 4, 5]);
    }

    #[test]
    fn queue_pop_discards_large_entries_older_than_3_s_as_stale() {
        let stats = Arc::new(Recorded::default());
        let mut queue = PublishQueue::new(stats.clone());
        let start = Instant::now();
        queue.push(item(Class::Large, 0, 100), start);
        queue.push(item(Class::Large, 1, 100), start + Duration::from_secs(2));

        let popped = queue.pop(start + PUBLISH_LARGE_STALE_AFTER + Duration::from_millis(1));

        assert_eq!(popped.as_ref().map(number), Some(1));
        assert_eq!(stats.drops(), vec![(Class::Large, DropReason::Stale)]);
        assert!(queue.is_empty());

        // Exactly the bound is not older than it.
        queue.push(item(Class::Large, 2, 100), start);
        let at_bound = queue.pop(start + PUBLISH_LARGE_STALE_AFTER);
        assert_eq!(at_bound.as_ref().map(number), Some(2));
        assert_eq!(stats.drops().len(), 1);
    }
}
