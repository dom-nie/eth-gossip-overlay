//! Recently seen message ids, so a message the sidecar already handled is dropped instead of
//! being fanned out or published twice.
//!
//! Exactly three places insert, each immediately before handing a message on: T-016 as a
//! message arrives from the beacon node (before fan-out), T-032's receiver as a whole message
//! or a batch entry arrives from the overlay (before it is queued for publish), and T-074's
//! reassembler when a large message completes (before it is queued for publish). The publisher
//! (T-017) holds no seen cache: whatever reaches the publish queue was inserted at its ingress.
//! Everything else only reads it through `contains`, for instance cut-through forwarding
//! (T-073) asking whether a chunk's message is already held. Do not add a fourth insert site.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::msgid::MessageId;
use crate::time::Clock;

/// A bounded FIFO of message ids with a TTL. Bounded by count as well as time, so a burst
/// cannot exhaust memory: at capacity the oldest entry goes even if it is unexpired.
///
/// The clock is an `Arc<dyn Clock>` rather than a type parameter so [`SharedSeenCache`] and
/// the three insert sites name one concrete type; [`crate::time::FakeClock`] is `Clone` with
/// shared state, so a test keeps its own handle and hands the cache an `Arc` of a clone.
pub struct SeenCache {
    ttl: Duration,
    capacity: usize,
    clock: Arc<dyn Clock>,
    seen: HashSet<MessageId>,
    order: VecDeque<(Instant, MessageId)>,
}

impl SeenCache {
    /// A cache that forgets an id `ttl` after it was inserted and never holds more than
    /// `capacity` ids. Both containers are allocated for `capacity` up front so the hot path
    /// never reallocates.
    pub fn new(ttl: Duration, capacity: usize, clock: Arc<dyn Clock>) -> Self {
        Self {
            ttl,
            capacity,
            clock,
            seen: HashSet::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
        }
    }

    /// Records `id` and reports whether it was new: `true` unless `id` was inserted less than
    /// `ttl` ago. A repeat does not refresh the TTL, so the deque stays in insertion order and
    /// expiry only ever looks at its front. O(1) amortised: expired entries come off the front,
    /// at capacity the oldest entry goes, and both containers are updated once.
    pub fn insert(&mut self, id: MessageId) -> bool {
        let now = self.clock.now();
        while let Some((at, _)) = self.order.front()
            && *at + self.ttl <= now
        {
            self.pop_oldest();
        }
        if self.seen.contains(&id) {
            return false;
        }
        if self.order.len() >= self.capacity {
            self.pop_oldest();
        }
        self.order.push_back((now, id));
        self.seen.insert(id);
        true
    }

    fn pop_oldest(&mut self) {
        if let Some((_, id)) = self.order.pop_front() {
            self.seen.remove(&id);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::time::FakeClock;

    fn id(byte: u8) -> MessageId {
        MessageId([byte; 20])
    }

    fn cache(ttl: Duration, capacity: usize, clock: &FakeClock) -> SeenCache {
        SeenCache::new(ttl, capacity, Arc::new(clock.clone()))
    }

    #[test]
    fn first_insert_returns_true_second_returns_false() {
        let mut cache = cache(Duration::from_secs(60), 100, &FakeClock::new());

        assert!(cache.insert(id(1)));
        assert!(!cache.insert(id(1)));
    }

    #[test]
    fn contains_reflects_insert() {
        let mut cache = cache(Duration::from_secs(60), 100, &FakeClock::new());

        assert!(!cache.contains(&id(1)));
        cache.insert(id(1));

        assert!(cache.contains(&id(1)));
        assert!(!cache.contains(&id(2)));
    }
}
