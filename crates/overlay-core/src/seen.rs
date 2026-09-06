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
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::msgid::MessageId;
use crate::time::Clock;

/// Where capacity evictions are counted, so `overlay-core` stays free of the metrics crate.
/// T-041 implements it on `seen_cache_evicted_total{reason="capacity"}`.
///
/// The call runs inside [`SharedSeenCache`]'s lock on the insert path, so an implementation
/// must be a counter increment and nothing slower.
pub trait SeenStats: Send + Sync {
    /// An insert evicted `count` unexpired entries to stay within capacity. Never called for
    /// expiry: that is the TTL doing its job, this is the bound doing the TTL's job.
    fn evicted_for_capacity(&self, count: usize);
}

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
    stats: Option<Arc<dyn SeenStats>>,
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
            stats: None,
            seen: HashSet::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
        }
    }

    /// Reports capacity evictions to `stats`. Without this nothing is called, so tests and
    /// callers that do not care pass nothing.
    pub fn with_stats(mut self, stats: Arc<dyn SeenStats>) -> Self {
        self.stats = Some(stats);
        self
    }

    /// Records `id` and reports whether it was new: `true` unless `id` was inserted less than
    /// `ttl` ago. A repeat does not refresh the TTL, so the deque stays in insertion order and
    /// expiry only ever looks at its front. O(1) amortised: expired entries come off the front,
    /// at capacity the oldest entry goes, and both containers are updated once.
    ///
    /// A capacity eviction is reported to the [`SeenStats`] hook, if any, after both containers
    /// are consistent again. Expiry is never reported.
    pub fn insert(&mut self, id: MessageId) -> bool {
        let now = self.clock.now();
        self.expire(now);
        if self.seen.contains(&id) {
            return false;
        }
        let evicted = self.order.len() >= self.capacity && self.pop_oldest();
        self.order.push_back((now, id));
        self.seen.insert(id);
        if evicted && let Some(stats) = &self.stats {
            stats.evicted_for_capacity(1);
        }
        true
    }

    /// Whether `id` is held. Expiry happens on `insert` and `evict_expired`, not here, so an
    /// entry past its TTL that neither has removed yet still reads as present.
    pub fn contains(&self, id: &MessageId) -> bool {
        self.seen.contains(id)
    }

    /// How many ids are held, expired ones included until something removes them.
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Whether nothing is held.
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Drops every entry past its TTL now, for a caller that wants memory back between
    /// inserts. `insert` does the same sweep on its own before adding.
    pub fn evict_expired(&mut self) {
        self.expire(self.clock.now());
    }

    fn expire(&mut self, now: Instant) {
        while let Some((at, _)) = self.order.front()
            && *at + self.ttl <= now
        {
            self.pop_oldest();
        }
    }

    // mutants::skip: expire drains through this until the front is unexpired, so a pop_oldest
    // that does not pop loops forever. The mutant hangs the suite instead of failing it, and no
    // test can tell the difference.
    #[cfg_attr(test, mutants::skip)]
    fn pop_oldest(&mut self) -> bool {
        match self.order.pop_front() {
            Some((_, id)) => self.seen.remove(&id),
            None => false,
        }
    }
}

/// One [`SeenCache`] shared by the three insert sites and the readers. Every method takes the
/// lock for that one call and releases it before returning, so the cache is never held across
/// an `await`; the [`SeenStats`] hook runs inside that window, which is why it must be cheap.
#[derive(Clone)]
pub struct SharedSeenCache(Arc<Mutex<SeenCache>>);

impl SharedSeenCache {
    /// Wraps `cache` so clones of the handle share it.
    pub fn new(cache: SeenCache) -> Self {
        Self(Arc::new(Mutex::new(cache)))
    }

    /// [`SeenCache::insert`] under the lock.
    pub fn insert(&self, id: MessageId) -> bool {
        self.lock().insert(id)
    }

    /// [`SeenCache::contains`] under the lock.
    pub fn contains(&self, id: &MessageId) -> bool {
        self.lock().contains(id)
    }

    /// [`SeenCache::len`] under the lock.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// [`SeenCache::is_empty`] under the lock.
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// [`SeenCache::evict_expired`] under the lock.
    pub fn evict_expired(&self) {
        self.lock().evict_expired();
    }

    fn lock(&self) -> MutexGuard<'_, SeenCache> {
        // The only code that runs under the lock and can panic is a stats hook, and insert
        // calls it after both containers are consistent, so a poisoned cache is still a valid
        // cache. Dropping every message after a metrics panic would be the worse failure.
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use proptest::prelude::*;

    use super::*;
    use crate::time::FakeClock;

    fn id(byte: u8) -> MessageId {
        MessageId([byte; 20])
    }

    fn cache(ttl: Duration, capacity: usize, clock: &FakeClock) -> SeenCache {
        SeenCache::new(ttl, capacity, Arc::new(clock.clone()))
    }

    /// Records the count passed to every capacity eviction call.
    #[derive(Default)]
    struct CountingStats(Mutex<Vec<usize>>);

    impl SeenStats for CountingStats {
        fn evicted_for_capacity(&self, count: usize) {
            self.0.lock().unwrap().push(count);
        }
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

    #[test]
    fn entry_expires_after_ttl() {
        let clock = FakeClock::new();
        let mut cache = cache(Duration::from_secs(60), 100, &clock);
        cache.insert(id(1));

        clock.advance(Duration::from_secs(60));

        assert!(cache.insert(id(1)));
    }

    #[test]
    fn entry_alive_just_before_ttl() {
        let clock = FakeClock::new();
        let mut cache = cache(Duration::from_secs(60), 100, &clock);
        cache.insert(id(1));

        clock.advance(Duration::from_secs(60) - Duration::from_millis(1));

        assert!(!cache.insert(id(1)));
    }

    #[test]
    fn reinsert_does_not_extend_ttl() {
        let clock = FakeClock::new();
        let mut cache = cache(Duration::from_secs(60), 100, &clock);
        cache.insert(id(1));

        clock.advance(Duration::from_secs(59));
        assert!(!cache.insert(id(1)));
        clock.advance(Duration::from_secs(1));

        assert!(cache.insert(id(1)));
    }

    #[test]
    fn capacity_evicts_oldest_first() {
        let mut cache = cache(Duration::from_secs(60), 3, &FakeClock::new());

        for byte in [1, 2, 3, 4] {
            cache.insert(id(byte));
        }

        assert!(!cache.contains(&id(1)));
        assert!(cache.contains(&id(2)));
        assert!(cache.contains(&id(4)));
    }

    proptest! {
        #[test]
        fn len_never_exceeds_capacity(
            capacity in 1usize..=8,
            steps in prop::collection::vec((0u8..8, 0u64..100), 0..64),
        ) {
            let clock = FakeClock::new();
            let mut cache = cache(Duration::from_millis(150), capacity, &clock);

            for (byte, advance_ms) in steps {
                clock.advance(Duration::from_millis(advance_ms));
                cache.insert(id(byte));
                prop_assert!(cache.len() <= capacity, "{} entries over capacity {capacity}", cache.len());
            }
        }
    }

    #[test]
    fn evict_expired_removes_only_expired() {
        let clock = FakeClock::new();
        let mut cache = cache(Duration::from_secs(60), 100, &clock);
        cache.insert(id(1));
        clock.advance(Duration::from_secs(30));
        cache.insert(id(2));
        clock.advance(Duration::from_secs(20));
        cache.insert(id(3));

        clock.advance(Duration::from_secs(10));
        cache.evict_expired();

        assert_eq!(cache.len(), 2);
        assert!(!cache.contains(&id(1)));
        assert!(cache.contains(&id(2)));
        assert!(cache.contains(&id(3)));
    }

    #[test]
    fn capacity_eviction_fires_stats_and_expiry_does_not() {
        let clock = FakeClock::new();
        let stats = Arc::new(CountingStats::default());
        let mut cache = cache(Duration::from_secs(60), 3, &clock).with_stats(stats.clone());

        for byte in [1, 2, 3, 4] {
            cache.insert(id(byte));
        }
        assert_eq!(*stats.0.lock().unwrap(), [1]);

        clock.advance(Duration::from_secs(61));
        cache.evict_expired();

        assert!(cache.is_empty());
        assert_eq!(*stats.0.lock().unwrap(), [1]);
    }

    #[test]
    fn shared_cache_clones_see_the_same_entries() {
        let clock = FakeClock::new();
        let held_by_ingress = SharedSeenCache::new(cache(Duration::from_secs(60), 100, &clock));
        let held_by_reader = held_by_ingress.clone();

        assert!(held_by_ingress.insert(id(1)));
        assert!(!held_by_reader.insert(id(1)));
        assert!(held_by_reader.insert(id(2)));

        assert!(held_by_reader.contains(&id(1)));
        assert!(!held_by_reader.contains(&id(3)));
        assert_eq!(held_by_reader.len(), 2);
        assert!(!held_by_reader.is_empty());

        clock.advance(Duration::from_secs(60));
        held_by_reader.evict_expired();

        assert!(held_by_ingress.is_empty());
    }

    /// Run by hand with `--ignored --nocapture` to put the number in a PR. Counts the deque
    /// slots and the set's buckets (one key plus one hashbrown control byte each) as allocated,
    /// which is what the process actually holds. hashbrown reports 7/8 of a power of two of
    /// buckets as capacity, so the bucket count is worked back from that.
    #[test]
    #[ignore]
    fn memory_footprint_estimate() {
        const ENTRIES: usize = 200_000;
        let mut cache = cache(Duration::from_secs(60), ENTRIES, &FakeClock::new());
        for n in 0..ENTRIES as u32 {
            let mut bytes = [0; 20];
            bytes[..4].copy_from_slice(&n.to_le_bytes());
            cache.insert(MessageId(bytes));
        }

        let deque = cache.order.capacity() * size_of::<(Instant, MessageId)>();
        let buckets = (cache.seen.capacity() * 8 / 7).next_power_of_two();
        let set = buckets * (size_of::<MessageId>() + 1);
        let total = deque + set;
        println!(
            "{ENTRIES} entries: deque {} KB + set {} KB = {:.1} MB",
            deque / 1024,
            set / 1024,
            total as f64 / (1024.0 * 1024.0)
        );

        assert_eq!(cache.len(), ENTRIES);
        assert!(
            total < 15 * 1024 * 1024,
            "{total} bytes is over the 15 MB target"
        );
    }
}
