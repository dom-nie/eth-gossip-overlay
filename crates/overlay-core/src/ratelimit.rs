//! Token buckets for the publish path (§5.7, DX-N3): a bug guard on what the sidecar injects
//! into the beacon node, not a normal control. Callers pass the current instant, so the
//! buckets hold no clock and a test drives them with plain `Instant` arithmetic.

use std::time::Instant;

use crate::config::PublishRateLimit;
use crate::topic::Class;

const NANOS_PER_SEC: u128 = 1_000_000_000;

fn nanos(tokens: u64) -> u128 {
    u128::from(tokens) * NANOS_PER_SEC
}

/// Tokens that refill at a fixed rate up to a burst. The level is kept in token-nanoseconds
/// so a refill by elapsed time is exact integer arithmetic: no float drift can push the level
/// past the burst or make a bucket admit what it should not.
#[derive(Clone, Debug)]
pub struct TokenBucket {
    rate_per_s: u64,
    burst_nanos: u128,
    level_nanos: u128,
    last: Instant,
}

impl TokenBucket {
    /// A full bucket at `now` that refills `rate_per_s` tokens per second and holds at most
    /// `burst`.
    pub fn new(rate_per_s: u64, burst: u64, now: Instant) -> Self {
        let burst_nanos = nanos(burst);
        Self {
            rate_per_s,
            burst_nanos,
            level_nanos: burst_nanos,
            last: now,
        }
    }

    /// Takes `tokens` if the bucket, refilled up to `now`, holds that many. A refused take
    /// leaves the level alone.
    pub fn try_take(&mut self, tokens: u64, now: Instant) -> bool {
        let admitted = self.can_take(tokens, now);
        if admitted {
            self.take(tokens);
        }
        admitted
    }

    fn can_take(&mut self, tokens: u64, now: Instant) -> bool {
        self.refill(now);
        self.level_nanos >= nanos(tokens)
    }

    fn take(&mut self, tokens: u64) {
        self.level_nanos = self.level_nanos.saturating_sub(nanos(tokens));
    }

    fn refill(&mut self, now: Instant) {
        if now <= self.last {
            return;
        }
        let elapsed = (now - self.last).as_nanos();
        self.last = now;
        self.level_nanos =
            (self.level_nanos + elapsed * u128::from(self.rate_per_s)).min(self.burst_nanos);
    }
}

/// The three buckets of DX-N3: one per [`Class`] on message count and one on payload bytes
/// shared by both. Each bursts to one second of its rate.
#[derive(Clone, Debug)]
pub struct PublishLimits {
    small: TokenBucket,
    large: TokenBucket,
    bytes: TokenBucket,
}

impl PublishLimits {
    /// Full buckets at `now` from `bn.publish_rate_limit`. A constructor rather than a `From`
    /// impl because the buckets need the instant they start counting from.
    pub fn new(cfg: &PublishRateLimit, now: Instant) -> Self {
        let bucket = |rate: u64| TokenBucket::new(rate, rate, now);
        Self {
            small: bucket(cfg.small_per_s.into()),
            large: bucket(cfg.large_per_s.into()),
            bytes: bucket(cfg.bytes_per_s),
        }
    }

    /// Whether an item of `class` and `bytes` may go to the beacon node now. Admission costs
    /// one token from the class bucket and `bytes` from the bytes bucket; both are checked
    /// before either is charged, so a refused item costs nothing.
    pub fn admit(&mut self, class: Class, bytes: usize, now: Instant) -> bool {
        let bytes = bytes as u64;
        let by_class = match class {
            Class::Small => &mut self.small,
            Class::Large => &mut self.large,
        };
        if !(by_class.can_take(1, now) && self.bytes.can_take(bytes, now)) {
            return false;
        }
        by_class.take(1);
        self.bytes.take(bytes);
        true
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::config::PublishRateLimit;
    use crate::topic::Class;

    #[test]
    fn token_bucket_allows_burst_then_refills_at_rate() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new(10, 5, start);

        for _ in 0..5 {
            assert!(bucket.try_take(1, start));
        }
        assert!(!bucket.try_take(1, start));

        // At 10 per second, 100 ms buys exactly one token.
        let later = start + Duration::from_millis(100);
        assert!(bucket.try_take(1, later));
        assert!(!bucket.try_take(1, later));

        // Idle for far longer than a burst is worth: back at the burst, not above it.
        let much_later = later + Duration::from_secs(60);
        for _ in 0..5 {
            assert!(bucket.try_take(1, much_later));
        }
        assert!(!bucket.try_take(1, much_later));
    }

    #[test]
    fn token_bucket_denies_when_empty() {
        let start = Instant::now();
        let mut bucket = TokenBucket::new(1000, 3, start);
        assert!(bucket.try_take(3, start));

        assert!(!bucket.try_take(1, start));

        // More than the burst can never be taken at once, and asking leaves the level alone.
        let later = start + Duration::from_secs(10);
        assert!(!bucket.try_take(4, later));
        assert!(bucket.try_take(3, later));
        assert!(!bucket.try_take(1, later));
    }

    fn limits() -> PublishRateLimit {
        PublishRateLimit {
            small_per_s: 2,
            large_per_s: 1,
            bytes_per_s: 10,
        }
    }

    #[test]
    fn publish_limits_burst_is_one_second_of_each_rate() {
        let start = Instant::now();
        let mut limits = PublishLimits::new(&limits(), start);

        assert!(limits.admit(Class::Small, 0, start));
        assert!(limits.admit(Class::Small, 0, start));
        assert!(!limits.admit(Class::Small, 0, start));
        assert!(limits.admit(Class::Large, 10, start));
        assert!(!limits.admit(Class::Large, 0, start));

        let later = start + Duration::from_secs(1);
        assert!(limits.admit(Class::Large, 10, later));
        assert!(!limits.admit(Class::Small, 1, later));
    }

    #[test]
    fn publish_limits_refused_item_takes_no_tokens() {
        let start = Instant::now();
        let mut limits = PublishLimits::new(&limits(), start);

        // The large bucket has its token but the bytes bucket cannot cover the payload.
        assert!(!limits.admit(Class::Large, 11, start));
        // Nothing was charged: the token is still there for a payload that fits.
        assert!(limits.admit(Class::Large, 4, start));
        // The large bucket is empty; the refusal leaves the six bytes for the small class.
        assert!(!limits.admit(Class::Large, 1, start));
        assert!(limits.admit(Class::Small, 6, start));
        assert!(!limits.admit(Class::Small, 1, start));
    }
}
