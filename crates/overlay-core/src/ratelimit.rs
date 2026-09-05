//! Token buckets for the publish path (§5.7, DX-N3): a bug guard on what the sidecar injects
//! into the beacon node, not a normal control. Callers pass the current instant, so the
//! buckets hold no clock and a test drives them with plain `Instant` arithmetic.

use std::time::Instant;

const NANOS_PER_SEC: u128 = 1_000_000_000;

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
        let burst_nanos = u128::from(burst) * NANOS_PER_SEC;
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
        self.refill(now);
        let wanted = u128::from(tokens) * NANOS_PER_SEC;
        if self.level_nanos < wanted {
            return false;
        }
        self.level_nanos -= wanted;
        true
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

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

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
}
