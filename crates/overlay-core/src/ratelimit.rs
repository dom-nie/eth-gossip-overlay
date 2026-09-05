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
}
