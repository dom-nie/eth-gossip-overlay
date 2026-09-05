//! Reconnect delays that double from a floor to a ceiling, with jitter so peers that lost the
//! same connection at the same moment do not all retry in lockstep.

use std::time::Duration;

use rand::Rng;

/// Reconnect delays that start at `min` and double on every call until they reach `max`.
/// `min` must not exceed `max`.
#[derive(Clone, Debug)]
pub struct Backoff {
    max: Duration,
    next: Duration,
}

impl Backoff {
    /// A backoff whose first delay is `min`.
    pub fn new(min: Duration, max: Duration) -> Self {
        Self { max, next: min }
    }

    /// The delay to wait before the next attempt.
    pub fn next_delay(&mut self, _rng: &mut impl Rng) -> Duration {
        let delay = self.next;
        self.next = self.next.saturating_mul(2).min(self.max);
        delay
    }
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::time::Duration;

    use proptest::prelude::*;
    use rand::rngs::StdRng;
    use rand::{SeedableRng, TryRng};

    use super::*;

    /// An RNG that always draws zero, which the jitter maps to the full, un-jittered delay.
    struct NoJitter;

    impl TryRng for NoJitter {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Infallible> {
            Ok(0)
        }

        fn try_next_u64(&mut self) -> Result<u64, Infallible> {
            Ok(0)
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
            dst.fill(0);
            Ok(())
        }
    }

    #[test]
    fn backoff_starts_at_min_and_doubles_up_to_max() {
        let mut backoff = Backoff::new(Duration::from_millis(100), Duration::from_millis(1000));

        let delays: Vec<Duration> = (0..6).map(|_| backoff.next_delay(&mut NoJitter)).collect();

        assert_eq!(
            delays,
            [100, 200, 400, 800, 1000, 1000].map(Duration::from_millis)
        );
    }

    proptest! {
        #[test]
        fn backoff_jitter_stays_within_documented_bounds(
            min_ms in 1u64..=60_000,
            max_ms in 1u64..=600_000,
            seed: u64,
        ) {
            let min = Duration::from_millis(min_ms);
            let max = Duration::from_millis(max_ms.max(min_ms));
            let mut jittered = Backoff::new(min, max);
            let mut plain = Backoff::new(min, max);
            let mut rng = StdRng::seed_from_u64(seed);

            let mut moved = false;
            for _ in 0..8 {
                let full = plain.next_delay(&mut NoJitter);
                let delay = jittered.next_delay(&mut rng);
                prop_assert!(full / 2 <= delay && delay <= full, "{delay:?} outside [{:?}, {full:?}]", full / 2);
                moved |= delay != full;
            }
            prop_assert!(moved, "eight seeded draws never moved the delay off the un-jittered value");
        }
    }
}
