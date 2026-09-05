//! Reconnect delays that double from a floor to a ceiling, with jitter so peers that lost the
//! same connection at the same moment do not all retry in lockstep.

#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::time::Duration;

    use rand::TryRng;

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

        assert_eq!(delays, [100, 200, 400, 800, 1000, 1000].map(Duration::from_millis));
    }
}
