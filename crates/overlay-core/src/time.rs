//! Injected time. Anything that asks "what time is it" takes a [`Clock`] so tests can drive it
//! with [`FakeClock`] instead of sleeping.

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    #[test]
    fn fake_clock_starts_at_construction_time_and_does_not_move_on_its_own() {
        let before = Instant::now();
        let clock = FakeClock::new();
        let after = Instant::now();

        let first = clock.now();
        let second = clock.now();

        assert!(before <= first && first <= after);
        assert_eq!(first, second);
    }
}
