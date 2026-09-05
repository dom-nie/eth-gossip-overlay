//! Injected time. Anything that asks "what time is it" takes a [`Clock`] so tests can drive it
//! with [`FakeClock`] instead of sleeping.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// A source of monotonic time. Production code takes a `Clock` so tests can substitute
/// [`FakeClock`] and drive it by hand.
pub trait Clock: Send + Sync {
    /// The current instant according to this clock.
    fn now(&self) -> Instant;
}

/// A clock that only moves when a test tells it to. Clones share one instant, so a test can
/// keep a handle while the unit under test owns another.
#[derive(Clone)]
pub struct FakeClock(Arc<Mutex<Instant>>);

impl FakeClock {
    /// Starts at the real current instant.
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(Instant::now())))
    }

    /// Moves the clock forward by `by`.
    pub fn advance(&self, by: Duration) {
        *self.slot() += by;
    }

    fn slot(&self) -> MutexGuard<'_, Instant> {
        // A poisoned lock means another test thread panicked mid-update. The stored instant is
        // still a valid instant, so recover it instead of spreading the panic.
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Default for FakeClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Instant {
        *self.slot()
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

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

    #[test]
    fn fake_clock_advance_moves_now_by_exactly_that_duration() {
        let clock = FakeClock::new();
        let start = clock.now();

        clock.advance(Duration::from_millis(1500));

        assert_eq!(clock.now() - start, Duration::from_millis(1500));
    }

    #[test]
    fn fake_clock_clones_share_state() {
        let held_by_test = FakeClock::new();
        let held_by_unit_under_test = held_by_test.clone();

        held_by_test.advance(Duration::from_secs(7));

        assert_eq!(held_by_unit_under_test.now(), held_by_test.now());
    }

    #[test]
    fn fake_clock_set_jumps_to_the_given_instant() {
        let clock = FakeClock::new();
        let target = clock.now() + Duration::from_secs(3600);

        clock.set(target);

        assert_eq!(clock.now(), target);
    }
}
