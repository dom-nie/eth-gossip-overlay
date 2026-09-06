//! Injected time. Anything that asks "what time is it" takes a [`Clock`] so tests can drive it
//! with [`FakeClock`] instead of sleeping.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime};

/// A source of monotonic time. Production code takes a `Clock` so tests can substitute
/// [`FakeClock`] and drive it by hand.
pub trait Clock: Send + Sync {
    /// The current instant according to this clock.
    fn now(&self) -> Instant;

    /// The same moment as [`now`](Self::now) on the wall clock, which is the only form that
    /// means anything on another host. The event log stamps arrivals with it so a message can
    /// be followed across the fleet (T-044); nothing inside one process should compare it,
    /// because it jumps when the host's clock is stepped.
    fn wall(&self) -> SystemTime;
}

/// The real monotonic clock, for production wiring.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn wall(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// A clock that only moves when a test tells it to. Clones share one reading, so a test can
/// keep a handle while the unit under test owns another.
#[derive(Clone)]
pub struct FakeClock(Arc<Mutex<Reading>>);

/// The two views of one moment. They move together, so a test that advances the clock knows
/// the exact wall time an event carries.
#[derive(Clone, Copy)]
struct Reading {
    instant: Instant,
    wall: SystemTime,
}

impl FakeClock {
    /// Starts at the real current time.
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(Reading {
            instant: Instant::now(),
            wall: SystemTime::now(),
        })))
    }

    /// Moves the clock forward by `by`, both readings together.
    pub fn advance(&self, by: Duration) {
        let mut slot = self.slot();
        slot.instant += by;
        slot.wall += by;
    }

    /// Jumps the clock to `instant`, forwards or backwards. The wall reading moves by the same
    /// amount, so the two never drift apart.
    pub fn set(&self, instant: Instant) {
        let mut slot = self.slot();
        slot.wall = match instant.checked_duration_since(slot.instant) {
            Some(forward) => slot.wall + forward,
            None => slot.wall - (slot.instant - instant),
        };
        slot.instant = instant;
    }

    fn slot(&self) -> MutexGuard<'_, Reading> {
        // A poisoned lock means another test thread panicked mid-update. The stored reading is
        // still a valid one, so recover it instead of spreading the panic.
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
        self.slot().instant
    }

    fn wall(&self) -> SystemTime {
        self.slot().wall
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant, SystemTime};

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

    #[test]
    fn fake_clock_set_moves_the_wall_clock_by_the_same_step() {
        let clock = FakeClock::new();
        let start = clock.wall();

        clock.set(clock.now() + Duration::from_secs(3600));
        assert_eq!(
            clock.wall().duration_since(start).unwrap(),
            Duration::from_secs(3600)
        );

        clock.set(clock.now() - Duration::from_secs(600));
        assert_eq!(
            clock.wall().duration_since(start).unwrap(),
            Duration::from_secs(3000)
        );
    }

    #[test]
    fn fake_clock_advance_moves_the_wall_clock_alongside_the_instant() {
        let clock = FakeClock::new();
        let start = clock.wall();

        clock.advance(Duration::from_nanos(1_500_000_007));

        assert_eq!(
            clock.wall().duration_since(start).unwrap(),
            Duration::from_nanos(1_500_000_007)
        );
    }

    #[test]
    fn system_clock_wall_reads_the_real_time() {
        let before = SystemTime::now();
        let wall = SystemClock.wall();
        let after = SystemTime::now();

        assert!(before <= wall && wall <= after);
    }

    #[test]
    fn system_clock_is_monotonic() {
        let clock = SystemClock;

        let first = clock.now();
        let second = clock.now();

        assert!(second >= first);
    }
}
