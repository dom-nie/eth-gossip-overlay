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
}
