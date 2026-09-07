#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;

    use super::*;
    use crate::roster::Hostname;
    use crate::time::{Clock, FakeClock};
    use crate::topic::table::TopicId;

    const WINDOW: Duration = Duration::from_millis(10);
    const STALE_AFTER: Duration = Duration::from_millis(1000);

    /// A datagram limit in the range path MTU discovery reports on the public internet (§5.4).
    const MAX_BYTES: usize = 1200;

    fn batcher() -> Batcher {
        Batcher::new(WINDOW, STALE_AFTER)
    }

    fn dest(name: &str) -> Hostname {
        Hostname(name.to_owned())
    }

    /// An attestation-sized payload, filled with `byte` so a test can tell entries apart.
    fn payload(byte: u8) -> Bytes {
        Bytes::from(vec![byte; 240])
    }

    #[test]
    fn single_payload_is_not_flushed_before_the_window() {
        let clock = FakeClock::new();
        let mut batcher = batcher();

        let pushed = batcher.push(
            &dest("host-a"),
            TopicId::new(1),
            payload(1),
            MAX_BYTES,
            clock.now(),
        );
        assert!(pushed.is_empty());

        clock.advance(WINDOW - Duration::from_millis(1));

        assert!(batcher.tick(clock.now()).is_empty());
    }
}
