#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use super::*;

    const TOPIC: &str = "/eth2/00000000/beacon_block/ssz_snappy";

    /// An item numbered `n`, so a test can tell which entries survived.
    fn item(class: Class, n: usize, payload_len: usize) -> PublishItem {
        let mut id = [0; 20];
        id[..8].copy_from_slice(&(n as u64).to_le_bytes());
        PublishItem {
            topic: Topic::parse(TOPIC).unwrap(),
            id: MessageId(id),
            payload: vec![0; payload_len].into(),
            class,
        }
    }

    fn number(item: &PublishItem) -> usize {
        u64::from_le_bytes(item.id.0[..8].try_into().unwrap()) as usize
    }

    #[derive(Default)]
    struct Recorded(Mutex<Vec<(Class, DropReason)>>);

    impl Recorded {
        fn drops(&self) -> Vec<(Class, DropReason)> {
            self.0.lock().unwrap().clone()
        }
    }

    impl QueueStats for Recorded {
        fn dropped(&self, class: Class, reason: DropReason) {
            self.0.lock().unwrap().push((class, reason));
        }
    }

    #[test]
    fn queue_small_lane_drops_oldest_past_4096_entries() {
        let stats = Arc::new(Recorded::default());
        let mut queue = PublishQueue::new(stats.clone());
        let now = Instant::now();
        for n in 0..PUBLISH_SMALL_LANE_ENTRIES {
            assert_eq!(
                queue.push(item(Class::Small, n, 100), now),
                Pushed::Enqueued
            );
        }

        let pushed = queue.push(item(Class::Small, PUBLISH_SMALL_LANE_ENTRIES, 100), now);

        assert_eq!(
            pushed,
            Pushed::Dropped {
                class: Class::Small,
                reason: DropReason::Full
            }
        );
        assert_eq!(stats.drops(), vec![(Class::Small, DropReason::Full)]);
        assert_eq!(queue.len(), PUBLISH_SMALL_LANE_ENTRIES);
        let survivors: Vec<usize> =
            std::iter::from_fn(|| queue.pop(now).as_ref().map(number)).collect();
        assert_eq!(
            survivors,
            (1..=PUBLISH_SMALL_LANE_ENTRIES).collect::<Vec<_>>()
        );
    }
}
