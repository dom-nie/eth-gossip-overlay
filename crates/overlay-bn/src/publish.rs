#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use overlay_core::msgid::MessageId;
    use overlay_core::pubqueue::PublishItem;
    use overlay_core::time::FakeClock;
    use overlay_core::topic::{Class, Topic};
    use tokio::sync::mpsc;
    use tokio::task::JoinHandle;

    use super::*;
    use crate::link::BnCommand;

    const ATTESTATION_3: &str = "/eth2/00000000/beacon_attestation_3/ssz_snappy";
    const BLOCK: &str = "/eth2/00000000/beacon_block/ssz_snappy";

    /// An item numbered `n` on the topic its class suggests, with `payload_len` bytes.
    fn sized_item(class: Class, n: usize, payload_len: usize) -> PublishItem {
        let mut id = [0; 20];
        id[..8].copy_from_slice(&(n as u64).to_le_bytes());
        let topic = match class {
            Class::Small => ATTESTATION_3,
            Class::Large => BLOCK,
        };
        PublishItem {
            topic: Topic::parse(topic).unwrap(),
            id: MessageId(id),
            payload: vec![n as u8; payload_len].into(),
            class,
        }
    }

    fn item(class: Class, n: usize) -> PublishItem {
        sized_item(class, n, 100)
    }

    /// Every stats call in the order it was made, keyed by method and, for errors and queue
    /// drops, the reason.
    #[derive(Default)]
    struct Recorded(Mutex<Vec<(String, Class)>>);

    impl Recorded {
        fn record(&self, what: impl Into<String>, class: Class) {
            self.0.lock().unwrap().push((what.into(), class));
        }

        fn count(&self, what: &str, class: Class) -> usize {
            self.0
                .lock()
                .unwrap()
                .iter()
                .filter(|(w, c)| w == what && *c == class)
                .count()
        }

        fn total(&self) -> usize {
            self.0.lock().unwrap().len()
        }
    }

    impl PublishStats for Recorded {
        fn published(&self, class: Class) {
            self.record("published", class);
        }

        fn suppressed_inject_off(&self, class: Class) {
            self.record("suppressed_inject_off", class);
        }

        fn rate_limited(&self, class: Class) {
            self.record("rate_limited", class);
        }

        fn error(&self, class: Class, reason: &'static str) {
            self.record(format!("error:{reason}"), class);
        }

        fn queue_drop(&self, class: Class, reason: DropReason) {
            self.record(format!("queue_drop:{reason:?}"), class);
        }
    }

    /// A running publisher with the command receiver the link would own held by the test.
    struct Harness {
        handle: PublishHandle,
        commands: mpsc::Receiver<BnCommand>,
        #[expect(dead_code, reason = "keeps the task alive for the test's duration")]
        task: JoinHandle<()>,
        stats: Arc<Recorded>,
    }

    impl Harness {
        fn spawn() -> Self {
            let (commands_tx, commands) = mpsc::channel(64);
            let clock = FakeClock::new();
            let stats = Arc::new(Recorded::default());
            let (handle, task) = Publisher::spawn(commands_tx, stats.clone(), Arc::new(clock));
            Self {
                handle,
                commands,
                task,
                stats,
            }
        }

        fn queued(&self) -> usize {
            self.handle.queue.lock().unwrap().len()
        }
    }

    #[tokio::test]
    async fn enqueue_returns_immediately_while_the_drain_task_is_blocked_on_gossipsub() {
        let mut h = Harness::spawn();
        h.handle.enqueue(item(Class::Small, 0));
        let BnCommand::Publish { reply: _held, .. } = h.commands.recv().await.unwrap() else {
            panic!("expected a Publish command");
        };

        let started = Instant::now();
        let outcomes: Vec<_> = (1..=100)
            .map(|n| h.handle.enqueue(item(Class::Small, n)))
            .collect();
        let elapsed = started.elapsed();

        assert!(elapsed < Duration::from_millis(20), "{elapsed:?}");
        assert!(outcomes.iter().all(|o| *o == EnqueueOutcome::Enqueued));
        assert_eq!(h.queued(), 100);
        assert_eq!(h.stats.total(), 0);
    }
}
