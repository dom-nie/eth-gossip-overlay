#[cfg(test)]
mod tests {
    use std::sync::{Arc, LazyLock, Mutex};
    use std::time::Duration;

    use libp2p::PeerId;
    use libp2p::gossipsub;
    use libp2p::identity::Keypair;
    use overlay_core::fanout::Outbound;
    use overlay_core::lanes::{ClassLanes, LanePusher};
    use overlay_core::msgid::{self, MessageId};
    use overlay_core::seen::{SeenCache, SharedSeenCache};
    use overlay_core::time::FakeClock;
    use overlay_core::topic::{Class, Topic};
    use tokio::sync::mpsc;

    use super::*;
    use crate::gossip::wire;
    use crate::link::{BnCommand, BnMessage};

    const ATTESTATION_3: &str = "/eth2/00000000/beacon_attestation_3/ssz_snappy";
    const BLOCK: &str = "/eth2/00000000/beacon_block/ssz_snappy";

    static BN: LazyLock<PeerId> =
        LazyLock::new(|| Keypair::generate_ed25519().public().to_peer_id());

    /// A message as the link pushes it: `data` is the wire payload and the id is the one
    /// T-012's function gives it, so two payloads never share an id and a repeat is a real
    /// duplicate.
    fn message(topic: &str, data: &[u8]) -> BnMessage {
        let id = msgid::compute(topic, data, wire::MAX_PAYLOAD_SIZE as usize).id;
        BnMessage {
            id: gossipsub::MessageId::from(&id.0[..]),
            topic: topic.to_owned(),
            data: data.to_vec(),
            source: *BN,
        }
    }

    fn core_id(msg: &BnMessage) -> MessageId {
        MessageId::from_slice(&msg.id.0).unwrap()
    }

    /// Every stats call in the order it was made.
    #[derive(Default)]
    struct Recorded(Mutex<Vec<(&'static str, Class)>>);

    impl Recorded {
        fn record(&self, what: &'static str, class: Class) {
            self.0.lock().unwrap().push((what, class));
        }

        fn count(&self, what: &str, class: Class) -> usize {
            self.0
                .lock()
                .unwrap()
                .iter()
                .filter(|(w, c)| *w == what && *c == class)
                .count()
        }

        fn total(&self) -> usize {
            self.0.lock().unwrap().len()
        }
    }

    impl InboundStats for Recorded {
        fn first_seen(&self, class: Class) {
            self.record("first_seen", class);
        }

        fn duplicate(&self, class: Class) {
            self.record("duplicate", class);
        }

        fn dropped_full(&self, class: Class) {
            self.record("dropped_full", class);
        }

        fn unknown_kind(&self, class: Class) {
            self.record("unknown_kind", class);
        }
    }

    /// The task's surroundings. Messages pushed before [`start`](Self::start) are waiting in
    /// the lanes when the task begins; pushes after it go through the same pusher the link
    /// would hold.
    struct Harness {
        lanes: Option<ClassLanes<BnMessage>>,
        pusher: LanePusher<BnMessage>,
        command_tx: mpsc::Sender<BnCommand>,
        commands: mpsc::Receiver<BnCommand>,
        seen: SharedSeenCache,
        out: ClassLanes<Outbound>,
        clock: FakeClock,
        stats: Arc<Recorded>,
    }

    impl Harness {
        fn new() -> Self {
            Self::with_out(ClassLanes::new(Arc::new(())))
        }

        fn with_out(out: ClassLanes<Outbound>) -> Self {
            let lanes = ClassLanes::new(Arc::new(()));
            let (command_tx, commands) = mpsc::channel(64);
            let clock = FakeClock::new();
            let seen = SharedSeenCache::new(SeenCache::new(
                Duration::from_secs(60),
                1024,
                Arc::new(clock.clone()),
            ));
            Self {
                pusher: lanes.pusher(),
                lanes: Some(lanes),
                command_tx,
                commands,
                seen,
                out,
                clock,
                stats: Arc::new(Recorded::default()),
            }
        }

        fn push(&self, class: Class, msg: BnMessage) {
            self.pusher.push(class, msg).unwrap();
        }

        fn start(&mut self) {
            Inbound::spawn(
                self.lanes.take().expect("start() is called once"),
                self.command_tx.clone(),
                self.seen.clone(),
                self.out.pusher(),
                Arc::new(self.clock.clone()),
                self.stats.clone(),
            );
        }
    }

    #[tokio::test]
    async fn new_message_is_forwarded_once_with_topic_class_id_and_payload() {
        let mut h = Harness::new();
        h.clock.advance(Duration::from_secs(5));
        let msg = message(ATTESTATION_3, b"an attestation");
        h.push(Class::Small, msg.clone());
        h.start();

        let out = h.out.recv().await;

        assert_eq!(out.topic, Topic::parse(ATTESTATION_3).unwrap());
        assert_eq!(out.class, Class::Small);
        assert_eq!(out.id, core_id(&msg));
        assert_eq!(out.payload, msg.data);
        assert_eq!(out.received_at, h.clock.now());
        assert_eq!(h.stats.count("first_seen", Class::Small), 1);
        assert_eq!(h.stats.total(), 1);
    }
}
