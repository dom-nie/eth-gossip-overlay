//! The task that keeps the sidecar connected to its beacon node: dial, explicit peer,
//! reconnect with backoff, and the hand-off of everything the swarm produces to the rest of
//! the sidecar without ever waiting on it.

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use prometheus_client::registry::Registry;
    use tokio::sync::mpsc;

    use super::*;
    use crate::bn_http::BnClient;
    use crate::gossip::BnLinkConfig;
    use crate::node_key::NodeKey;
    use crate::testutil::FakeBn;

    /// Long enough for a dial, a noise handshake and a gossipsub exchange on a loaded CI box,
    /// short enough that a test which waits in vain still ends inside its 5 s budget.
    const WAIT: Duration = Duration::from_secs(3);

    fn link_config(bn: &FakeBn) -> LinkConfig {
        LinkConfig {
            libp2p_addr: bn.addr(),
            backoff_min: Duration::from_millis(10),
            backoff_max: Duration::from_millis(100),
            gossip: BnLinkConfig {
                idontwant_on_publish: true,
            },
        }
    }

    /// A running link and the test's ends of its channels.
    struct Harness {
        link: BnLink,
        control: mpsc::Receiver<BnEvent>,
        commands: mpsc::Sender<BnCommand>,
        _dir: tempfile::TempDir,
    }

    fn node_key(dir: &tempfile::TempDir) -> NodeKey {
        NodeKey::load_or_create(&dir.path().join("node.key")).unwrap()
    }

    fn spawn(cfg: LinkConfig, bn: &FakeBn) -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let (control_tx, control) = mpsc::channel(64);
        let (commands, commands_rx) = mpsc::channel(64);
        let link = BnLink::spawn(
            cfg,
            &node_key(&dir),
            BnClient::new(bn.http_addr(), Duration::from_secs(2)),
            &mut Registry::default(),
            control_tx,
            commands_rx,
        );
        Harness {
            link,
            control,
            commands,
            _dir: dir,
        }
    }

    async fn next_event(control: &mut mpsc::Receiver<BnEvent>) -> BnEvent {
        tokio::time::timeout(WAIT, control.recv())
            .await
            .expect("no control event arrived in time")
            .expect("the link ended")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn link_connects_and_emits_connected_with_bn_peer_id() {
        let bn = FakeBn::start().await;
        let mut harness = spawn(link_config(&bn), &bn);

        let event = next_event(&mut harness.control).await;

        assert_eq!(
            event,
            BnEvent::Connected {
                peer_id: bn.peer_id()
            }
        );
        assert!(!harness.link.task.is_finished());
        drop(harness.commands);
    }
}
