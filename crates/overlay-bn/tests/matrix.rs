//! CL-N2's assumptions that need Lighthouse's real peer manager, run against a downloaded
//! release by `scripts/lighthouse-matrix.sh`. Every test is ignored: it needs
//! `LIGHTHOUSE_HTTP` (the beacon API origin), `LIGHTHOUSE_P2P` (`/ip4/127.0.0.1/tcp/<port>`)
//! and `SIDECAR_NODE_KEY` (the node key whose peer id the beacon node was given as
//! `--trusted-peers`); the tests the beacon node has to dial into also read `SIDECAR_LISTEN`,
//! the address it was given in `--libp2p-addresses`. The ten-minute test also reads
//! `LIGHTHOUSE_LOG`, the beacon node's debug-level file log, and runs only under
//! `MATRIX_TEN_MINUTES=1`, which the nightly job sets.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use libp2p::gossipsub::PublishError;
use libp2p::{Multiaddr, PeerId};
use overlay_bn::bn_http::BnClient;
use overlay_bn::gossip::BnLinkConfig;
use overlay_bn::link::{
    BACKOFF_MAX, BACKOFF_MIN, BnCommand, BnEvent, BnLink, BnMessage, LinkConfig,
};
use overlay_bn::node_key::NodeKey;
use overlay_bn::spec::spec_watch;
use overlay_core::lanes::ClassLanes;
use overlay_core::topic::SubscriptionSets;
use prometheus_client::registry::Registry;
use tokio::sync::{mpsc, oneshot, watch};

/// The ticket's bound on connect, trusted and the first mirrored subscription.
const CONNECT: Duration = Duration::from_secs(60);

struct Env {
    http: String,
    p2p: Multiaddr,
    /// Where the sidecar listens for the beacon node's own dial. An ephemeral port unless the
    /// script named one, which it does for the tests the beacon node has to dial into.
    listen: Multiaddr,
    key: NodeKey,
}

fn env() -> Env {
    let var = |name: &str| {
        std::env::var(name).unwrap_or_else(|_| {
            panic!("{name} is not set; run this through scripts/lighthouse-matrix.sh")
        })
    };
    Env {
        http: var("LIGHTHOUSE_HTTP").trim_end_matches('/').to_owned(),
        p2p: var("LIGHTHOUSE_P2P").parse().unwrap(),
        listen: std::env::var("SIDECAR_LISTEN")
            .unwrap_or_else(|_| "/ip4/127.0.0.1/tcp/0".to_owned())
            .parse()
            .unwrap(),
        key: NodeKey::load_or_create(std::path::Path::new(&var("SIDECAR_NODE_KEY"))).unwrap(),
    }
}

struct Sidecar {
    peer_id: PeerId,
    link: BnLink,
    commands: mpsc::Sender<BnCommand>,
    _lanes: ClassLanes<BnMessage>,
    /// Every topic the beacon node has announced so far; the announcements can land before
    /// the connect probe's `BnInfo`, so they are kept rather than skipped.
    subscribed: Vec<String>,
}

fn spawn(env: &Env) -> Sidecar {
    spawn_with(env, &env.key, env.listen.clone(), env.p2p.clone())
}

/// A link under `key`, listening on `listen` and dialling `libp2p_addr`. The three differ from
/// the environment's only for the peers a test attaches itself.
fn spawn_with(env: &Env, key: &NodeKey, listen: Multiaddr, libp2p_addr: Multiaddr) -> Sidecar {
    let (commands, commands_rx) = mpsc::channel(64);
    let (spec_tx, _spec) = spec_watch();
    let (_sets, sets) = watch::channel(SubscriptionSets::default());
    let lanes = ClassLanes::new(Arc::new(()));
    let identity = format!("{}/eth/v1/node/identity", env.http)
        .parse()
        .unwrap();
    let link = BnLink::spawn(
        LinkConfig {
            libp2p_addr,
            listen_addr: listen,
            backoff_min: BACKOFF_MIN,
            backoff_max: BACKOFF_MAX,
            gossip: BnLinkConfig {
                idontwant_on_publish: true,
            },
        },
        key,
        BnClient::new(identity, Duration::from_secs(5)),
        &mut Registry::default(),
        lanes.pusher(),
        spec_tx,
        sets,
        commands_rx,
    );
    Sidecar {
        peer_id: key.peer_id(),
        link,
        commands,
        _lanes: lanes,
        subscribed: Vec::new(),
    }
}

impl Sidecar {
    /// The next event satisfying `wanted` before `deadline`; every event is printed so the
    /// matrix job's output shows what the beacon node did.
    async fn wait_for(
        &mut self,
        deadline: Instant,
        mut wanted: impl FnMut(&BnEvent) -> bool,
    ) -> BnEvent {
        tokio::time::timeout_at(deadline.into(), async {
            loop {
                let event = self.link.events.recv().await.expect("the link ended");
                println!("link event: {event:?}");
                if let BnEvent::Subscribed { topic, .. } = &event {
                    self.subscribed.push(topic.clone());
                }
                if wanted(&event) {
                    return event;
                }
            }
        })
        .await
        .expect("the awaited link event never arrived")
    }

    /// The first topic satisfying `wanted` the beacon node announces, already seen or still
    /// to come before `deadline`.
    async fn subscription(&mut self, deadline: Instant, wanted: impl Fn(&str) -> bool) -> String {
        if let Some(topic) = self.subscribed.iter().find(|topic| wanted(topic)) {
            return topic.clone();
        }
        let BnEvent::Subscribed { topic, .. } = self
            .wait_for(
                deadline,
                |e| matches!(e, BnEvent::Subscribed { topic, .. } if wanted(topic)),
            )
            .await
        else {
            unreachable!()
        };
        topic
    }

    async fn publish(&self, topic: &str, data: &[u8]) -> Result<(), PublishError> {
        let (reply, answer) = oneshot::channel();
        self.commands
            .send(BnCommand::Publish {
                topic: topic.to_owned(),
                data: data.to_vec(),
                reply,
            })
            .await
            .unwrap();
        answer.await.unwrap().map(|_| ())
    }

    /// Connects and checks the beacon node lists the sidecar as trusted.
    async fn connect(&mut self) -> Instant {
        let deadline = Instant::now() + CONNECT;
        self.wait_for(deadline, |e| matches!(e, BnEvent::Connected { .. }))
            .await;
        let info = self
            .wait_for(deadline, |e| matches!(e, BnEvent::BnInfo { .. }))
            .await;
        assert!(
            matches!(
                info,
                BnEvent::BnInfo {
                    trusted: Some(true),
                    ..
                }
            ),
            "the beacon node does not list the sidecar as trusted: {info:?}"
        );
        deadline
    }
}

/// What the beacon node says about who dialled whom, once it has decided. The entry appears a
/// moment after the connection does, so this polls until `deadline`.
async fn peer_direction(env: &Env, peer_id: PeerId, deadline: Instant) -> String {
    tokio::time::timeout_at(deadline.into(), async {
        loop {
            if let Some(peer) = lighthouse_peer(env, peer_id).await
                && let Some(direction) = peer["connection_direction"].as_str()
            {
                return direction.to_owned();
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("the beacon node never reported a connection direction for the peer")
}

/// A loopback port nothing listens on: a link configured with it can never connect by its own
/// dial, so whatever connects it came from the beacon node.
fn closed_port() -> Multiaddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap()
}

/// The sidecar's entry in `GET /lighthouse/peers`, if the beacon node lists it.
async fn lighthouse_peer(env: &Env, peer_id: PeerId) -> Option<serde_json::Value> {
    let peers: Vec<serde_json::Value> = reqwest::get(format!("{}/lighthouse/peers", env.http))
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    peers
        .into_iter()
        .find(|peer| peer["peer_id"] == peer_id.to_string())
        .map(|peer| peer["peer_info"].clone())
}

/// CL-N2 (1), the under-the-cap-and-never-pruned half (MD-01). Connected, listed as
/// trusted, and the first mirrored subscription, all inside the ticket's 60 s. The
/// subscription comes without sync: Lighthouse joins its persistent attestation subnets at
/// startup and its core topics only once synced.
///
/// The beacon node runs at `--target-peers 1`, the smallest value with an inbound slot: at 0
/// v8.2.2 admits nobody, because `service/mod.rs` gives libp2p's connection limits
/// `max_established_incoming = ceil(target * 0.9)`, checked by count before any peer id is
/// known, and the peer manager's own inbound cap exempts a peer with a future duty, never a
/// trusted one. The other half of the assumption, the beacon node dialling the sidecar when
/// its inbound cap is full, is T-020's test 10.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a Lighthouse beacon node: scripts/lighthouse-matrix.sh"]
async fn matrix_trusted_peer_is_admitted_under_the_inbound_cap_and_never_pruned() {
    let env = env();
    let mut sidecar = spawn(&env);

    let deadline = sidecar.connect().await;
    assert!(sidecar.link.connected.load(Ordering::Relaxed));
    let topic = sidecar.subscription(deadline, |_| true).await;

    println!("first mirrored subscription: {topic}");
    let peer = lighthouse_peer(&env, sidecar.peer_id).await.unwrap();
    assert_eq!(peer["is_trusted"], true, "{peer}");
    assert_eq!(peer["connection_status"]["status"], "connected", "{peer}");
}

/// CL-N2 (2). One payload of random bytes on an attestation subnet topic the beacon node
/// announced, then the same well-formed payload every 100 ms for a minute. The sidecar's
/// own gossipsub refuses the repeats as duplicates before they reach the wire, so what the
/// beacon node sees is one invalid message from a trusted peer followed by a quiet minute;
/// through it all the link must stay up and the peer entry trusted and connected. The topic
/// has to be one the beacon node is subscribed to, or gossipsub has nobody to publish to.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a Lighthouse beacon node: scripts/lighthouse-matrix.sh"]
async fn matrix_trusted_peer_survives_one_invalid_message_and_a_period_of_duplicates_only() {
    let env = env();
    let mut sidecar = spawn(&env);
    let deadline = sidecar.connect().await;
    let attestation = sidecar
        .subscription(deadline, |topic| topic.contains("/beacon_attestation_"))
        .await;

    let garbage: Vec<u8> = (0..300u32).map(|i| (i * 7919 % 251) as u8).collect();
    sidecar
        .publish(&attestation, &garbage)
        .await
        .expect("the invalid message must leave the sidecar");
    let duplicate = snap::raw::Encoder::new()
        .compress_vec(&[0x5a; 228])
        .unwrap();
    let mut sent = 0;
    let mut refused_as_duplicate = 0;
    let end = Instant::now() + Duration::from_secs(60);
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    while Instant::now() < end {
        tokio::select! {
            _ = tick.tick() => match sidecar.publish(&attestation, &duplicate).await {
                Ok(()) => sent += 1,
                Err(PublishError::Duplicate) => refused_as_duplicate += 1,
                Err(err) => panic!("publish failed: {err}"),
            },
            event = sidecar.link.events.recv() => {
                let event = event.expect("the link ended");
                println!("link event: {event:?}");
                assert_ne!(event, BnEvent::Disconnected, "the beacon node dropped the sidecar");
            }
        }
    }

    println!(
        "duplicate sent {sent} time(s), refused by the sidecar's own cache {refused_as_duplicate} times"
    );
    assert!(sent >= 1);
    assert!(sidecar.link.connected.load(Ordering::Relaxed));
    let peer = lighthouse_peer(&env, sidecar.peer_id).await.unwrap();
    assert_eq!(peer["is_trusted"], true, "{peer}");
    assert_eq!(peer["connection_status"]["status"], "connected", "{peer}");
}

/// D09's nightly assertion: ten minutes connected, `sync_status: Synced` in
/// `/lighthouse/peers`, and no peer-manager warning naming the sidecar in the beacon node's
/// log. It is what the sidecar's answer to Status buys, and it takes ten minutes, so a run
/// without `--ten-minutes` (`MATRIX_TEN_MINUTES=1`) returns at once.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a Lighthouse beacon node: scripts/lighthouse-matrix.sh --ten-minutes"]
async fn matrix_bn_link_stays_synced_ten_minutes_without_peer_manager_warnings() {
    if std::env::var("MATRIX_TEN_MINUTES").as_deref() != Ok("1") {
        println!("MATRIX_TEN_MINUTES is not 1; run with --ten-minutes for this one");
        return;
    }
    let env = env();
    let log_path =
        std::env::var("LIGHTHOUSE_LOG").expect("LIGHTHOUSE_LOG names the beacon node's log");
    let mut sidecar = spawn(&env);
    sidecar.connect().await;

    let end = Instant::now() + Duration::from_secs(600);
    while let Ok(event) = tokio::time::timeout_at(end.into(), sidecar.link.events.recv()).await {
        let event = event.expect("the link ended");
        println!("link event: {event:?}");
        assert_ne!(
            event,
            BnEvent::Disconnected,
            "the beacon node dropped the sidecar"
        );
    }

    let peer = lighthouse_peer(&env, sidecar.peer_id).await.unwrap();
    let synced = peer["sync_status"] == "Synced" || peer["sync_status"].get("Synced").is_some();
    assert!(synced, "sync_status is not Synced: {}", peer["sync_status"]);
    let log = std::fs::read_to_string(&log_path).unwrap();
    let id = sidecar.peer_id.to_string();
    let warnings: Vec<&str> = log
        .lines()
        .filter(|line| line.contains("WARN") && line.contains(&id))
        .collect();
    assert!(
        warnings.is_empty(),
        "peer-manager warnings about the sidecar:\n{}",
        warnings.join("\n")
    );
}

/// MD-01's outbound half, and CL-N2 (1) as it was reworded: with the beacon node's one inbound
/// slot taken, the sidecar's own dial cannot get in, and the ENR it registers is what makes the
/// beacon node dial it instead. `connection_direction` is the beacon node's own record of who
/// dialled whom, so `Outgoing` is the beacon node saying it did.
///
/// The dummy that fills the slot is a second link under a throwaway key. It dials the beacon
/// node the way any peer would, and it answers Status and Ping, which a bare libp2p swarm does
/// not: an unanswered Status is a fatal peer action, and the slot would be free again within
/// seconds. Its ENR carries port 0, so the beacon node's own dial to it fails and the
/// connection it holds stays inbound.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a Lighthouse beacon node: scripts/lighthouse-matrix.sh"]
async fn matrix_bn_dials_the_listening_sidecar_when_its_inbound_cap_is_full() {
    let env = env();
    let dummy_dir = tempfile::tempdir().unwrap();
    let dummy_key = NodeKey::load_or_create(&dummy_dir.path().join("node.key")).unwrap();
    let mut dummy = spawn_with(
        &env,
        &dummy_key,
        "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
        env.p2p.clone(),
    );
    let filled = Instant::now() + CONNECT;
    dummy
        .wait_for(filled, |e| matches!(e, BnEvent::Connected { .. }))
        .await;
    let holding = peer_direction(&env, dummy.peer_id, filled).await;
    assert_eq!(
        holding, "Incoming",
        "the dummy peer is not on the inbound slot"
    );

    let mut sidecar = spawn(&env);

    let deadline = Instant::now() + Duration::from_secs(30);
    sidecar
        .wait_for(deadline, |e| matches!(e, BnEvent::Connected { .. }))
        .await;
    let direction = peer_direction(&env, sidecar.peer_id, deadline).await;
    let peer = lighthouse_peer(&env, sidecar.peer_id).await.unwrap();
    assert_eq!(direction, "Outgoing", "{peer}");
    assert_eq!(peer["is_trusted"], true, "{peer}");
    drop(dummy);
}

/// The beacon node was started with both flags of the env file MD-01 specifies, and the
/// sidecar's own dial goes to a closed port, so the only way the two can meet is the beacon
/// node dialling the sidecar's listen address. What actually connects them here is the ENR the
/// link registers: `--libp2p-addresses` is dialled once when the network service starts, long
/// before a test process is listening on that port. Its value in this matrix is that the
/// beacon node accepted the flag at all, which is what breaks the day a release removes it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a Lighthouse beacon node: scripts/lighthouse-matrix.sh"]
async fn matrix_bn_startup_flags_dial_the_listening_sidecar() {
    let env = env();
    let mut sidecar = spawn_with(&env, &env.key, env.listen.clone(), closed_port());

    let deadline = Instant::now() + Duration::from_secs(30);
    sidecar
        .wait_for(deadline, |e| matches!(e, BnEvent::Connected { .. }))
        .await;

    let peer = lighthouse_peer(&env, sidecar.peer_id).await.unwrap();
    assert_eq!(peer["connection_direction"], "Outgoing", "{peer}");
}
