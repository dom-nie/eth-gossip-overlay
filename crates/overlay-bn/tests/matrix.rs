//! CL-N2's assumptions that need Lighthouse's real peer manager, run against a downloaded
//! release by `scripts/lighthouse-matrix.sh`. Every test is ignored: it needs
//! `LIGHTHOUSE_HTTP` (the beacon API origin), `LIGHTHOUSE_P2P` (`/ip4/127.0.0.1/tcp/<port>`)
//! and `SIDECAR_NODE_KEY` (the node key whose peer id the beacon node was given as
//! `--trusted-peers`); the tests the beacon node has to dial into also read `SIDECAR_LISTEN`,
//! the address it was given in `--libp2p-addresses`. The ten-minute test also reads
//! `LIGHTHOUSE_LOG`, the beacon node's debug-level file log, and runs only under
//! `MATRIX_TEN_MINUTES=1`, which the nightly job sets. The test that reads events into the
//! custody tracker needs a beacon node that is following the chain rather than the script's
//! genesis-only node, and runs only under `MATRIX_FOLLOWING_CHAIN=1`; the one that checks the
//! node accepts the shipped topics does not.
//!
//! The tests gated on `MATRIX_GLOAS=1` need the Gloas devnet `scripts/lighthouse-matrix.sh
//! <version> --gloas` brings up: `LIGHTHOUSE_HTTP`, `LIGHTHOUSE_P2P` and `LIGHTHOUSE_METRICS`
//! name the node that follows the chain with public peers, `LIGHTHOUSE_FAR_HTTP`,
//! `LIGHTHOUSE_FAR_P2P` and `LIGHTHOUSE_FAR_METRICS` the node whose only gossip peers are
//! sidecars and `LIGHTHOUSE_FAR_LOG` its debug-level file log, `SIDECAR_FAR_LOG`,
//! `SIDECAR_FAR_ADMIN` and `SIDECAR_FAR_METRICS` that node's shipped sidecar's JSON log, admin
//! socket and metrics origin, `SIDECAR_CTL` the ctl binary, `LIGHTHOUSE_PROPOSERS` the
//! `first-last` validator indices the near node's own validator client runs, and
//! `MATRIX_SLOTS` how many slots the counting tests watch (64 unless set).
//! The by-root test needs that devnet brought up with `GLOAS_BY_ROOT=1`, and is the only test
//! the script runs on it.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use libp2p::gossipsub::PublishError;
use libp2p::{Multiaddr, PeerId};
use overlay_bn::bn_http::BnClient;
use overlay_bn::decode::Headers;
use overlay_bn::events::BlockEvents;
use overlay_bn::gossip::BnLinkConfig;
use overlay_bn::link::{
    BACKOFF_MAX, BACKOFF_MIN, BnCommand, BnEvent, BnLink, BnMessage, LinkConfig,
};
use overlay_bn::node_key::NodeKey;
use overlay_bn::rpc::proto::Protocol;
use overlay_bn::rpc::{ByRootCache, ByRootOutcome, ByRootStats};
use overlay_bn::spec::spec_watch;
use overlay_bn::testutil::by_root_off;
use overlay_core::backoff::Backoff;
use overlay_core::config::Config;
use overlay_core::custody::SharedCustody;
use overlay_core::events::Arrivals;
use overlay_core::header::{Header, HeaderDecoder};
use overlay_core::lanes::ClassLanes;
use overlay_core::recent::{RECENT_MAX_BYTES, RECENT_TTL, RecentLarge, SharedRecentLarge};
use overlay_core::spec::SpecSnapshot;
use overlay_core::time::SystemClock;
use overlay_core::topic::{Class, SubscriptionSets, Topic, TopicKind};
use prometheus_client::registry::Registry;
use ssz::Decode;
use tokio::sync::{mpsc, oneshot, watch};
use types::{MainnetEthSpec, SignedExecutionPayloadEnvelope};

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
    /// What the beacon node forwarded, by class.
    lanes: ClassLanes<BnMessage>,
    /// The spec the connect probe read off the beacon node.
    spec: watch::Receiver<SpecSnapshot>,
    /// Every topic the beacon node has announced so far; the announcements can land before
    /// the connect probe's `BnInfo`, so they are kept rather than skipped.
    subscribed: Vec<String>,
}

fn spawn(env: &Env) -> Sidecar {
    spawn_with(
        env,
        &env.key,
        env.listen.clone(),
        env.p2p.clone(),
        by_root_off(),
    )
}

/// A link under `key`, listening on `listen` and dialling `libp2p_addr`, answering by-root
/// requests out of `by_root`. The addresses differ from the environment's only for the peers a
/// test attaches itself; the cache is counted only by the test that watches refusals.
fn spawn_with(
    env: &Env,
    key: &NodeKey,
    listen: Multiaddr,
    libp2p_addr: Multiaddr,
    by_root: ByRootCache,
) -> Sidecar {
    let (commands, commands_rx) = mpsc::channel(64);
    let (spec_tx, spec) = spec_watch();
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
        Arc::default(),
        by_root,
    );
    Sidecar {
        peer_id: key.peer_id(),
        link,
        commands,
        lanes,
        spec,
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
        by_root_off(),
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
/// link registers: on v8.2 `--libp2p-addresses` is dialled once when the network service
/// starts, long before a test process is listening on that port, and from v8.3.0 it is never
/// dialled at all. Its value in this matrix is that the beacon node accepted the flag at all,
/// which is what breaks the day a release removes it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a Lighthouse beacon node: scripts/lighthouse-matrix.sh"]
async fn matrix_bn_startup_flags_dial_the_listening_sidecar() {
    let env = env();
    let mut sidecar = spawn_with(
        &env,
        &env.key,
        env.listen.clone(),
        closed_port(),
        by_root_off(),
    );

    let deadline = Instant::now() + Duration::from_secs(30);
    sidecar
        .wait_for(deadline, |e| matches!(e, BnEvent::Connected { .. }))
        .await;

    let peer = lighthouse_peer(&env, sidecar.peer_id).await.unwrap();
    assert_eq!(peer["connection_direction"], "Outgoing", "{peer}");
}

/// T-102. The sidecar answers MetaData v2, which has no custody group count, and for a peer
/// with no ENR that count is the only thing Lighthouse assigns custody subnets from: a v2 body
/// is "gracefully ignored" by `meta_data_response`
/// (`beacon_node/lighthouse_network/src/peer_manager/mod.rs:767-770`). Both places that make a
/// peer count as a custody peer read that assignment and nothing else,
/// `has_good_peers_in_custody_subnet` (`peer_manager/peerdb.rs:344-365`) and
/// `good_custody_subnet_peer` (`:297-313`), so an empty set here is what keeps the sidecar from
/// standing in for a real custody peer in the node's discovery, or from being asked for a column
/// it would refuse. Trust is untouched: the entry is still `is_trusted`, and `connect` already
/// saw the `BnInfo` the `overlay_bn_trusted` gauge is fed from.
///
/// The node asks a new peer for metadata on its first ping exchange, up to 20 s after connect,
/// and assigns the subnets under the same lock it stores the metadata under, so once the entry
/// carries `meta_data` the assignment is whatever it is going to be.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a Lighthouse beacon node: scripts/lighthouse-matrix.sh"]
async fn matrix_node_assigns_the_sidecar_no_custody_subnets() {
    let env = env();
    let mut sidecar = spawn(&env);
    let deadline = sidecar.connect().await;

    let peer = tokio::time::timeout_at(deadline.into(), async {
        loop {
            if let Some(peer) = lighthouse_peer(&env, sidecar.peer_id).await
                && !peer["meta_data"].is_null()
            {
                return peer;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("the beacon node never obtained the sidecar's metadata");

    println!(
        "meta_data: {} custody_subnets: {}",
        peer["meta_data"], peer["custody_subnets"]
    );
    assert_eq!(peer["custody_subnets"], serde_json::json!([]), "{peer}");
    assert_eq!(peer["is_trusted"], true, "{peer}");
}

/// T-102's third check, which the beacon API cannot show. `has_good_peers_in_custody_subnet`
/// (`peer_manager/peerdb.rs:344-365`) counts the connected, synced peers whose
/// `is_assigned_to_custody_subnet` holds; its one caller is `maintain_custody_peers`
/// (`peer_manager/mod.rs:978-1003`), and what that decides is a discovery query, which the
/// matrix node runs without (`--disable-discovery`) and a node following the chain does not
/// report. The only input the sidecar can move is its own assignment, and the test above pins
/// that empty, so the sidecar adds zero to every subnet's count by construction.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "has_good_peers_in_custody_subnet is not on the beacon API; matrix_node_assigns_the_sidecar_no_custody_subnets pins its input"]
async fn matrix_discovery_is_not_satisfied_by_the_sidecar() {
    println!(
        "skipped: has_good_peers_in_custody_subnet is not on the beacon API; \
         matrix_node_assigns_the_sidecar_no_custody_subnets pins its input"
    );
}

/// T-120: the beacon node accepts every topic the shipped `bn.events_url` asks for. Lighthouse
/// answers 400 to a topic it does not know, which would leave import telemetry and column repair
/// off, so a 200 with the event-stream content type on every release in `SUPPORTED` is the
/// proof. A genesis-only node sends no events, so only the response head is read, and this
/// test needs no node following the chain.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a Lighthouse beacon node: scripts/lighthouse-matrix.sh"]
async fn matrix_node_accepts_the_shipped_event_topics() {
    let env = env();
    let shipped = Config::default().bn.events_url;
    let url = format!(
        "{}{}?{}",
        env.http,
        shipped.path(),
        shipped
            .query()
            .expect("the shipped events_url names its topics")
    );

    let response = tokio::time::timeout(CONNECT, reqwest::get(&url))
        .await
        .expect("the beacon node answered the event stream request")
        .expect("the event stream request reached the beacon node");

    assert_eq!(response.status(), reqwest::StatusCode::OK, "{url}");
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(
        content_type.starts_with("text/event-stream"),
        "{url}: {content_type}"
    );
}

/// CL-N2 (7), the assumption T-087's custody tracker rests on. Two event names carry the whole
/// of what column repair knows, and neither is promised by the beacon API specification:
/// `block_gossip` fires inside gossip verification, after the proposer-signature check and after
/// the duplicate check, so a block on it is one this node accepted; `data_column_sidecar` fires
/// after KZG verification, whichever of the four sources the column came from.
///
/// What a running node can show is that both reach the tracker: a block opens an entry, and
/// columns clear expectations inside it. The expected set here is every column on the network,
/// which no node custodies, so the entry keeps a gap to read `have_count` off. Which of the four
/// sources a column came from is not in the payload and cannot be asserted from the API; a
/// release that stopped firing either event fails this test by name.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a Lighthouse beacon node following the chain: MATRIX_FOLLOWING_CHAIN=1"]
async fn matrix_event_stream_reports_accepted_blocks_and_verified_columns() {
    if std::env::var("MATRIX_FOLLOWING_CHAIN").as_deref() != Ok("1") {
        println!("MATRIX_FOLLOWING_CHAIN is not 1; this one needs a node following the chain");
        return;
    }
    let env = env();
    let (_spec_tx, spec) = spec_watch();
    let columns = spec.borrow().number_of_columns;
    let (_sets_tx, sets) = watch::channel(every_column_topic(columns));
    let arrivals = Arc::new(Arrivals::new(Arc::new(SystemClock), spec_watch().1));
    let custody = SharedCustody::new(spec, sets, arrivals.clone(), Arc::new(()));

    let shipped = Config::default().bn.events_url;
    let events = BlockEvents::spawn(
        format!(
            "{}{}?{}",
            env.http,
            shipped.path(),
            shipped
                .query()
                .expect("the shipped events_url names its topics")
        )
        .parse()
        .unwrap(),
        Backoff::new(BACKOFF_MIN, BACKOFF_MAX),
        arrivals,
        custody.clone(),
        Arc::new(SystemClock),
        Arc::new(()),
    );

    let none = custody.column_set([]);
    let deadline = Instant::now() + THREE_SLOTS;
    let held = loop {
        assert!(
            Instant::now() < deadline,
            "no block and columns within three slots"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        let gaps = custody.gaps(Duration::ZERO, Instant::now(), &none);
        let Some(gap) = gaps.first() else { continue };
        if gap.have_count > 0 {
            break gap.have_count;
        }
    };

    println!("columns verified for the block this node accepted: {held}");
    events.task.abort();
}

/// Long enough that a block and its columns cannot all have been missed, short enough that a
/// beacon node which has stopped firing the events fails rather than hangs the nightly job.
const THREE_SLOTS: Duration = Duration::from_secs(40);

/// Every column topic there is, which is the widest expected set: no node custodies all of them,
/// so the tracker always has a gap to report `have_count` from. The digest is a placeholder,
/// because the tracker reads only the column index out of a topic.
fn every_column_topic(columns: u64) -> SubscriptionSets {
    let advertised = (0..columns)
        .filter_map(|index| {
            Topic::parse(&format!(
                "/eth2/6a95a1a9/data_column_sidecar_{index}/ssz_snappy"
            ))
            .ok()
        })
        .collect();
    SubscriptionSets {
        advertised,
        ..SubscriptionSets::default()
    }
}

/// T-101 test 1 on a real node, and the assumption `COMPATIBILITY.md` names for it: Lighthouse
/// seeds a parent lookup with the block's sender and nobody else (`block_lookups/mod.rs:175-189`
/// at v8.2.2), asks that peer again at once on `ResourceUnavailable`
/// (`single_block_lookup.rs:609-618`) and drops the lookup and the block on the fourth failure
/// (`mod.rs:657-661`). The sidecar hands the node its own head block rewritten with a parent
/// root nobody has, at the slot after the head's so the node has observed no proposal for the
/// pair and the parent check is the first to fail, then counts what the node asks it: four
/// refusals on `beacon_blocks_by_root` and no more. With `LIGHTHOUSE_METRICS` naming the node's
/// metrics port, its `sync_lookups_dropped_total{reason="TooManyAttempts"}` is read before and
/// after as well.
///
/// The publish here goes straight to gossipsub, past the check `receive.rs` puts in front of a
/// real one, which is what makes the four refusals observable; the check itself is pinned on the
/// transport cluster and the fleet. A release on which this count changes is the one that
/// retires the check, and this test is where that shows.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a Lighthouse beacon node following the chain: MATRIX_FOLLOWING_CHAIN=1"]
async fn matrix_a_block_whose_parent_the_node_lacks_is_dropped_by_lighthouse_after_four_refusals() {
    if std::env::var("MATRIX_FOLLOWING_CHAIN").as_deref() != Ok("1") {
        println!("MATRIX_FOLLOWING_CHAIN is not 1; this one needs a node following the chain");
        return;
    }
    let env = env();
    let refusals = Arc::new(Refusals::default());
    let mut sidecar = spawn_with(
        &env,
        &env.key,
        env.listen.clone(),
        env.p2p.clone(),
        counting(&refusals),
    );
    let deadline = sidecar.connect().await;
    let topic = sidecar
        .subscription(deadline, |topic| topic.contains("/beacon_block/"))
        .await;
    let dropped_before = lookups_dropped().await;

    let mut child = beacon_ssz(&env, "/eth/v2/beacon/blocks/head").await;
    let slot = u64::from_le_bytes(child[100..108].try_into().unwrap()) + 1;
    child[100..108].copy_from_slice(&slot.to_le_bytes());
    child[116..148].copy_from_slice(&rand::random::<[u8; 32]>());
    // The link's gossipsub runs the identity transform, so the wire form is handed over
    // compressed; a raw block would fail the node's decompression before any check.
    let wire = snap::raw::Encoder::new().compress_vec(&child).unwrap();
    wait_for_slot(&env, slot).await;
    sidecar
        .publish(&topic, &wire)
        .await
        .expect("the beacon node takes the block off the wire");

    tokio::time::sleep(Duration::from_secs(5)).await;
    let refused = refusals.blocks.load(Ordering::Relaxed);
    println!("beacon_blocks_by_root refusals: {refused}");
    assert_eq!(
        refused, 4,
        "v8.2.2 asks its only lookup peer four times and then drops the lookup"
    );
    if let Some(before) = dropped_before {
        let after = lookups_dropped().await;
        println!(
            "sync_lookups_dropped_total{{reason=\"TooManyAttempts\"}}: {before} then {after:?}"
        );
        assert_eq!(after, Some(before + 1));
    }
}

/// T-101 test 6: the `block` event fires for a block the node imported over RPC, not only for
/// one that came by gossip, which is what lets the sidecar anchor its parent check on it.
/// `import_block_update_metrics_and_events` registers the event on every import path
/// (`beacon_chain/src/beacon_chain.rs:5099`, the register at `:5153`, at v8.3.2): gossip, RPC
/// by root or by range, and the node's own proposal. `block_gossip` is registered in one
/// place, `GossipVerifiedBlock::new` (`block_verification.rs:1116-1124`), which a gossip block
/// and a block published over the beacon API both go through and a lookup does not;
/// `matrix_block_gossip_does_not_fire_for_a_block_fetched_by_root` is where that is measured.
/// So a `block` for a root no `block_gossip` named is an import that came over RPC. A node in
/// step with the chain may see none inside the window; then the source is what says so, and
/// this prints as much.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a Lighthouse beacon node following the chain: MATRIX_FOLLOWING_CHAIN=1"]
async fn matrix_the_block_event_fires_for_an_rpc_imported_block() {
    if std::env::var("MATRIX_FOLLOWING_CHAIN").as_deref() != Ok("1") {
        println!("MATRIX_FOLLOWING_CHAIN is not 1; this one needs a node following the chain");
        return;
    }
    let env = env();
    let mut events = sse(format!(
        "{}/eth/v1/events?topics=block,block_gossip",
        env.http
    ));
    let mut gossiped = HashSet::new();
    let deadline = Instant::now() + THREE_SLOTS;
    while let Ok(Some((name, data))) = tokio::time::timeout_at(deadline.into(), events.recv()).await
    {
        let Some(root) = data["block"].as_str().map(str::to_owned) else {
            continue;
        };
        match name.as_str() {
            "block_gossip" => {
                gossiped.insert(root);
            }
            "block" if !gossiped.contains(&root) => {
                println!("block {root} imported with no block_gossip before it");
                return;
            }
            _ => {}
        }
    }
    println!(
        "every block imported inside {THREE_SLOTS:?} came by gossip; start the node a few slots \
         behind the head to watch an RPC import register the block event \
         (beacon_chain.rs:5153 at v8.3.2)"
    );
}

/// What the sidecar's responder was asked while the cache is off: the `refused` outcome of
/// `by_root_requests_total`, for blocks and for payload envelopes.
#[derive(Default)]
struct Refusals {
    blocks: AtomicUsize,
    envelopes: AtomicUsize,
}

impl ByRootStats for Refusals {
    fn by_root_request(&self, protocol: Protocol, outcome: ByRootOutcome) {
        if outcome != ByRootOutcome::Refused {
            return;
        }
        match protocol {
            Protocol::BlocksByRootV2 => self.blocks.fetch_add(1, Ordering::Relaxed),
            Protocol::EnvelopesByRootV1 => self.envelopes.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
    }
}

/// The beacon node's event stream at `url`, one `(event, data)` per frame, until the
/// receiver is dropped.
fn sse(url: String) -> mpsc::Receiver<(String, serde_json::Value)> {
    let (tx, rx) = mpsc::channel(4096);
    tokio::spawn(async move {
        let mut response = reqwest::get(&url)
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        let mut buf = Vec::new();
        while let Ok(Some(chunk)) = response.chunk().await {
            buf.extend_from_slice(&chunk);
            while let Some(end) = buf.windows(2).position(|pair| pair == b"\n\n") {
                let frame = String::from_utf8_lossy(&buf[..end]).into_owned();
                buf.drain(..end + 2);
                // Lighthouse writes `event:name` with no space after the colon, which the
                // SSE grammar allows either way.
                let field = |key: &str| {
                    frame
                        .lines()
                        .find_map(|line| line.strip_prefix(key))
                        .map(str::trim_start)
                };
                let name = field("event:");
                let data = field("data:")
                    .and_then(|data| serde_json::from_str::<serde_json::Value>(data).ok());
                if let (Some(name), Some(data)) = (name, data)
                    && tx.send((name.to_owned(), data)).await.is_err()
                {
                    return;
                }
            }
        }
    });
    rx
}

/// The shipped default, cache off and inject on, counted on `refusals`.
fn counting(refusals: &Arc<Refusals>) -> ByRootCache {
    ByRootCache::new(
        SharedRecentLarge::new(RecentLarge::new(RECENT_TTL, RECENT_MAX_BYTES)),
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(true)),
        refusals.clone(),
    )
}

/// `GET {path}` on the beacon API as SSZ.
async fn beacon_ssz(env: &Env, path: &str) -> Vec<u8> {
    reqwest::Client::new()
        .get(format!("{}{path}", env.http))
        .header("Accept", "application/octet-stream")
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .bytes()
        .await
        .unwrap()
        .to_vec()
}

/// `GET {path}` on the beacon API as JSON.
async fn beacon_json(env: &Env, path: &str) -> serde_json::Value {
    reqwest::get(format!("{}{path}", env.http))
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// Sleeps until `slot` has begun on the node's clock, a little past the boundary so the block
/// is inside the clock disparity the node allows rather than ahead of it.
async fn wait_for_slot(env: &Env, slot: u64) {
    let quoted = |value: &serde_json::Value| -> u64 { value.as_str().unwrap().parse().unwrap() };
    let genesis_time =
        quoted(&beacon_json(env, "/eth/v1/beacon/genesis").await["data"]["genesis_time"]);
    let seconds_per_slot =
        quoted(&beacon_json(env, "/eth/v1/config/spec").await["data"]["SECONDS_PER_SLOT"]);
    let starts = UNIX_EPOCH
        + Duration::from_secs(genesis_time + slot * seconds_per_slot)
        + Duration::from_millis(200);
    if let Ok(wait) = starts.duration_since(SystemTime::now()) {
        tokio::time::sleep(wait).await;
    }
}

/// The node's `sync_lookups_dropped_total{reason="TooManyAttempts"}`, from the metrics port
/// `LIGHTHOUSE_METRICS` names as an origin; `None` when the variable is not set.
async fn lookups_dropped() -> Option<u64> {
    let origin = std::env::var("LIGHTHOUSE_METRICS").ok()?;
    let text = reqwest::get(format!("{origin}/metrics"))
        .await
        .ok()?
        .text()
        .await
        .ok()?;
    let series = "sync_lookups_dropped_total{reason=\"TooManyAttempts\"} ";
    let value = text
        .lines()
        .find_map(|line| line.strip_prefix(series))
        .map_or(0.0, |value| value.trim().parse::<f64>().unwrap_or(0.0));
    Some(value as u64)
}

/// The Gloas devnet's extra environment (module doc).
struct Gloas {
    far_http: String,
    far_p2p: Multiaddr,
    far_metrics: String,
    far_log: PathBuf,
    far_admin: PathBuf,
    far_sidecar_metrics: String,
    /// The far node's own debug-level file log.
    far_node_log: PathBuf,
    ctl: PathBuf,
    /// The validator indices the near node's own validator client runs, which is how its own
    /// proposals are told from gossiped ones.
    proposers: Range<u64>,
    /// How many slots the counting tests watch.
    slots: u64,
}

/// The Gloas environment, or `None` with a line saying why the test did nothing.
fn gloas() -> Option<Gloas> {
    if std::env::var("MATRIX_GLOAS").as_deref() != Ok("1") {
        println!(
            "MATRIX_GLOAS is not 1; this one needs the Gloas devnet: \
             scripts/lighthouse-matrix.sh <version> --gloas"
        );
        return None;
    }
    let var = |name: &str| {
        std::env::var(name).unwrap_or_else(|_| {
            panic!("{name} is not set; run this through scripts/lighthouse-matrix.sh --gloas")
        })
    };
    let proposers = var("LIGHTHOUSE_PROPOSERS");
    let (first, last) = proposers
        .split_once('-')
        .expect("LIGHTHOUSE_PROPOSERS is first-last");
    Some(Gloas {
        far_http: var("LIGHTHOUSE_FAR_HTTP").trim_end_matches('/').to_owned(),
        far_p2p: var("LIGHTHOUSE_FAR_P2P").parse().unwrap(),
        far_metrics: var("LIGHTHOUSE_FAR_METRICS")
            .trim_end_matches('/')
            .to_owned(),
        far_log: var("SIDECAR_FAR_LOG").into(),
        far_admin: var("SIDECAR_FAR_ADMIN").into(),
        far_sidecar_metrics: var("SIDECAR_FAR_METRICS").trim_end_matches('/').to_owned(),
        far_node_log: var("LIGHTHOUSE_FAR_LOG").into(),
        ctl: var("SIDECAR_CTL").into(),
        proposers: first.parse().unwrap()..last.parse::<u64>().unwrap() + 1,
        slots: std::env::var("MATRIX_SLOTS")
            .ok()
            .and_then(|slots| slots.parse().ok())
            .unwrap_or(64),
    })
}

impl Gloas {
    /// The far node as an `Env`, under the same harness key.
    fn far(&self, env: &Env) -> Env {
        Env {
            http: self.far_http.clone(),
            p2p: self.far_p2p.clone(),
            listen: env.listen.clone(),
            key: NodeKey::load_or_create(std::path::Path::new(
                &std::env::var("SIDECAR_NODE_KEY").unwrap(),
            ))
            .unwrap(),
        }
    }

    /// Turns the far sidecar's inject off until the guard drops, so a test that fails halfway
    /// does not leave it off.
    fn inject_off(&self) -> InjectOff<'_> {
        self.inject(false);
        InjectOff(self)
    }

    /// Flips the far sidecar's inject switch over its admin socket, the way an operator does.
    fn inject(&self, on: bool) {
        let status = std::process::Command::new(&self.ctl)
            .arg("--socket")
            .arg(&self.far_admin)
            .args(["inject", if on { "on" } else { "off" }])
            .status()
            .expect("the ctl binary runs");
        assert!(status.success(), "inject {on}: {status}");
    }

    /// The `first_arrival` lines the far sidecar has logged with `source: overlay` on a topic
    /// of `kind`.
    fn overlay_arrivals(&self, kind: &str) -> usize {
        let text = std::fs::read_to_string(&self.far_log).unwrap_or_default();
        text.lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|line| line["event"] == "first_arrival" && line["source"] == "overlay")
            .filter(|line| {
                line["topic"]
                    .as_str()
                    .is_some_and(|topic| topic.split('/').nth(3) == Some(kind))
            })
            .count()
    }
}

struct InjectOff<'a>(&'a Gloas);

impl Drop for InjectOff<'_> {
    fn drop(&mut self) {
        self.0.inject(true);
    }
}

/// The chain's clock, read off the beacon API.
struct Chain {
    genesis_time: u64,
    seconds_per_slot: u64,
}

async fn chain(http: &str) -> Chain {
    let quoted = |value: &serde_json::Value| -> u64 { value.as_str().unwrap().parse().unwrap() };
    Chain {
        genesis_time: quoted(
            &beacon_json_at(http, "/eth/v1/beacon/genesis").await["data"]["genesis_time"],
        ),
        seconds_per_slot: quoted(
            &beacon_json_at(http, "/eth/v1/config/spec").await["data"]["SECONDS_PER_SLOT"],
        ),
    }
}

impl Chain {
    fn slots(&self, count: u64) -> Duration {
        Duration::from_secs(count * self.seconds_per_slot)
    }

    fn slot_now(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now.saturating_sub(self.genesis_time) / self.seconds_per_slot
    }
}

/// A root as the beacon API spells one, `0x` and 64 hex digits.
fn hex0x(root: [u8; 32]) -> String {
    format!("0x{}", overlay_core::events::hex(root))
}

/// `0x`-prefixed hex to a root.
fn unhex(text: &str) -> Option<[u8; 32]> {
    let text = text.strip_prefix("0x")?;
    let mut root = [0; 32];
    for (i, byte) in root.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(root)
}

/// The `(block_root, index)` a Gloas column sidecar names, at the fixed offsets T-120 reads.
fn column_identity(message: &BnMessage) -> Option<([u8; 32], u16)> {
    let ssz = snap::raw::Decoder::new()
        .decompress_vec(&message.data)
        .ok()?;
    if ssz.len() < 56 || u32::from_le_bytes(ssz[8..12].try_into().ok()?) != 56 {
        return None;
    }
    let index = u64::from_le_bytes(ssz[0..8].try_into().ok()?);
    Some((ssz[24..56].try_into().ok()?, u16::try_from(index).ok()?))
}

/// The block root a payload envelope on the wire is for.
fn envelope_root(message: &BnMessage) -> Option<[u8; 32]> {
    let ssz = snap::raw::Decoder::new()
        .decompress_vec(&message.data)
        .ok()?;
    let envelope = SignedExecutionPayloadEnvelope::<MainnetEthSpec>::from_ssz_bytes(&ssz).ok()?;
    Some(envelope.message.beacon_block_root.0)
}

fn kind_of(topic: &str) -> Option<TopicKind> {
    Topic::parse(topic).ok().map(|topic| topic.kind().clone())
}

/// One Prometheus series at `origin`, named by the text up to its value; 0 when absent.
async fn series(origin: &str, text: &str) -> f64 {
    let body = reqwest::get(format!("{origin}/metrics"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    body.lines()
        .find_map(|line| line.strip_prefix(text))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0.0)
}

/// The far node's gossipsub counters for `kind` under `digest`: accepted, rejected, invalid.
async fn gossip_counts(origin: &str, digest: &str, kind: &str) -> [f64; 3] {
    let topic = format!("/eth2/{digest}/{kind}/ssz_snappy");
    let mut counts = [0.0; 3];
    for (i, name) in ["accepted", "rejected", "invalid"].iter().enumerate() {
        counts[i] = series(
            origin,
            &format!("gossipsub_{name}_messages_per_topic_total{{hash=\"{topic}\"}} "),
        )
        .await;
    }
    counts
}

/// The fork digest the node's topics carry right now, off its `beacon_block` subscription.
async fn digest_of(sidecar: &mut Sidecar, deadline: Instant) -> String {
    let topic = sidecar
        .subscription(deadline, |topic| topic.contains("/beacon_block/"))
        .await;
    topic.split('/').nth(2).unwrap().to_owned()
}

/// Question 1 of T-121. From v8.3.0 Lighthouse enables gossipsub partial messages on every
/// `data_column_sidecar_*` topic by default (`--enable-partial-columns`), and on a devnet
/// where every node has the blobs in its execution layer no full column travels on gossip at
/// all: the node verifies partials, merges them, and completes the rest from `getBlobs`. The
/// sidecar never asks for partials. What this counts is whether the node still hands its
/// explicit peer a full message for every column its own `data_column_sidecar` event reports:
/// a merged column is published whole (`gossip_methods.rs:1343-1366` at v8.3.2), and
/// `publish` sends it to every peer that did not request partials (`behaviour.rs:676-689`
/// at the pinned rust-libp2p). Blocks cut by the window are left out of the tally.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the Gloas devnet: scripts/lighthouse-matrix.sh <version> --gloas"]
async fn matrix_the_node_forwards_full_columns_to_its_explicit_peer_with_partials_on() {
    let Some(gloas) = gloas() else { return };
    let env = env();
    let chain = chain(&env.http).await;
    let columns = beacon_json(&env, "/eth/v1/config/spec").await["data"]["NUMBER_OF_COLUMNS"]
        .as_str()
        .unwrap()
        .parse::<u16>()
        .unwrap();
    let mut sidecar = spawn(&env);
    let deadline = sidecar.connect().await;
    let digest = digest_of(&mut sidecar, deadline).await;
    for index in 0..columns {
        sidecar
            .commands
            .send(BnCommand::Subscribe(format!(
                "/eth2/{digest}/data_column_sidecar_{index}/ssz_snappy"
            )))
            .await
            .unwrap();
    }
    let mut events = sse(format!(
        "{}/eth/v1/events?topics=data_column_sidecar",
        env.http
    ));

    let mut reported: BTreeMap<(u64, [u8; 32]), BTreeSet<u16>> = BTreeMap::new();
    let mut forwarded: BTreeMap<[u8; 32], BTreeSet<u16>> = BTreeMap::new();
    let end = Instant::now() + chain.slots(gloas.slots);
    let Sidecar { lanes, link, .. } = &mut sidecar;
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(end.into()) => break,
            Some((_, data)) = events.recv() => {
                let slot: u64 = data["slot"].as_str().unwrap().parse().unwrap();
                let index: u16 = data["index"].as_str().unwrap().parse().unwrap();
                let root = unhex(data["block_root"].as_str().unwrap()).unwrap();
                reported.entry((slot, root)).or_default().insert(index);
            }
            message = lanes.recv_from(Class::Large) => {
                if let Some((root, index)) = column_identity(&message) {
                    forwarded.entry(root).or_default().insert(index);
                }
            }
            event = link.events.recv() => {
                let event = event.expect("the link ended");
                assert_ne!(event, BnEvent::Disconnected, "the beacon node dropped the sidecar");
            }
        }
    }

    let blocks: Vec<_> = reported.iter().collect();
    let (mut reported_total, mut forwarded_total) = (0, 0);
    println!("slot  reported  forwarded_of_those  forwarded_extra");
    for ((slot, root), indices) in blocks.iter().skip(1).rev().skip(1).rev() {
        let got = forwarded.get(root).cloned().unwrap_or_default();
        let both = indices.intersection(&got).count();
        println!(
            "{slot:<5} {:<9} {both:<19} {}",
            indices.len(),
            got.len() - both
        );
        reported_total += indices.len();
        forwarded_total += both;
    }
    let own = forwarded
        .keys()
        .filter(|root| !reported.keys().any(|(_, reported)| reported == *root))
        .count();
    println!(
        "{} blocks, {reported_total} columns reported by the node, {forwarded_total} of them \
         forwarded whole to the sidecar; columns of {own} more blocks forwarded with no event \
         (another node's blocks, whose columns the node merged from partials)",
        blocks.len().saturating_sub(2)
    );
    assert!(
        blocks.len() > 4,
        "too few blocks with columns in the window"
    );
    assert_eq!(
        forwarded_total, reported_total,
        "the node reported columns it never handed its explicit peer"
    );
}

/// Question 2 of T-121, assumption 8's shape with the parent's payload in place of the
/// parent block. The far node's only gossip peers are its shipped sidecar and this harness.
/// The harness waits for a block B the far node accepts, turns the shipped sidecar's inject
/// off before B's envelope reaches it, and when the chain produces B's child C hands C to
/// the far node itself. D42 lets C through: B is imported. Lighthouse reads
/// `ParentImportStatus::UnknownPayload` for it (`fork_choice.rs:1663-1679` at v8.3.2),
/// returns `ParentUnknown` with the bid's parent hash (`block_verification.rs:1516-1521`),
/// and opens a lookup for B seeded with C's sender alone (`block_lookups/mod.rs:360-440`):
/// this harness. The lookup starts with B's block, which the node already holds, so what it
/// sends is `beacon_blocks_by_root`, refused four times; the envelope is never asked for,
/// and the lookup and C are dropped for too many attempts, exactly as in assumption 8. The
/// two refusal counts, the far node's `block` event for C inside the window and its
/// `sync_lookups_dropped_total` are what this pins. A self-building proposer reveals the
/// envelope within tens of milliseconds of the block, so the window the switch has to land
/// in is the overlay's own latency, and the attempt repeats until it does. The envelope and
/// C are handed over at the end so the far node is left in step.
///
/// D44 is read against the same block. The far node's event stream feeds an `Arrivals` the
/// way the shipped sidecar's does, and the check the receive path makes is asked of C twice:
/// when C arrives it has to say the payload C builds on is not imported, which is what keeps
/// the shipped sidecar from offering the node the block this test goes on to hand it, and
/// once the node has imported the payload it has to let C by.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the Gloas devnet: scripts/lighthouse-matrix.sh <version> --gloas"]
async fn matrix_a_block_whose_parent_envelope_the_node_lacks() {
    let Some(gloas) = gloas() else { return };
    let env = env();
    let far = gloas.far(&env);
    let chain = chain(&env.http).await;
    let refusals = Arc::new(Refusals::default());
    let mut sidecar = spawn_with(
        &far,
        &far.key,
        far.listen.clone(),
        far.p2p.clone(),
        counting(&refusals),
    );
    sidecar.connect().await;
    // The far node joins its core topics only once it counts itself synced with a peer, which
    // right after genesis can be an epoch away; its persistent attestation subnets come first.
    let block_topic = sidecar
        .subscription(Instant::now() + chain.slots(64), |topic| {
            topic.contains("/beacon_block/")
        })
        .await;
    let envelope_topic = block_topic.replace("beacon_block", "execution_payload");
    let mut far_events = sse(format!(
        "{}/eth/v1/events?topics=block_gossip,execution_payload_gossip,block",
        far.http
    ));
    let mut near_events = sse(format!("{}/eth/v1/events?topics=block_gossip", env.http));
    // D44's check as the shipped sidecar holds it: the far node's own event stream, at the
    // shipped topics, filing what the node says it imported.
    let arrivals = Arc::new(Arrivals::new(Arc::new(SystemClock), sidecar.spec.clone()));
    let shipped = Config::default().bn.events_url;
    let far_stream = BlockEvents::spawn(
        format!(
            "{}{}?{}",
            far.http,
            shipped.path(),
            shipped.query().unwrap()
        )
        .parse()
        .unwrap(),
        Backoff::new(BACKOFF_MIN, BACKOFF_MAX),
        arrivals.clone(),
        SharedCustody::new(
            sidecar.spec.clone(),
            watch::channel(SubscriptionSets::default()).1,
            arrivals.clone(),
            Arc::new(()),
        ),
        Arc::new(SystemClock),
        Arc::new(()),
    );
    let root_in = |data: &serde_json::Value| unhex(data["block"].as_str().unwrap()).unwrap();
    let slot_in =
        |data: &serde_json::Value| -> u64 { data["slot"].as_str().unwrap().parse().unwrap() };

    let mut outcome = None;
    for attempt in 1..=8 {
        // In step first: a far node still filling a gap would open lookups for the blocks
        // it lacks, which is assumption 8's case and not this one.
        loop {
            let near_head = head_slot(&env.http).await;
            let far_head = head_slot(&far.http).await;
            if far_head + 1 >= near_head {
                break;
            }
            println!("far node at slot {far_head}, near at {near_head}; waiting");
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        // A block B the far node accepted in step with the chain.
        let (slot, parent) = loop {
            let (name, data) = far_events.recv().await.unwrap();
            if name == "block_gossip" && slot_in(&data) + 1 >= chain.slot_now() {
                break (slot_in(&data), root_in(&data));
            }
        };
        let off = gloas.inject_off();
        println!("attempt {attempt}: block at slot {slot} accepted, inject off");

        // B's child from the near node, unless B's envelope got through first.
        let mut parent_imported = false;
        let child = loop {
            tokio::select! {
                Some((name, data)) = far_events.recv() => {
                    match name.as_str() {
                        "execution_payload_gossip"
                            if unhex(data["block_root"].as_str().unwrap()) == Some(parent) =>
                        {
                            break None;
                        }
                        "block" if root_in(&data) == parent => parent_imported = true,
                        _ => {}
                    }
                }
                Some((_, data)) = near_events.recv() => {
                    if slot_in(&data) > slot {
                        break Some(root_in(&data));
                    }
                }
            }
        };
        if child.is_some() && !parent_imported {
            println!("the far node had not imported the block when its child came; next block");
            drop(off);
            continue;
        }
        let Some(child) = child else {
            println!("the envelope reached the far node before the switch; next block");
            drop(off);
            continue;
        };
        let bytes = beacon_ssz(&env, &format!("/eth/v2/beacon/blocks/{}", hex0x(child))).await;
        let block_parent: [u8; 32] = bytes[116..148].try_into().unwrap();
        if block_parent != parent {
            println!("the child builds on another block; next block");
            drop(off);
            continue;
        }
        // What the shipped receive path asks before it offers the node this block.
        let Some(Header::Block {
            parent_payload: Some(built_on),
            ..
        }) = Headers.header(&Topic::parse(&block_topic).unwrap(), &bytes)
        else {
            panic!("a Gloas block's bid names the payload it builds on");
        };
        let kept_back = arrivals.lacks_payload(built_on);
        println!(
            "the parent-payload check on the child: parent block imported {}, payload it \
             builds on imported {}",
            arrivals.is_imported(parent),
            !kept_back
        );
        let dropped_before = lookups_dropped_at(&gloas.far_metrics).await;
        let wire = snap::raw::Encoder::new().compress_vec(&bytes).unwrap();
        sidecar
            .publish(&block_topic, &wire)
            .await
            .expect("the far node takes the block off the wire");

        let mut imported = false;
        let window = Instant::now() + Duration::from_secs(8);
        while let Ok(Some((name, data))) =
            tokio::time::timeout_at(window.into(), far_events.recv()).await
        {
            if name == "block" && root_in(&data) == child {
                imported = true;
            }
        }
        let asked = (
            refusals.blocks.load(Ordering::Relaxed),
            refusals.envelopes.load(Ordering::Relaxed),
        );
        let dropped_after = lookups_dropped_at(&gloas.far_metrics).await;
        println!(
            "refusals: beacon_blocks_by_root {}, execution_payload_envelopes_by_root {}; child \
             imported inside 8 s: {imported}; \
             sync_lookups_dropped_total{{reason=\"TooManyAttempts\"}}: {dropped_before} then \
             {dropped_after}",
            asked.0, asked.1
        );

        // Towards leaving the far node in step: the envelope by gossip, then the child over
        // the beacon API, which the gossip duplicate cache does not cover. Best effort: the
        // node also wants the envelope's columns before it counts the payload as received,
        // and the script's catch-up loop supplies those with the envelope once the node is
        // three slots behind.
        let envelope = beacon_ssz(
            &env,
            &format!(
                "/eth/v1/beacon/execution_payload_envelopes/{}",
                hex0x(parent)
            ),
        )
        .await;
        let compressed = snap::raw::Encoder::new().compress_vec(&envelope).unwrap();
        sidecar.publish(&envelope_topic, &compressed).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let posted = reqwest::Client::new()
            .post(format!("{}/eth/v2/beacon/blocks", far.http))
            .header("Content-Type", "application/octet-stream")
            .header("Eth-Consensus-Version", "gloas")
            .body(bytes)
            .send()
            .await
            .unwrap();
        let status = posted.status();
        println!(
            "child handed over the beacon API: {status} {}",
            posted.text().await.unwrap_or_default()
        );
        drop(off);
        // The far node imports the payload once it has the envelope and its columns, which the
        // catch-up loop sees to within a few slots. From then on the check lets the child by.
        let until = Instant::now() + chain.slots(8);
        while arrivals.lacks_payload(built_on) && Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        let let_through = !arrivals.lacks_payload(built_on);
        outcome = Some((
            asked,
            imported,
            dropped_after - dropped_before,
            kept_back,
            let_through,
        ));
        break;
    }
    far_stream.task.abort();

    let (asked, imported, dropped, kept_back, let_through) =
        outcome.expect("no block gave a clean window in 8 tries");
    assert!(
        kept_back,
        "the shipped check would have offered the node a child it then dropped"
    );
    assert!(
        let_through,
        "the node imported the payload and the check still keeps its child back"
    );
    assert_eq!(
        asked,
        (4, 0),
        "Lighthouse asks its one lookup peer for the parent block four times and never for \
         the envelope"
    );
    assert!(
        !imported,
        "the child was imported without its parent's envelope"
    );
    assert!(
        dropped >= 1,
        "the lookup was not dropped for too many attempts"
    );
}

/// Question 3 of T-121, the event MD-09 anchors column repair on. Over `MATRIX_SLOTS` slots
/// every payload envelope the near node forwards to its explicit peer is matched with its
/// `execution_payload_gossip` event, and the proposer of each is looked up so the node's own
/// envelopes are told from gossiped ones. Lighthouse registers the event on the first
/// observation from any source (`gossip_verified_envelope.rs:297-327` at v8.3.2), so a node
/// that publishes its own envelope over the beacon API fires it too; T-120's review corrected
/// MD-09 on that point, and this is the live check. An event for an envelope the node neither
/// gossiped nor built is one it first saw over RPC, fetched by a lookup before the gossip copy
/// came: the gossip copy is then a duplicate and is not forwarded, so the sidecar never sees
/// it. One such row in 32 slots was seen on the devnet; a run with many would say envelopes
/// mostly reach the node some other way, which the bound below would catch.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the Gloas devnet: scripts/lighthouse-matrix.sh <version> --gloas"]
async fn matrix_execution_payload_gossip_fires_once_per_envelope_from_any_source() {
    let Some(gloas) = gloas() else { return };
    let env = env();
    let chain = chain(&env.http).await;
    let mut sidecar = spawn(&env);
    let deadline = sidecar.connect().await;
    let digest = digest_of(&mut sidecar, deadline).await;
    // The stream first, so no envelope is forwarded before its event could be heard.
    let mut events = sse(format!(
        "{}/eth/v1/events?topics=execution_payload_gossip",
        env.http
    ));
    sidecar
        .commands
        .send(BnCommand::Subscribe(format!(
            "/eth2/{digest}/execution_payload/ssz_snappy"
        )))
        .await
        .unwrap();

    let mut fired: BTreeMap<[u8; 32], (u64, usize)> = BTreeMap::new();
    let mut forwarded: BTreeSet<[u8; 32]> = BTreeSet::new();
    let end = Instant::now() + chain.slots(gloas.slots);
    let Sidecar { lanes, link, .. } = &mut sidecar;
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(end.into()) => break,
            Some((_, data)) = events.recv() => {
                let slot: u64 = data["slot"].as_str().unwrap().parse().unwrap();
                let root = unhex(data["block_root"].as_str().unwrap()).unwrap();
                let entry = fired.entry(root).or_insert((slot, 0));
                entry.1 += 1;
            }
            message = lanes.recv_from(Class::Large) => {
                if kind_of(&message.topic) == Some(TopicKind::ExecutionPayload)
                    && let Some(root) = envelope_root(&message)
                {
                    forwarded.insert(root);
                }
            }
            event = link.events.recv() => {
                let event = event.expect("the link ended");
                assert_ne!(event, BnEvent::Disconnected, "the beacon node dropped the sidecar");
            }
        }
    }

    // Every root either side saw, with its slot and proposer off the near node.
    let mut rows: BTreeMap<[u8; 32], (u64, u64)> = BTreeMap::new();
    for root in forwarded.iter().chain(fired.keys()) {
        let header = beacon_json(&env, &format!("/eth/v1/beacon/headers/{}", hex0x(*root))).await;
        let number = |key: &str| -> u64 {
            header["data"]["header"]["message"][key]
                .as_str()
                .unwrap()
                .parse()
                .unwrap()
        };
        rows.insert(*root, (number("slot"), number("proposer_index")));
    }
    let (mut own, mut own_fired, mut gossiped, mut gossiped_without_event) = (0, 0, 0, 0);
    let (mut stray, mut twice) = (0, 0);
    // The window's first and last slots can hold half of a pair, so they are left out.
    let edge = |slot: u64| {
        rows.values().map(|(slot, _)| *slot).min() == Some(slot)
            || rows.values().map(|(slot, _)| *slot).max() == Some(slot)
    };
    println!("slot  proposer  own    forwarded  events");
    for (root, (slot, proposer)) in &rows {
        if edge(*slot) {
            continue;
        }
        let is_own = gloas.proposers.contains(proposer);
        let count = fired.get(root).map_or(0, |(_, count)| *count);
        let was_forwarded = forwarded.contains(root);
        println!("{slot:<5} {proposer:<9} {is_own:<6} {was_forwarded:<10} {count}");
        match (is_own, was_forwarded) {
            (true, _) => {
                own += 1;
                own_fired += usize::from(count > 0);
            }
            (false, true) => {
                gossiped += 1;
                gossiped_without_event += usize::from(count == 0);
            }
            (false, false) => stray += 1,
        }
        twice += usize::from(count > 1);
    }
    println!(
        "{gossiped} gossiped envelopes, {gossiped_without_event} with no event; {own} own \
         envelopes, {own_fired} with an event; {stray} events for envelopes from neither, \
         which the node first saw over RPC; {twice} roots with more than one event"
    );
    assert!(gossiped >= 4, "too few gossiped envelopes in the window");
    assert_eq!(
        gossiped_without_event, 0,
        "a gossiped envelope fired no event"
    );
    assert!(own >= 1, "the near node proposed nothing in the window");
    assert_eq!(own_fired, own, "the node's own envelope fired no event");
    assert!(
        stray * 4 <= gossiped,
        "{stray} events for envelopes the node neither gossiped nor built, against {gossiped} \
         gossiped: envelopes mostly reach the node some other way than gossip"
    );
    assert_eq!(twice, 0, "an envelope fired more than once");
}

/// D44's first step: the event the parent-payload check reads. `execution_payload` fires when
/// the node imports a payload envelope, which is when a child built on it stops being
/// `UnknownPayload`; `execution_payload_gossip` fires earlier, at gossip verification. Over
/// `MATRIX_SLOTS` slots every envelope the near node gossip-verified is matched with its import
/// event, own proposals and other nodes' apart, and the gap between the two events is printed.
/// The far node is read as well: its envelopes come from its shipped sidecar and, when it
/// falls behind, from the catch-up loop over the beacon API, so an import event there is one
/// for an envelope that never arrived from a public gossip peer. An envelope fetched by root
/// is not covered: T-121 saw the node ask for none. The node can fire the event twice for one
/// envelope, 8 of 61 on the devnet, which is counted and costs a set nothing.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the Gloas devnet: scripts/lighthouse-matrix.sh <version> --gloas"]
async fn matrix_execution_payload_fires_at_import_for_every_envelope() {
    let Some(gloas) = gloas() else { return };
    let env = env();
    let chain = chain(&env.http).await;
    let mut near = sse(format!(
        "{}/eth/v1/events?topics=execution_payload_gossip,execution_payload",
        env.http
    ));
    let mut far = sse(format!(
        "{}/eth/v1/events?topics=execution_payload",
        gloas.far_http
    ));

    #[derive(Default)]
    struct Seen {
        slot: u64,
        verified_at: Option<Instant>,
        imported_at: Option<Instant>,
        imports: usize,
        block_hash: Option<String>,
        far_imports: usize,
    }
    let mut seen: BTreeMap<[u8; 32], Seen> = BTreeMap::new();
    let mut printed = false;
    let end = Instant::now() + chain.slots(gloas.slots);
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(end.into()) => break,
            Some((name, data)) = near.recv() => {
                let root = unhex(data["block_root"].as_str().unwrap()).unwrap();
                let entry = seen.entry(root).or_default();
                entry.slot = data["slot"].as_str().unwrap().parse().unwrap();
                if name == "execution_payload_gossip" {
                    entry.verified_at = Some(Instant::now());
                } else {
                    if !printed {
                        println!("an execution_payload event as the node sends it: {data}");
                        printed = true;
                    }
                    entry.imported_at.get_or_insert_with(Instant::now);
                    entry.imports += 1;
                    entry.block_hash = data["block_hash"].as_str().map(str::to_owned);
                }
            }
            Some((_, data)) = far.recv() => {
                let root = unhex(data["block_root"].as_str().unwrap()).unwrap();
                seen.entry(root).or_default().far_imports += 1;
            }
        }
    }

    let slots: Vec<u64> = seen.values().map(|envelope| envelope.slot).collect();
    // The window's first and last slots can hold half of a pair, so they are left out.
    let edge = |slot: u64| slots.iter().min() == Some(&slot) || slots.iter().max() == Some(&slot);
    let (mut own, mut gossiped, mut unimported, mut hashless, mut twice, mut on_far) =
        (0, 0, 0, 0, 0, 0);
    let mut gaps = Vec::new();
    println!("slot  own    import_events  import_after_gossip  far_import_events");
    for (root, envelope) in &seen {
        if envelope.verified_at.is_none() || edge(envelope.slot) {
            continue;
        }
        let header = beacon_json(&env, &format!("/eth/v1/beacon/headers/{}", hex0x(*root))).await;
        let proposer: u64 = header["data"]["header"]["message"]["proposer_index"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let is_own = gloas.proposers.contains(&proposer);
        match is_own {
            true => own += 1,
            false => gossiped += 1,
        }
        unimported += usize::from(envelope.imports == 0);
        hashless += usize::from(envelope.imports > 0 && envelope.block_hash.is_none());
        twice += usize::from(envelope.imports > 1);
        on_far += usize::from(envelope.far_imports > 0);
        let gap = envelope
            .verified_at
            .zip(envelope.imported_at)
            .map(|(verified, imported)| imported.saturating_duration_since(verified).as_millis());
        gaps.extend(gap);
        println!(
            "{:<5} {is_own:<6} {:<14} {:<20} {}",
            envelope.slot,
            envelope.imports,
            gap.map_or("none".to_owned(), |gap| format!("+{gap} ms")),
            envelope.far_imports
        );
    }
    gaps.sort_unstable();
    println!(
        "{own} own envelopes and {gossiped} gossiped: {unimported} with no import event, \
         {hashless} import events with no block_hash, {twice} imported more than once; import \
         after gossip verification min {:?} median {:?} max {:?} ms; the far node fired an \
         import event for {on_far} of them",
        gaps.first(),
        gaps.get(gaps.len() / 2),
        gaps.last()
    );
    assert!(own >= 1 && gossiped >= 4, "too few envelopes in the window");
    assert_eq!(
        unimported, 0,
        "an envelope the node verified fired no import event"
    );
    assert_eq!(hashless, 0, "an import event named no block hash");
    assert!(
        on_far * 2 >= own + gossiped,
        "the far node fired an import event for {on_far} of {} envelopes",
        own + gossiped
    );
}

/// T-119's end-to-end check. The far node's only gossip peer is its shipped sidecar, so every
/// message its gossipsub has accepted on a Gloas topic since it started came over the
/// overlay, and a REJECT or an invalid message on those topics is what acceptance rules out.
/// The counters are read whole rather than over a window, because the validator client
/// sends proposer preferences once per proposer duty rather than every slot. The envelope
/// also has to cross inside the window: the far node's accepted count on its topic has to
/// move, and the far sidecar has to log a `first_arrival` with `source: overlay` for one;
/// the small kinds carry no block root and log no line. The bid topic is reported but not
/// required: a devnet that self-builds every payload gossips no bids.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the Gloas devnet: scripts/lighthouse-matrix.sh <version> --gloas"]
async fn matrix_every_gloas_kind_crosses_the_overlay() {
    let Some(gloas) = gloas() else { return };
    let env = env();
    let chain = chain(&env.http).await;
    let mut sidecar = spawn(&env);
    let deadline = sidecar.connect().await;
    let digest = digest_of(&mut sidecar, deadline).await;
    // The harness leaves: the far node's only gossip peer from here on is its shipped sidecar.
    sidecar.link.task.abort();
    drop(sidecar);
    const KINDS: [&str; 4] = [
        "execution_payload",
        "execution_payload_bid",
        "payload_attestation_message",
        "proposer_preferences",
    ];
    // Live, inside the window: the far node's own count of accepted envelopes has to move,
    // which only its sidecar's publish can do, and the far sidecar has to log one arriving
    // over the overlay.
    let arrivals_before = gloas.overlay_arrivals("execution_payload");
    let accepted_before = gossip_counts(&gloas.far_metrics, &digest, KINDS[0]).await[0];
    let end = Instant::now() + chain.slots(8);
    loop {
        let accepted = gossip_counts(&gloas.far_metrics, &digest, KINDS[0]).await[0];
        if accepted > accepted_before
            && gloas.overlay_arrivals("execution_payload") > arrivals_before
        {
            break;
        }
        assert!(
            Instant::now() < end,
            "no envelope crossed to the far node in eight slots: {accepted_before} accepted \
             before, {accepted} now"
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
    }

    println!("kind                         accepted  rejected  invalid");
    let mut counts = [[0.0; 3]; 4];
    for (i, kind) in KINDS.iter().enumerate() {
        counts[i] = gossip_counts(&gloas.far_metrics, &digest, kind).await;
        let [accepted, rejected, invalid] = counts[i];
        println!("{kind:<28} {accepted:<9} {rejected:<9} {invalid}");
        assert_eq!(rejected + invalid, 0.0, "{kind} was rejected or invalid");
    }
    for i in [0, 2, 3] {
        assert!(counts[i][0] >= 1.0, "{} never crossed", KINDS[i]);
    }
    if counts[1][0] == 0.0 {
        println!("execution_payload_bid: no builder on this devnet gossips bids, so unmeasured");
    }
    println!(
        "envelope first_arrival lines with source overlay: {} new",
        gloas.overlay_arrivals("execution_payload") - arrivals_before
    );
}

/// MD-09 and D43 on a running chain. The custody tracker is fed the near node's own events,
/// its own column subscriptions and the columns it forwards on the link, exactly as the
/// sidecar feeds it, and its gaps are read every 50 ms at the shipped `repair_deadline_ms`. A
/// slot counts as late when a block of it still has a column missing past the deadline, which
/// from the Gloas fork runs from the envelope plus `GLOAS_COLUMN_GRACE`; the test expects
/// fewer than one such slot in a hundred. It prints per block whether the node proposed it,
/// how many columns it reported and forwarded, and when the last of each came after the
/// envelope, which is the measurement the grace is set from. At v8.3.2 the node reports no
/// column of another node's block, whose columns arrive as partial messages, and forwards
/// every one of them.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the Gloas devnet: scripts/lighthouse-matrix.sh <version> --gloas"]
async fn matrix_column_repair_is_quiet_on_a_healthy_gloas_chain() {
    let Some(gloas) = gloas() else { return };
    let env = env();
    let chain = chain(&env.http).await;
    let deadline = Config::default().classes.large.repair_deadline;
    let mut sidecar = spawn(&env);
    sidecar.connect().await;
    let (sets_tx, sets) = watch::channel(SubscriptionSets::default());
    for topic in &sidecar.subscribed {
        if let Ok(topic) = Topic::parse(topic) {
            sets_tx.send_modify(|sets| {
                sets.advertised.insert(topic);
            });
        }
    }
    let arrivals = Arc::new(Arrivals::new(Arc::new(SystemClock), sidecar.spec.clone()));
    let custody = SharedCustody::new(sidecar.spec.clone(), sets, arrivals.clone(), Arc::new(()));
    let shipped = Config::default().bn.events_url;
    let events = BlockEvents::spawn(
        format!(
            "{}{}?{}",
            env.http,
            shipped.path(),
            shipped.query().unwrap()
        )
        .parse()
        .unwrap(),
        Backoff::new(BACKOFF_MIN, BACKOFF_MAX),
        arrivals,
        custody.clone(),
        Arc::new(SystemClock),
        Arc::new(()),
    );
    // A second reading of the same stream, for when each block's envelope and columns came.
    let mut timeline = sse(format!(
        "{}/eth/v1/events?topics=block_gossip,execution_payload_gossip,data_column_sidecar",
        env.http
    ));

    #[derive(Default)]
    struct Seen {
        slot: u64,
        envelope_at: Option<Instant>,
        columns: usize,
        last_column_at: Option<Instant>,
        /// The columns the node forwarded on the link, and when the last new one came.
        forwarded: BTreeSet<u16>,
        last_forwarded_at: Option<Instant>,
    }
    // What the shipped sidecar's mirror does: the node forwards a column only to a peer
    // subscribed to its subnet.
    let column_topic =
        |topic: &str| matches!(kind_of(topic), Some(TopicKind::DataColumnSidecar(_)));
    for topic in sidecar
        .subscribed
        .iter()
        .filter(|topic| column_topic(topic))
    {
        sidecar
            .commands
            .send(BnCommand::Subscribe(topic.clone()))
            .await
            .unwrap();
    }
    let Sidecar {
        lanes,
        link,
        commands,
        ..
    } = &mut sidecar;
    let none = custody.column_set([]);
    let mut seen: BTreeMap<[u8; 32], Seen> = BTreeMap::new();
    let mut late: BTreeMap<[u8; 32], usize> = BTreeMap::new();
    let end = Instant::now() + chain.slots(gloas.slots);
    let mut tick = tokio::time::interval(Duration::from_millis(50));
    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(end.into()) => break,
            _ = tick.tick() => {
                for gap in custody.gaps(deadline, Instant::now(), &none) {
                    let missing = late.entry(gap.block_root).or_default();
                    *missing = (*missing).max(gap.missing.len());
                }
            }
            Some((name, data)) = timeline.recv() => {
                let now = Instant::now();
                let key = if name == "block_gossip" { "block" } else { "block_root" };
                let root = unhex(data["block_root"].as_str().or(data[key].as_str()).unwrap()).unwrap();
                let entry = seen.entry(root).or_default();
                match name.as_str() {
                    "block_gossip" => entry.slot = data["slot"].as_str().unwrap().parse().unwrap(),
                    "execution_payload_gossip" => entry.envelope_at = Some(now),
                    _ => {
                        entry.columns += 1;
                        entry.last_column_at = Some(now);
                    }
                }
            }
            message = lanes.recv_from(Class::Large) => {
                if let Some((root, index)) = column_identity(&message) {
                    let entry = seen.entry(root).or_default();
                    if entry.forwarded.insert(index) {
                        entry.last_forwarded_at = Some(Instant::now());
                    }
                }
                // D43, as the shipped inbound path does it: a column the node forwards is one
                // the node holds.
                if let Ok(topic) = Topic::parse(&message.topic)
                    && let Ok(ssz) = snap::raw::Decoder::new().decompress_vec(&message.data)
                    && let Some(Header::Column { slot, index, block_root }) =
                        Headers.header(&topic, &ssz)
                {
                    custody.on_column(slot, index, block_root);
                }
            }
            event = link.events.recv() => {
                let event = event.expect("the link ended");
                if let BnEvent::Subscribed { topic: name, .. } = &event
                    && let Ok(topic) = Topic::parse(name)
                {
                    if column_topic(name) {
                        commands.send(BnCommand::Subscribe(name.clone())).await.unwrap();
                    }
                    sets_tx.send_modify(|sets| {
                        sets.advertised.insert(topic);
                    });
                }
                assert_ne!(event, BnEvent::Disconnected, "the beacon node dropped the sidecar");
            }
        }
    }
    events.task.abort();

    // Own proposals and other nodes' blocks are tallied apart: the node builds its own
    // columns from the blobs its validator client posted and fires an event per column, while
    // another node's columns reach it as partials and fired none in the measured windows.
    let mut own_of = BTreeMap::new();
    for root in seen.keys() {
        let header = beacon_json(&env, &format!("/eth/v1/beacon/headers/{}", hex0x(*root))).await;
        let proposer: u64 = header["data"]["header"]["message"]["proposer_index"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        own_of.insert(*root, gloas.proposers.contains(&proposer));
    }
    let (mut gossiped, mut late_gossiped, mut own, mut late_own) = (0, 0, 0, 0);
    println!(
        "slot  own    missing_at_deadline  columns_by_the_end  last_column_after_envelope  \
         forwarded  last_forwarded_after_envelope"
    );
    let (mut own_lag, mut gossiped_lag) = (Vec::new(), Vec::new());
    for (root, block) in &seen {
        if block.slot == 0 {
            continue;
        }
        let is_own = own_of[root];
        let missing = late.get(root).copied();
        match (is_own, missing.is_some()) {
            (true, late) => {
                own += 1;
                late_own += usize::from(late);
            }
            (false, late) => {
                gossiped += 1;
                late_gossiped += usize::from(late);
            }
        }
        // Signed: a column can reach the link before the envelope's event does.
        let after_envelope = |at: Option<Instant>| {
            let (envelope, at) = (block.envelope_at?, at?);
            let ahead = at.saturating_duration_since(envelope).as_millis() as i64;
            let behind = envelope.saturating_duration_since(at).as_millis() as i64;
            Some(ahead - behind)
        };
        let shown = |lag: Option<i64>| lag.map_or("none".to_owned(), |lag| format!("{lag:+} ms"));
        let forwarded_lag = after_envelope(block.last_forwarded_at);
        if let Some(lag) = forwarded_lag {
            match is_own {
                true => own_lag.push(lag),
                false => gossiped_lag.push(lag),
            }
        }
        println!(
            "{:<5} {is_own:<6} {:<20} {:<19} {:<27} {:<10} {}",
            block.slot,
            missing.map_or("0".to_owned(), |missing| missing.to_string()),
            block.columns,
            shown(after_envelope(block.last_column_at)),
            block.forwarded.len(),
            shown(forwarded_lag)
        );
    }
    for (whose, lags) in [("own", &mut own_lag), ("gossiped", &mut gossiped_lag)] {
        lags.sort_unstable();
        println!(
            "last forwarded column after the envelope, {whose}: {} blocks, min {:?} median {:?} \
             max {:?} ms",
            lags.len(),
            lags.first(),
            lags.get(lags.len() / 2),
            lags.last()
        );
    }
    println!(
        "{own} own proposals, {late_own} reached the {deadline:?} deadline with columns \
         missing; {gossiped} other nodes' blocks, {late_gossiped} did"
    );
    assert!(gossiped + own >= 12, "too few blocks in the window");
    assert!(
        (late_gossiped + late_own) * 100 < gossiped + own,
        "{} of {} slots reached the repair deadline with columns missing",
        late_gossiped + late_own,
        gossiped + own
    );
}

/// T-128, the half of T-101's reason for anchoring D42 on `block` that nobody had measured:
/// a block the node fetches by root fires `block` and no `block_gossip`. At v8.3.2 the event
/// is registered in one place, `GossipVerifiedBlock::new` (`block_verification.rs:1116-1124`),
/// which a lookup never reaches: `process_lookup_block` (`sync_methods.rs:112-180`) hands
/// `chain.process_block` a `LookupBlock`, whose `into_execution_pending_block_slashable`
/// (`block_verification.rs:1433-1458`) goes straight to the signature check.
///
/// The far node's only libp2p peer is its shipped sidecar, which on this devnet answers
/// by-root requests from its store. The test turns that sidecar's inject off for one slot N,
/// so the far node misses block N, and back on before slot N+1. D42 then keeps N+1 back, and
/// the first message naming N+1, a payload attestation on the devnet, makes the node ask its
/// sender, the sidecar, for N+1 by root and then for N+1's parent. Lighthouse opens such a
/// lookup only once `--unknown-root-min-peers` distinct peers have named the root, three by
/// default at v8.3.2, so the script starts the far node with 1; without it the node sits at
/// N-1 until the catch-up loop steps in.
///
/// The catch-up loop is the other way the node could get N, and it posts over the beacon API,
/// which does fire `block_gossip`. So that such a run fails for the right reason, the
/// sidecar's `overlay_by_root_requests_total{outcome="hit"}` has to rise and the node's own
/// log has to say "Processing Lookup block" for N's root (`sync_methods.rs:165-167`). The
/// counter alone would not do: the devnet's clock runs a few tens of milliseconds ahead of
/// the host's, and when a block comes before its slot by the far node's clock, its payload
/// attestations open a lookup that is refused as `FutureSlot`, and that one hits too. Every
/// `block` and `block_gossip` the far node fires from slot N on is printed with its time, and
/// none of the latter may name N from the moment the stream opens until three slots after N's
/// import.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the Gloas devnet with GLOAS_BY_ROOT=1: scripts/lighthouse-matrix.sh <version> --gloas"]
async fn matrix_block_gossip_does_not_fire_for_a_block_fetched_by_root() {
    let Some(gloas) = gloas() else { return };
    let env = env();
    let chain = chain(&env.http).await;
    const HITS: &str =
        "overlay_by_root_requests_total{outcome=\"hit\",protocol=\"beacon_blocks_by_root\"} ";
    let mut far_events = sse(format!(
        "{}/eth/v1/events?topics=block,block_gossip",
        gloas.far_http
    ));
    let mut near_events = sse(format!("{}/eth/v1/events?topics=block", env.http));
    let root_in = |data: &serde_json::Value| unhex(data["block"].as_str().unwrap()).unwrap();
    let slot_in =
        |data: &serde_json::Value| -> u64 { data["slot"].as_str().unwrap().parse().unwrap() };
    let slot_start = |slot: u64| {
        UNIX_EPOCH + Duration::from_secs(chain.genesis_time + slot * chain.seconds_per_slot)
    };
    let sleep_until = |at: SystemTime| async move {
        if let Ok(wait) = at.duration_since(SystemTime::now()) {
            tokio::time::sleep(wait).await;
        }
    };

    // A block the far node took by gossip in its own slot: it is in step, and N is the next.
    let n = loop {
        let (name, data) = far_events.recv().await.unwrap();
        if name == "block_gossip" && slot_in(&data) >= chain.slot_now() {
            break slot_in(&data) + 1;
        }
    };
    let hits_before = series(&gloas.far_sidecar_metrics, HITS).await;
    // Late enough that the block before N and its envelope are in, early enough for all of N.
    sleep_until(slot_start(n) - Duration::from_secs(1)).await;
    let off = gloas.inject_off();
    println!("inject off for slot {n}; by-root hits so far: {hits_before}");
    sleep_until(slot_start(n + 1) - Duration::from_millis(500)).await;
    drop(off);
    println!("inject on");
    let root = loop {
        let (_, data) = tokio::time::timeout(chain.slots(1), near_events.recv())
            .await
            .expect("the near node imported no block at slot N")
            .unwrap();
        if slot_in(&data) == n {
            break root_in(&data);
        }
    };
    println!(
        "block {} at slot {n} is the one the far node missed",
        hex0x(root)
    );

    let (mut imported, mut gossiped) = (false, false);
    let mut end = Instant::now() + chain.slots(4);
    while let Ok(Some((name, data))) = tokio::time::timeout_at(end.into(), far_events.recv()).await
    {
        let slot = slot_in(&data);
        if slot < n {
            continue;
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        let into_slot = now.saturating_sub(slot_start(slot).duration_since(UNIX_EPOCH).unwrap());
        println!(
            "{}.{:03} far node {name:<12} slot {slot} {} ({:.3} s into its slot)",
            now.as_secs(),
            now.subsec_millis(),
            data["block"].as_str().unwrap(),
            into_slot.as_secs_f64()
        );
        if root_in(&data) != root {
            continue;
        }
        match name.as_str() {
            "block" if !imported => {
                imported = true;
                end = Instant::now() + chain.slots(3);
            }
            "block_gossip" => gossiped = true,
            _ => {}
        }
    }
    let hits_after = series(&gloas.far_sidecar_metrics, HITS).await;
    println!("{HITS}{hits_before} then {hits_after}");
    let log = std::fs::read_to_string(&gloas.far_node_log).unwrap_or_default();
    let looked_up = log
        .lines()
        .find(|line| line.contains("Processing Lookup block") && line.contains(&hex0x(root)));
    println!("far node log: {}", looked_up.unwrap_or("no lookup line"));

    assert!(imported, "the far node never imported the block it missed");
    assert!(
        hits_after > hits_before,
        "the sidecar served no block by root, so the far node got it some other way"
    );
    assert!(
        looked_up.is_some(),
        "the far node's log has no lookup for the block, so it got it some other way"
    );
    assert!(
        !gossiped,
        "block_gossip fired for a block the node fetched by root"
    );
}

/// `GET {path}` on the beacon API at `http` as JSON.
async fn beacon_json_at(http: &str, path: &str) -> serde_json::Value {
    reqwest::get(format!("{http}{path}"))
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}

/// The slot of the node's head block.
async fn head_slot(http: &str) -> u64 {
    beacon_json_at(http, "/eth/v1/beacon/headers/head").await["data"]["header"]["message"]["slot"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

/// `sync_lookups_dropped_total{reason="TooManyAttempts"}` at the metrics `origin`.
async fn lookups_dropped_at(origin: &str) -> u64 {
    series(
        origin,
        "sync_lookups_dropped_total{reason=\"TooManyAttempts\"} ",
    )
    .await as u64
}
