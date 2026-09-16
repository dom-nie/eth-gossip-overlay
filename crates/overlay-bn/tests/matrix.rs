//! CL-N2's assumptions that need Lighthouse's real peer manager, run against a downloaded
//! release by `scripts/lighthouse-matrix.sh`. Every test is ignored: it needs
//! `LIGHTHOUSE_HTTP` (the beacon API origin), `LIGHTHOUSE_P2P` (`/ip4/127.0.0.1/tcp/<port>`)
//! and `SIDECAR_NODE_KEY` (the node key whose peer id the beacon node was given as
//! `--trusted-peers`); the tests the beacon node has to dial into also read `SIDECAR_LISTEN`,
//! the address it was given in `--libp2p-addresses`. The ten-minute test also reads
//! `LIGHTHOUSE_LOG`, the beacon node's debug-level file log, and runs only under
//! `MATRIX_TEN_MINUTES=1`, which the nightly job sets. The event-stream test needs a beacon
//! node that is following the chain rather than the script's genesis-only node, and runs only
//! under `MATRIX_FOLLOWING_CHAIN=1`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use libp2p::gossipsub::PublishError;
use libp2p::{Multiaddr, PeerId};
use overlay_bn::bn_http::BnClient;
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
use overlay_core::custody::SharedCustody;
use overlay_core::events::Arrivals;
use overlay_core::lanes::ClassLanes;
use overlay_core::recent::{RECENT_MAX_BYTES, RECENT_TTL, RecentLarge, SharedRecentLarge};
use overlay_core::time::SystemClock;
use overlay_core::topic::{SubscriptionSets, Topic};
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
        Arc::default(),
        by_root,
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
/// link registers: `--libp2p-addresses` is dialled once when the network service starts, long
/// before a test process is listening on that port. Its value in this matrix is that the
/// beacon node accepted the flag at all, which is what breaks the day a release removes it.
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
    let custody = SharedCustody::new(spec, sets, Arc::new(()));

    let events = BlockEvents::spawn(
        format!(
            "{}/eth/v1/events?topics=block,block_gossip,data_column_sidecar",
            env.http
        )
        .parse()
        .unwrap(),
        Backoff::new(BACKOFF_MIN, BACKOFF_MAX),
        Arc::new(Arrivals::new(Arc::new(SystemClock), spec_watch().1)),
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
    wait_for_slot(&env, slot).await;
    sidecar
        .publish(&topic, &child)
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
/// (`beacon_chain/src/beacon_chain.rs:4803-4811`): gossip, RPC by root or by range, and the
/// node's own proposal. `block_gossip` fires inside gossip verification only
/// (`block_verification.rs:1068-1076`), so a `block` for a root no `block_gossip` named is an
/// import that did not come by gossip. A node in step with the chain may see none inside the
/// window; then the source is what says so, and this prints as much.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a Lighthouse beacon node following the chain: MATRIX_FOLLOWING_CHAIN=1"]
async fn matrix_the_block_event_fires_for_an_rpc_imported_block() {
    if std::env::var("MATRIX_FOLLOWING_CHAIN").as_deref() != Ok("1") {
        println!("MATRIX_FOLLOWING_CHAIN is not 1; this one needs a node following the chain");
        return;
    }
    let env = env();
    let mut response = reqwest::get(format!(
        "{}/eth/v1/events?topics=block,block_gossip",
        env.http
    ))
    .await
    .unwrap()
    .error_for_status()
    .unwrap();
    let mut gossiped = HashSet::new();
    let mut buf = Vec::new();
    let deadline = Instant::now() + THREE_SLOTS;
    while let Ok(Ok(Some(chunk))) = tokio::time::timeout_at(deadline.into(), response.chunk()).await
    {
        buf.extend_from_slice(&chunk);
        while let Some(end) = buf.windows(2).position(|pair| pair == b"\n\n") {
            let frame = String::from_utf8_lossy(&buf[..end]).into_owned();
            buf.drain(..end + 2);
            let name = frame.lines().find_map(|line| line.strip_prefix("event: "));
            let data = frame.lines().find_map(|line| line.strip_prefix("data: "));
            let root = data
                .and_then(|data| serde_json::from_str::<serde_json::Value>(data).ok())
                .and_then(|data| data["block"].as_str().map(str::to_owned));
            let (Some(name), Some(root)) = (name, root) else {
                continue;
            };
            match name {
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
    }
    println!(
        "every block imported inside {THREE_SLOTS:?} came by gossip; start the node a few slots \
         behind the head to watch an RPC import register the block event \
         (beacon_chain.rs:4803-4811)"
    );
}

/// What the sidecar's responder was asked while the cache is off: the `refused` outcome of
/// `by_root_requests_total`, for blocks.
#[derive(Default)]
struct Refusals {
    blocks: AtomicUsize,
}

impl ByRootStats for Refusals {
    fn by_root_request(&self, protocol: Protocol, outcome: ByRootOutcome) {
        if matches!(protocol, Protocol::BlocksByRootV2) && outcome == ByRootOutcome::Refused {
            self.blocks.fetch_add(1, Ordering::Relaxed);
        }
    }
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
