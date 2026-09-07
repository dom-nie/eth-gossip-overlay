//! The system-level properties of a running fleet (T-051). Every test here drives whole
//! sidecars: the wiring `eth-gossip-overlay run` builds, with only the beacon node replaced.

use std::time::{Duration, Instant};

use eth_gossip_overlay::metrics::{
    BN_SUBSCRIPTIONS, FIRST_SEEN_TOTAL, LABEL_CLASS, LABEL_DIRECTION, LABEL_PEER, LABEL_REASON,
    LABEL_SOURCE, LABEL_UNIT, MESSAGES_TOTAL, PEER_AUTH_VIA_PREVIOUS_SEED_TOTAL, PEER_QUEUE_DEPTH,
    PEER_QUEUE_DROPS_TOTAL, PUBLISH_SUPPRESSED_TOTAL, REASON_INJECT_OFF, RELAYED_BATCHES_TOTAL,
    SOURCE_OVERLAY, UNIT_BYTES, UNWANTED_TOPIC_TOTAL,
};
use harness::{Fleet, SETTLE, Scrape, WAIT, topic};
use overlay_core::protocol::features;
use overlay_core::relay;
use overlay_core::roster::Hostname;
use overlay_transport::sender::{DropReason, LARGE_LANE_BYTES};
use overlay_transport::testutil::features::mask;

mod harness;

/// §6.1 and §5.5: a block one beacon node validated reaches every other beacon node in the
/// fleet, and each of them sees it once. That is the whole point of the overlay, and the seen
/// cache is what keeps the second copy from arriving.
#[tokio::test(flavor = "multi_thread")]
async fn block_from_one_bn_reaches_every_other_bn_exactly_once() {
    let block = topic("beacon_block");
    let mut fleet = Fleet::builder().regions(&[("eu", 5)]).start().await;
    for node in fleet.nodes() {
        node.subscribe(&block).await;
    }
    fleet.wait_full_mesh(WAIT).await;

    let payload = b"a block from bn 0".to_vec();
    fleet.node(0).bn().publish(&block, &payload).await;

    fleet
        .wait_for(
            "every other beacon node to import the block",
            WAIT,
            |fleet| (1..5).all(|i| fleet.node(i).bn().count(&block, &payload) == 1),
        )
        .await;
    assert_eq!(fleet.node(0).bn().count(&block, &payload), 0, "echoed home");
    fleet.settle().await;
    for i in 1..5 {
        assert_eq!(fleet.node(i).bn().count(&block, &payload), 1, "node {i}");
    }
}

/// D13 and the subscription bitmap: a sender routes from its own view of what each peer asked
/// for, so a beacon node that never subscribed to a subnet is not sent that subnet's traffic at
/// all. Nothing is filtered at the far end, because nothing is sent.
#[tokio::test(flavor = "multi_thread")]
async fn attestation_on_subnet_reaches_only_subscribed_bns() {
    let subnet = topic("beacon_attestation_5");
    let mut fleet = Fleet::builder().regions(&[("eu", 4)]).start().await;
    for index in 0..3 {
        fleet.node(index).subscribe(&subnet).await;
    }
    fleet.wait_full_mesh(WAIT).await;
    fleet.settle().await;

    let unsubscribed = fleet.node(3).hostname().0.clone();
    let sent_to_unsubscribed = |fleet: &Fleet, scrape: &Scrape| {
        let _ = fleet;
        scrape.sum(
            MESSAGES_TOTAL,
            &[(LABEL_DIRECTION, "out"), (LABEL_PEER, &unsubscribed)],
        )
    };
    let before = sent_to_unsubscribed(&fleet, &fleet.node(0).metrics().await);
    let payload = b"an attestation on subnet 5".to_vec();
    fleet.node(0).bn().publish(&subnet, &payload).await;

    fleet
        .wait_for("both subscribed beacon nodes to import it", WAIT, |fleet| {
            (1..3).all(|i| fleet.node(i).bn().count(&subnet, &payload) == 1)
        })
        .await;
    fleet.settle().await;
    assert_eq!(
        fleet.node(3).bn().count(&subnet, &payload),
        0,
        "unsubscribed"
    );
    let after = sent_to_unsubscribed(&fleet, &fleet.node(0).metrics().await);
    assert_eq!(after, before, "the attestation was sent to node 3 anyway");
}

/// §5.5: two beacon nodes validating the same message from public gossip is the normal case,
/// and the seen cache is what turns the two copies into one publish at every other host.
///
/// The two origins are cut from each other so that both really publish. Sharing a connection
/// would let whichever went first reach the other's beacon node before it had, and the copy the
/// scenario is about would never be sent.
#[tokio::test(flavor = "multi_thread")]
async fn same_message_from_two_origins_is_published_once_everywhere() {
    let block = topic("beacon_block");
    let mut fleet = Fleet::builder().regions(&[("eu", 4)]).start().await;
    for node in fleet.nodes() {
        node.subscribe(&block).await;
    }
    fleet.wait_full_mesh(WAIT).await;
    fleet.partition(&[0], &[1]).await;

    let payload = b"one block, two origins".to_vec();
    tokio::join!(
        fleet.node(0).bn().publish(&block, &payload),
        fleet.node(1).bn().publish(&block, &payload),
    );

    fleet
        .wait_for("both other beacon nodes to import it", WAIT, |fleet| {
            (2..4).all(|i| fleet.node(i).bn().count(&block, &payload) == 1)
        })
        .await;
    fleet.settle().await;
    for index in 2..4 {
        assert_eq!(fleet.node(index).bn().count(&block, &payload), 1, "{index}");
    }
    for index in 0..2 {
        assert_eq!(fleet.node(index).bn().count(&block, &payload), 0, "{index}");
    }
}

/// D27: a region is a label, not a topology. One region is a whole fleet and the fanout has no
/// remote half to plan for.
#[tokio::test(flavor = "multi_thread")]
async fn single_region_fleet_works() {
    let block = topic("beacon_block");
    let mut fleet = Fleet::builder().regions(&[("eu", 4)]).start().await;
    for node in fleet.nodes() {
        node.subscribe(&block).await;
    }
    fleet.wait_full_mesh(WAIT).await;

    let payload = b"a block in a one-region fleet".to_vec();
    fleet.node(0).bn().publish(&block, &payload).await;

    fleet
        .wait_for(
            "every other beacon node to import the block",
            WAIT,
            |fleet| (1..4).all(|i| fleet.node(i).bn().count(&block, &payload) == 1),
        )
        .await;
}

/// The other end of D27: three regions, and v1 reaches every one of them directly because a
/// whole message goes to every live subscribed peer wherever it is (§5.4).
#[tokio::test(flavor = "multi_thread")]
async fn three_region_fleet_works() {
    let block = topic("beacon_block");
    let mut fleet = Fleet::builder()
        .regions(&[("eu", 2), ("us", 2), ("ap", 2)])
        .start()
        .await;
    for node in fleet.nodes() {
        node.subscribe(&block).await;
    }
    fleet.wait_full_mesh(WAIT).await;

    let payload = b"a block across three regions".to_vec();
    fleet.node(0).bn().publish(&block, &payload).await;

    fleet
        .wait_for(
            "every other beacon node to import the block",
            WAIT,
            |fleet| (1..6).all(|i| fleet.node(i).bn().count(&block, &payload) == 1),
        )
        .await;
}

/// §5.7's kill switch: a sidecar with `inject: false` is a sidecar an operator has told to stop
/// changing anything. It stays on the overlay, keeps counting what it wins and hands its beacon
/// node nothing.
#[tokio::test(flavor = "multi_thread")]
async fn inject_off_node_receives_and_counts_but_publishes_nothing() {
    let block = topic("beacon_block");
    let mut fleet = Fleet::builder()
        .regions(&[("eu", 3)])
        .config(|settings| settings.inject = false)
        .start()
        .await;
    for node in fleet.nodes() {
        node.subscribe(&block).await;
    }
    fleet.wait_full_mesh(WAIT).await;

    let payload = b"a block nobody may inject".to_vec();
    fleet.node(0).bn().publish(&block, &payload).await;

    fleet
        .wait_for_metrics("node 1 to count what it may not publish", WAIT, |scrapes| {
            let won = scrapes[1].sum(
                FIRST_SEEN_TOTAL,
                &[(LABEL_CLASS, "large"), (LABEL_SOURCE, SOURCE_OVERLAY)],
            );
            let held = scrapes[1].sum(
                PUBLISH_SUPPRESSED_TOTAL,
                &[(LABEL_CLASS, "large"), (LABEL_REASON, REASON_INJECT_OFF)],
            );
            won > 0.0 && held > 0.0
        })
        .await;
    fleet.settle().await;
    assert_eq!(fleet.node(1).bn().count(&block, &payload), 0, "injected");
    assert_eq!(fleet.node(2).bn().count(&block, &payload), 0, "injected");
}

/// §3 principle 1 and the structure that enforces it: the receive path holds nothing that can
/// send, so what reaches a host from the overlay is published locally and goes no further. With
/// A cut from C, a block published at A is at B and nowhere else.
#[tokio::test(flavor = "multi_thread")]
async fn message_takes_one_overlay_hop_only() {
    let block = topic("beacon_block");
    let mut fleet = Fleet::builder().regions(&[("eu", 3)]).start().await;
    for node in fleet.nodes() {
        node.subscribe(&block).await;
    }
    fleet.wait_full_mesh(WAIT).await;
    fleet.partition(&[0], &[2]).await;

    let payload = b"a block that must not be relayed".to_vec();
    fleet.node(0).bn().publish(&block, &payload).await;

    fleet
        .wait_for("node 1 to import the block", WAIT, |fleet| {
            fleet.node(1).bn().count(&block, &payload) == 1
        })
        .await;
    fleet.settle().await;
    assert_eq!(fleet.node(2).bn().count(&block, &payload), 0, "second hop");
}

/// §9: a sidecar that crashes or is upgraded comes back on the same node key and the same
/// address, redials its peers and is a full member of the fleet again. Nothing it missed while
/// it was down is replayed, so what the scenario checks is the next message.
#[tokio::test(flavor = "multi_thread")]
async fn restarted_node_rejoins_and_receives_the_next_message() {
    let block = topic("beacon_block");
    let mut fleet = Fleet::builder().regions(&[("eu", 3)]).start().await;
    for node in fleet.nodes() {
        node.subscribe(&block).await;
    }
    fleet.wait_full_mesh(WAIT).await;

    fleet.restart_node(2).await;
    fleet.wait_full_mesh(WAIT).await;

    let payload = b"a block after the restart".to_vec();
    fleet.node(0).bn().publish(&block, &payload).await;

    fleet
        .wait_for(
            "the restarted node to import the next block",
            WAIT,
            |fleet| fleet.node(2).bn().count(&block, &payload) == 1,
        )
        .await;
}

/// §9: a beacon node that is down or restarting takes its subscriptions with it. Its sidecar
/// stays on the overlay and advertises an empty bitmap, so its siblings stop sending to it
/// instead of queueing for a host that cannot use anything.
#[tokio::test(flavor = "multi_thread")]
async fn bn_disconnect_stops_siblings_sending_to_that_node() {
    let block = topic("beacon_block");
    let mut fleet = Fleet::builder().regions(&[("eu", 3)]).start().await;
    for node in fleet.nodes() {
        node.subscribe(&block).await;
    }
    fleet.wait_full_mesh(WAIT).await;
    let quiet = fleet.node(1).hostname().0.clone();
    let sent_to_quiet = |scrape: &Scrape| {
        scrape.sum(
            MESSAGES_TOTAL,
            &[(LABEL_DIRECTION, "out"), (LABEL_PEER, &quiet)],
        )
    };

    fleet.stop_bn(1).await;
    let mut round = 0;
    let flat = loop {
        let before = sent_to_quiet(&fleet.node(0).metrics().await);
        publish_and_wait(&fleet, &block, &format!("draining {round}")).await;
        let after = sent_to_quiet(&fleet.node(0).metrics().await);
        if after == before {
            break after;
        }
        round += 1;
        assert!(
            round < 20,
            "node 0 kept sending to a beacon node that is gone"
        );
    };

    for message in 0..3 {
        publish_and_wait(&fleet, &block, &format!("after the disconnect {message}")).await;
    }
    let after = sent_to_quiet(&fleet.node(0).metrics().await);
    assert_eq!(after, flat, "node 0 sent to a node with no subscriptions");
}

/// Publishes at node 0 and returns once node 2 has imported it, so the counter a scenario reads
/// afterwards is about a message that has already crossed the fleet.
async fn publish_and_wait(fleet: &Fleet, topic: &str, text: &str) {
    let payload = text.as_bytes().to_vec();
    fleet.node(0).bn().publish(topic, &payload).await;
    fleet
        .wait_for("node 2 to import the block", WAIT, |fleet| {
            fleet.node(2).bn().count(topic, &payload) == 1
        })
        .await;
    fleet.settle().await;
}

/// D17: a peer that cannot keep up costs its senders a bounded amount of memory and nothing
/// else. One node reads at 1 Mbps while large messages are published at full rate; the sender's
/// queue for it stays inside `LARGE_LANE_BYTES`, what does not fit is counted as dropped, and
/// the nodes that are not throttled receive everything at the speed they always did.
#[tokio::test(flavor = "multi_thread")]
async fn slow_peer_at_1_mbps_keeps_sender_memory_under_bound_and_others_unaffected() {
    /// 1 Mbps in bytes per second.
    const ONE_MBPS: u64 = 125_000;
    /// More than the hundred concurrent unidirectional streams a peer will accept, because a
    /// node that stops reading holds every stream it was sent open and the sender blocks on the
    /// next one. That is where the queue behind it starts to fill.
    const MESSAGES: u64 = 140;
    /// Enough messages before the throttle to say what delivery costs without one.
    const BASELINE: u64 = 10;
    const PAYLOAD_BYTES: usize = 64 * 1024;

    let block = topic("beacon_block");
    let mut fleet = Fleet::builder().regions(&[("eu", 4)]).start().await;
    for node in fleet.nodes() {
        node.subscribe(&block).await;
    }
    fleet.wait_full_mesh(WAIT).await;
    let slow = fleet.node(3).hostname().0.clone();
    fleet.throttle_node(3, Some(ONE_MBPS));

    let blocks: Vec<Vec<u8>> = (BASELINE..BASELINE + MESSAGES)
        .map(|index| incompressible(index, PAYLOAD_BYTES))
        .collect();
    let mut unthrottled = Vec::new();
    for index in 0..BASELINE {
        unthrottled.push(
            deliver_to_fast_nodes(&fleet, &block, &incompressible(index, PAYLOAD_BYTES)).await,
        );
    }

    fleet.throttle_node(3, Some(ONE_MBPS));
    let mut paced = Vec::new();
    for payload in &blocks {
        paced.push(deliver_to_fast_nodes(&fleet, &block, payload).await);
        let queued = fleet.node(0).metrics().await.sum(
            PEER_QUEUE_DEPTH,
            &[
                (LABEL_PEER, &slow),
                (LABEL_CLASS, "large"),
                (LABEL_UNIT, UNIT_BYTES),
            ],
        );
        assert!(
            queued <= LARGE_LANE_BYTES as f64,
            "{queued} bytes queued for the slow peer, bound is {LARGE_LANE_BYTES}"
        );
    }
    let (before, after) = (median(&mut unthrottled), median(&mut paced));
    assert!(
        after <= before * 4 + SETTLE,
        "a message took {after:?} to reach the fast nodes, {before:?} before the throttle"
    );

    fleet
        .wait_for_metrics("the sender to count the frames it threw away", WAIT, |s| {
            [DropReason::Full, DropReason::Stale].iter().any(|reason| {
                s[0].sum(
                    PEER_QUEUE_DROPS_TOTAL,
                    &[
                        (LABEL_PEER, &slow),
                        (LABEL_CLASS, "large"),
                        (LABEL_REASON, reason.as_str()),
                    ],
                ) > 0.0
            })
        })
        .await;
    let arrived = blocks
        .iter()
        .filter(|payload| fleet.node(3).bn().count(&block, payload) == 1)
        .count() as u64;
    assert!(arrived < MESSAGES, "the slow peer kept up with {arrived}");
    fleet.throttle_node(3, None);
}

/// Publishes one block at node 0 and answers with how long it took to reach the two nodes
/// nothing has throttled.
async fn deliver_to_fast_nodes(fleet: &Fleet, topic: &str, payload: &[u8]) -> Duration {
    let sent = Instant::now();
    fleet.node(0).bn().publish(topic, payload).await;
    fleet
        .wait_for("both fast nodes to import the block", WAIT, |fleet| {
            (1..3).all(|node| fleet.node(node).bn().count(topic, payload) == 1)
        })
        .await;
    sent.elapsed()
}

/// The middle of `times`, which says what a message costs without one slow round deciding it.
fn median(times: &mut [Duration]) -> Duration {
    times.sort_unstable();
    times[times.len() / 2]
}

/// A payload snappy cannot shrink, so what a beacon node puts on the wire is the size asked for.
fn incompressible(seed: u64, bytes: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
    (0..bytes)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as u8
        })
        .collect()
}

/// DX-N2 and D01: rotating the fleet seed is a rolling operation on the sidecars alone. Every
/// host accepts both seeds while the rotation runs, the sidecars restart one at a time onto the
/// new one, and the beacon nodes see a reconnect from their own sidecar and nothing else,
/// because the libp2p node key is a file on the host rather than something the seed derives.
#[tokio::test(flavor = "multi_thread")]
async fn seed_rotation_with_host_by_host_sidecar_restarts_keeps_the_full_mesh_and_never_restarts_a_bn()
 {
    let block = topic("beacon_block");
    let mut fleet = Fleet::builder().regions(&[("eu", 3)]).start().await;
    for node in fleet.nodes() {
        node.subscribe(&block).await;
    }
    fleet.wait_full_mesh(WAIT).await;

    let identities: Vec<(String, Vec<u8>)> = fleet
        .nodes()
        .iter()
        .map(|node| (node.peer_id().to_owned(), node.lighthouse_env()))
        .collect();
    let connects: Vec<usize> = fleet
        .nodes()
        .iter()
        .map(|node| node.bn().connects())
        .collect();
    let via_previous_seed = |scrapes: &[Scrape]| -> f64 {
        scrapes
            .iter()
            .map(|scrape| scrape.sum(PEER_AUTH_VIA_PREVIOUS_SEED_TOTAL, &[]))
            .sum()
    };
    let before = via_previous_seed(&fleet.metrics().await);

    fleet.rotate_seed([0x22; 32]).await;
    for index in 0..fleet.hosts() {
        fleet.restart_node(index).await;
        fleet.wait_full_mesh(WAIT).await;
    }
    let during = via_previous_seed(&fleet.metrics().await);
    assert!(during > before, "no pairing in the walk used the old seed");

    fleet.retire_previous_seed().await;
    fleet.wait_full_mesh(WAIT).await;
    assert_eq!(
        via_previous_seed(&fleet.metrics().await),
        during,
        "the retired seed still let a peer in"
    );

    let payload = b"a block on the new seed".to_vec();
    fleet.node(0).bn().publish(&block, &payload).await;
    fleet
        .wait_for("the rotated fleet to still deliver", WAIT, |fleet| {
            (1..3).all(|index| fleet.node(index).bn().count(&block, &payload) == 1)
        })
        .await;

    for (index, (peer_id, env)) in identities.iter().enumerate() {
        assert_eq!(fleet.node(index).peer_id(), peer_id, "node {index} peer id");
        assert_eq!(&fleet.node(index).lighthouse_env(), env, "node {index} env");
        assert_eq!(
            fleet.node(index).bn().connects(),
            connects[index] + 1,
            "node {index} beacon node saw more than one reconnect"
        );
        assert_eq!(fleet.node(index).bn().disconnects(), 1, "node {index}");
    }
}

/// §10 and §5.4: a slot's worth of attestations from one beacon node reaches every other beacon
/// node in the fleet, batched into datagrams rather than a stream per attestation. A thousand is
/// more than a fleet this size sees in a slot, and it runs on loopback, so what the bound covers
/// is the sidecar's own path: the batch window, the send queues and the publish queue.
///
/// The bound is measured from the last publish rather than the first, because the burst arrives
/// through the beacon node's own gossipsub link one message at a time and how long a loaded
/// machine takes to hand over a thousand of them is not what this scenario is about. Both
/// numbers are printed.
#[tokio::test(flavor = "multi_thread")]
async fn attestation_burst_of_1000_arrives_within_100_ms_on_loopback() {
    let subnet = topic("beacon_attestation_11");
    let burst: Vec<Vec<u8>> = (0..1000)
        .map(|n| format!("attestation {n} of the burst").into_bytes())
        .collect();
    let mut fleet = Fleet::builder().regions(&[("eu", 3)]).start().await;
    for node in fleet.nodes() {
        node.subscribe(&subnet).await;
    }
    fleet.wait_full_mesh(WAIT).await;
    fleet.settle().await;
    let arrived = |fleet: &Fleet, index: usize| {
        fleet
            .node(index)
            .bn()
            .received()
            .iter()
            .filter(|(seen, _)| *seen == subnet)
            .count()
    };
    let hosts = fleet.hosts();

    let started = Instant::now();
    for payload in &burst {
        fleet.node(0).bn().publish(&subnet, payload).await;
    }
    let published = Instant::now();

    fleet
        .wait_for(
            "every other beacon node to import the burst",
            WAIT,
            |fleet| (1..hosts).all(|index| arrived(fleet, index) >= burst.len()),
        )
        .await;
    let delivery = published.elapsed();
    println!(
        "burst of {} published in {:?}, delivered {:?} later",
        burst.len(),
        published - started,
        delivery
    );
    assert!(
        delivery < Duration::from_millis(100),
        "the burst took {delivery:?} to arrive after the last publish"
    );
    for index in 1..hosts {
        assert_eq!(arrived(&fleet, index), burst.len(), "node {index}");
    }
}

/// Scenario 18 (D29): this release is the first to advertise a feature bit, and a fleet is
/// upgraded host by host, so for as long as the rollout takes some pairs have the bit and some
/// do not. Both keep working: the pair still forms, the older host is served by the whole
/// message path it can read, and what it publishes still reaches the upgraded ones.
///
/// The host that has not been upgraded is one whose HELLO advertises nothing, which is exactly
/// what a release before this one puts in it. A feature set is read once per HELLO, so changing
/// it is a restart, the way upgrading a host is.
#[tokio::test(flavor = "multi_thread")]
async fn rolling_upgrade_adding_a_feature_bit_keeps_pairing_and_serves_older_peers_by_fallback() {
    let subnet = topic("beacon_attestation_9");
    let mut fleet = Fleet::builder().regions(&[("eu", 3)]).start().await;
    for node in fleet.nodes() {
        node.subscribe(&subnet).await;
    }
    fleet.wait_full_mesh(WAIT).await;
    let (upgraded, older) = (
        fleet.node(1).hostname().clone(),
        fleet.node(2).hostname().clone(),
    );

    mask(&older, Some(0));
    fleet.restart_node(2).await;
    fleet.wait_full_mesh(WAIT).await;

    assert_eq!(
        fleet.node(0).negotiated_features(&upgraded).await,
        features::DATAGRAM_BATCHES,
        "two hosts on this release should have negotiated the bit"
    );
    assert_eq!(
        fleet.node(0).negotiated_features(&older).await,
        0,
        "a host that advertised nothing should have negotiated nothing"
    );

    let out = b"an attestation for a fleet halfway through the upgrade".to_vec();
    fleet.node(0).bn().publish(&subnet, &out).await;
    fleet
        .wait_for("both other beacon nodes to import it", WAIT, |fleet| {
            (1..3).all(|index| fleet.node(index).bn().count(&subnet, &out) == 1)
        })
        .await;

    let back = b"an attestation from the host that has not upgraded".to_vec();
    fleet.node(2).bn().publish(&subnet, &back).await;
    fleet
        .wait_for("the upgraded hosts to import what it sent", WAIT, |fleet| {
            (0..2).all(|index| fleet.node(index).bn().count(&subnet, &back) == 1)
        })
        .await;

    mask(&older, None);
    fleet.restart_node(2).await;
    fleet.wait_full_mesh(WAIT).await;
    assert_eq!(
        fleet.node(0).negotiated_features(&older).await,
        features::DATAGRAM_BATCHES,
        "the upgraded host should have negotiated the bit"
    );
}

/// §5.4's WAN saving, measured: one attestation published in `eu` crosses to `us` once per
/// relay and no more, and every host of the remote region is offered it just the same. Sending
/// it directly would have cost a WAN copy per subscriber, which is the five this fleet has and
/// the hundred the deployment §2 describes does.
#[tokio::test(flavor = "multi_thread")]
async fn cross_region_small_batches_cost_one_wan_copy_per_relay() {
    let subnet = topic("beacon_attestation_11");
    let mut fleet = Fleet::builder()
        .regions(&[("eu", 2), ("us", 5)])
        .start()
        .await;
    for node in fleet.nodes() {
        node.subscribe(&subnet).await;
    }
    fleet.wait_full_mesh(WAIT).await;
    let relays = 3;
    fleet.set_relays(4, relays).await;
    let remote: Vec<String> = (2..fleet.hosts())
        .map(|node| fleet.node(node).hostname().0.clone())
        .collect();
    let sent = |scrape: &Scrape| -> f64 {
        remote
            .iter()
            .map(|peer| {
                scrape.sum(
                    MESSAGES_TOTAL,
                    &[(LABEL_DIRECTION, "out"), (LABEL_PEER, peer)],
                )
            })
            .sum()
    };
    let before = sent(&fleet.node(0).metrics().await);

    let payload = b"one attestation for the other region".to_vec();
    fleet.node(0).bn().publish(&subnet, &payload).await;

    for node in 1..fleet.hosts() {
        fleet
            .wait_for(
                "every other host to import the attestation",
                WAIT,
                |fleet| fleet.node(node).bn().count(&subnet, &payload) == 1,
            )
            .await;
    }
    fleet.settle().await;
    let after = sent(&fleet.node(0).metrics().await);
    assert_eq!(after - before, relays as f64, "WAN copies per batch");
}

/// DX-N5 scenario 13, and DX-N1: a relay fans a batch out for its region whether or not it
/// wants anything in it. The host the origin relays through has unsubscribed from the subnet,
/// so it counts the entry as unwanted and offers its own beacon node nothing, and the two hosts
/// beside it are given the attestation all the same (D20).
#[tokio::test(flavor = "multi_thread")]
async fn unsubscribed_relay_refans_but_does_not_publish() {
    let subnet = topic("beacon_attestation_11");
    let mut fleet = Fleet::builder()
        .regions(&[("eu", 1), ("us", 3)])
        .start()
        .await;
    for node in fleet.nodes() {
        node.subscribe(&subnet).await;
    }
    fleet.wait_full_mesh(WAIT).await;
    fleet.set_relays(1, 1).await;
    // Which host the origin relays through is a hash of its own name over the region's hosts in
    // hostname order (D20), which is what the fleet's own numbering gives.
    let pool: Vec<Hostname> = (1..4)
        .map(|node| fleet.node(node).hostname().clone())
        .collect();
    let chosen = relay::select(fleet.node(0).hostname(), &pool, 1);
    let relay = 1 + pool.iter().position(|host| *host == chosen[0]).unwrap();
    let before = fleet.node(relay).metrics().await.sum(BN_SUBSCRIPTIONS, &[]);

    fleet.node(relay).unsubscribe(&subnet).await;
    fleet
        .wait_for_metrics(
            "the relay to stop advertising the subnet",
            WAIT,
            |scrapes| scrapes[relay].sum(BN_SUBSCRIPTIONS, &[]) < before,
        )
        .await;
    let payload = b"an attestation the relay does not want".to_vec();
    fleet.node(0).bn().publish(&subnet, &payload).await;

    for node in (1..4).filter(|node| *node != relay) {
        fleet
            .wait_for("the hosts beside the relay to import it", WAIT, |fleet| {
                fleet.node(node).bn().count(&subnet, &payload) == 1
            })
            .await;
    }
    fleet.settle().await;
    assert_eq!(fleet.node(relay).bn().count(&subnet, &payload), 0);
    let scrape = fleet.node(relay).metrics().await;
    assert!(
        scrape.sum(
            UNWANTED_TOPIC_TOTAL,
            &[(LABEL_PEER, &fleet.node(0).hostname().0)]
        ) > 0.0
    );
    assert!(scrape.sum(RELAYED_BATCHES_TOTAL, &[]) > 0.0);
}

/// DX-N5 scenario 15 for the relay half, and DX-N4: nothing on the overlay receive path waits
/// for a beacon node. The host the origin relays through has a beacon node that has stopped
/// reading its socket, and the region behind it is served all the same: the batch is charged,
/// re-coalesced and handed to the send lanes without the wedged node being consulted.
#[tokio::test(flavor = "multi_thread")]
async fn wedged_bn_on_one_host_does_not_delay_the_second_hop_to_its_region() {
    let subnet = topic("beacon_attestation_11");
    let mut fleet = Fleet::builder()
        .regions(&[("eu", 1), ("us", 3)])
        .start()
        .await;
    for node in fleet.nodes() {
        node.subscribe(&subnet).await;
    }
    fleet.wait_full_mesh(WAIT).await;
    fleet.set_relays(1, 1).await;
    let pool: Vec<Hostname> = (1..4)
        .map(|node| fleet.node(node).hostname().clone())
        .collect();
    let chosen = relay::select(fleet.node(0).hostname(), &pool, 1);
    let relay = 1 + pool.iter().position(|host| *host == chosen[0]).unwrap();

    fleet.node(relay).wedge_bn().await;
    let payload = b"an attestation behind a wedged beacon node".to_vec();
    fleet.node(0).bn().publish(&subnet, &payload).await;

    for node in (1..4).filter(|node| *node != relay) {
        fleet
            .wait_for("the region behind the relay to import it", WAIT, |fleet| {
                fleet.node(node).bn().count(&subnet, &payload) == 1
            })
            .await;
    }
    fleet.settle().await;
    assert_eq!(
        fleet.node(relay).bn().count(&subnet, &payload),
        0,
        "the wedged beacon node cannot have taken anything"
    );
}
