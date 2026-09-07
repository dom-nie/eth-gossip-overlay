//! The system-level properties of a running fleet (T-051). Every test here drives whole
//! sidecars: the wiring `fleet-overlay run` builds, with only the beacon node replaced.

use std::time::{Duration, Instant};

use fleet_overlay::metrics::{
    FIRST_SEEN_TOTAL, LABEL_CLASS, LABEL_DIRECTION, LABEL_PEER, LABEL_REASON, LABEL_SOURCE,
    LABEL_UNIT, MESSAGES_TOTAL, PEER_AUTH_VIA_PREVIOUS_SEED_TOTAL, PEER_QUEUE_DEPTH,
    PEER_QUEUE_DROPS_TOTAL, PUBLISH_SUPPRESSED_TOTAL, REASON_INJECT_OFF, SOURCE_OVERLAY,
    UNIT_BYTES,
};
use harness::{Fleet, SETTLE, Scrape, WAIT, topic};
use overlay_transport::sender::{DropReason, LARGE_LANE_BYTES};

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
#[tokio::test(flavor = "multi_thread")]
async fn same_message_from_two_origins_is_published_once_everywhere() {
    let block = topic("beacon_block");
    let mut fleet = Fleet::builder().regions(&[("eu", 4)]).start().await;
    for node in fleet.nodes() {
        node.subscribe(&block).await;
    }
    fleet.wait_full_mesh(WAIT).await;

    let payload = b"one block, two origins".to_vec();
    fleet.node(0).bn().publish(&block, &payload).await;
    fleet.node(1).bn().publish(&block, &payload).await;

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
