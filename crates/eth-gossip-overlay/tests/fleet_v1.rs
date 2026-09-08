//! The system-level properties of a running fleet (T-051). Every test here drives whole
//! sidecars: the wiring `eth-gossip-overlay run` builds, with only the beacon node replaced.

use std::time::{Duration, Instant};

use eth_gossip_overlay::metrics::{
    BN_SUBSCRIPTIONS, BYTES_TOTAL, CHUNKS_RECEIVED_TOTAL, FIRST_SEEN_TOTAL, LABEL_CLASS,
    LABEL_DIRECTION, LABEL_OUTCOME, LABEL_PEER, LABEL_REASON, LABEL_SOURCE, LABEL_UNIT,
    MESSAGES_TOTAL, PARITY_USED_TOTAL, PEER_AUTH_VIA_PREVIOUS_SEED_TOTAL, PEER_QUEUE_DEPTH,
    PEER_QUEUE_DROPS_TOTAL, PUBLISH_SUPPRESSED_TOTAL, REASON_INJECT_OFF, RECONSTRUCT_SECONDS,
    RELAYED_BATCHES_TOTAL, REPAIR_REQUESTS_TOTAL, SOURCE_OVERLAY, UNANNOUNCED_TOPIC_TOTAL,
    UNIT_BYTES, UNKNOWN_TOPIC_ID_TOTAL, UNWANTED_TOPIC_TOTAL,
};
use harness::{Fleet, SETTLE, Scrape, WAIT, incompressible, topic};
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
        features::DATAGRAM_BATCHES | features::STRIPING | features::REPAIR,
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
        features::DATAGRAM_BATCHES | features::STRIPING | features::REPAIR,
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

/// DX-N5 scenario 13, DX-N1 and MD-04: a relay carries a batch for its region whether or not it
/// wants anything in it. The host the origin relays through has never subscribed to the subnet,
/// which is the ordinary case for an attestation subnet on a fleet where duties are spread: it
/// interns an id, announces it, counts the entries as unwanted and offers its own beacon node
/// nothing, and the two hosts beside it are given the attestation all the same (D20).
#[tokio::test(flavor = "multi_thread")]
async fn unsubscribed_relay_refans_but_does_not_publish() {
    let subnet = topic("beacon_attestation_11");
    let mut fleet = Fleet::builder()
        .regions(&[("eu", 1), ("us", 3)])
        .start()
        .await;
    fleet.wait_full_mesh(WAIT).await;
    fleet.set_relays(1, 1).await;
    // Which host the origin relays through is a hash of its own name over the region's hosts in
    // hostname order (D20), which is what the fleet's own numbering gives.
    let pool: Vec<Hostname> = (1..4)
        .map(|node| fleet.node(node).hostname().clone())
        .collect();
    let chosen = relay::select(fleet.node(0).hostname(), &pool, 1);
    let relay = 1 + pool.iter().position(|host| *host == chosen[0]).unwrap();
    let subscribers: Vec<usize> = (1..4).filter(|node| *node != relay).collect();
    let before = fleet.metrics().await;
    for node in std::iter::once(0).chain(subscribers.iter().copied()) {
        fleet.node(node).subscribe(&subnet).await;
    }
    fleet
        .wait_for_metrics("everyone but the relay to want the subnet", WAIT, |now| {
            std::iter::once(0)
                .chain(subscribers.iter().copied())
                .all(|node| {
                    now[node].sum(BN_SUBSCRIPTIONS, &[]) > before[node].sum(BN_SUBSCRIPTIONS, &[])
                })
        })
        .await;
    fleet.settle().await;
    // The first attestation is what makes the relay intern an id for the subnet, and it is lost
    // while the TOPIC_ADD crosses the control stream: an entry never goes out under a binding
    // the peer has not been told (MD-04).
    fleet
        .node(0)
        .bn()
        .publish(&subnet, b"the one that pays for the announcement")
        .await;
    fleet.settle().await;

    let payload = b"an attestation the relay does not want".to_vec();
    fleet.node(0).bn().publish(&subnet, &payload).await;

    for node in subscribers {
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
    assert_eq!(
        scrape.sum(UNANNOUNCED_TOPIC_TOTAL, &[]),
        0.0,
        "the relay refused to name a topic it was asked to carry"
    );
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

/// DX-N5 scenario 12: a region with fewer subscribers than `stripe_min_recipients` takes a
/// large message whole, and one below `relay_min_remote_hosts` takes the small class straight
/// from the origin (§5.4, D36). A single-host region and a two-host region are under both
/// thresholds the shipped configuration sets, which is how a small fleet stays on the path v1
/// delivered everything by while a fleet of a hundred hosts per region stripes and relays.
#[tokio::test(flavor = "multi_thread")]
async fn single_and_two_host_regions_use_whole_delivery_and_the_direct_small_path() {
    let (block, subnet) = (topic("beacon_block"), topic("beacon_attestation_9"));
    let mut fleet = Fleet::builder()
        .regions(&[("eu", 1), ("us", 2)])
        .start()
        .await;
    for node in fleet.nodes() {
        node.subscribe(&block).await;
        node.subscribe(&subnet).await;
    }
    fleet.wait_full_mesh(WAIT).await;
    fleet.settle().await;
    let sent_to = |scrape: &Scrape, peer: &Hostname| {
        scrape.sum(
            MESSAGES_TOTAL,
            &[(LABEL_DIRECTION, "out"), (LABEL_PEER, &peer.0)],
        )
    };
    let before = fleet.node(0).metrics().await;

    let payload = b"a block into a two host region".to_vec();
    fleet.node(0).bn().publish(&block, &payload).await;
    fleet
        .wait_for(
            "both hosts of the other region to import it",
            WAIT,
            |fleet| (1..3).all(|node| fleet.node(node).bn().count(&block, &payload) == 1),
        )
        .await;
    let attestation = b"an attestation into a two host region".to_vec();
    fleet.node(0).bn().publish(&subnet, &attestation).await;
    fleet
        .wait_for(
            "both of them to import the attestation too",
            WAIT,
            |fleet| (1..3).all(|node| fleet.node(node).bn().count(&subnet, &attestation) == 1),
        )
        .await;
    fleet.settle().await;

    // One copy of each message per host, which is what whole delivery and a direct batch look
    // like from the origin: no chunk went to one host for the other to forward, and no batch
    // went to one host to be re-fanned to the other.
    let after = fleet.node(0).metrics().await;
    for node in 1..3 {
        let peer = fleet.node(node).hostname();
        assert_eq!(
            sent_to(&after, peer) - sent_to(&before, peer),
            2.0,
            "node {node}"
        );
    }
    // The single-host region is a recipient as well as an origin: nobody in it forwards, so a
    // message that reached it whole is a message its beacon node has.
    let homeward = b"a block into a single host region".to_vec();
    fleet.node(1).bn().publish(&block, &homeward).await;
    fleet
        .wait_for(
            "the other region and the region peer to import it",
            WAIT,
            |fleet| {
                [0, 2]
                    .iter()
                    .all(|node| fleet.node(*node).bn().count(&block, &homeward) == 1)
            },
        )
        .await;
    fleet.settle().await;
    for (node, scrape) in fleet.metrics().await.iter().enumerate() {
        assert_eq!(scrape.sum(RELAYED_BATCHES_TOTAL, &[]), 0.0, "node {node}");
    }
}

/// DX-N5 scenario 15 for the chunk half, and DX-N4: cut-through does not wait for a beacon
/// node. The host a chunk lands on has a beacon node that has stopped reading its socket, and
/// the rest of its region is given that chunk all the same, because the forward is issued from
/// the chunk's arrival and nothing on that path consults the node.
#[tokio::test(flavor = "multi_thread")]
async fn wedged_bn_on_one_host_does_not_delay_the_chunk_second_hop_to_its_region() {
    let block = topic("beacon_block");
    let mut fleet = Fleet::builder()
        .regions(&[("eu", 4)])
        .config(|settings| settings.stripe_min_recipients = 2)
        .start()
        .await;
    for node in fleet.nodes() {
        node.subscribe(&block).await;
    }
    fleet.wait_full_mesh(WAIT).await;
    fleet.node(1).wedge_bn().await;
    let wedged = fleet.node(1).hostname().0.clone();

    fleet
        .node(0)
        .bn()
        .publish(&block, &incompressible(7, 200 * 1024))
        .await;

    for node in [2, 3] {
        fleet
            .wait_for_metrics(
                "the region behind the wedged host to be given chunks",
                WAIT,
                |now| {
                    now[node].sum(
                        MESSAGES_TOTAL,
                        &[(LABEL_DIRECTION, "in"), (LABEL_PEER, &wedged)],
                    ) > 0.0
                },
            )
            .await;
    }
}

/// DX-N5 scenario 11 and D12: an id reaches a peer over the control stream and a chunk naming
/// it travels on a stream of its own, so a topic the origin has only just subscribed to can be
/// named on the wire before the peer has been told what the name means. This drives the race a
/// fleet really runs, subscribing the origin last and publishing at once, and asserts what it is
/// meant to leave behind: a fleet that carried the message anyway and a counter that stops
/// moving once the announcement has landed, which is what makes a non-zero rate in the canary
/// worth looking at. The announcement wins every time here, so the drop itself is asserted where
/// it can be forced, in `receive`'s `chunk_under_an_unannounced_topic_id_is_counted_and_dropped`.
#[tokio::test(flavor = "multi_thread")]
async fn chunk_arriving_before_topic_add_is_counted_not_crashed_and_zero_in_steady_state() {
    let column = topic("data_column_sidecar_5");
    let mut fleet = Fleet::builder()
        .regions(&[("eu", 3)])
        .config(|settings| settings.stripe_min_recipients = 2)
        .start()
        .await;
    fleet.wait_full_mesh(WAIT).await;
    // The subscribers first, so the origin's stripe has somewhere to go, and the origin last, so
    // the only announcement still in flight when it publishes is its own.
    for node in [1, 2] {
        fleet.node(node).subscribe(&column).await;
    }
    fleet.settle().await;
    fleet.node(0).subscribe(&column).await;

    let racing = incompressible(11, 200 * 1024);
    fleet.node(0).bn().publish(&column, &racing).await;
    for node in [1, 2] {
        fleet
            .wait_for_metrics(
                "both hosts to be reading the column's chunks",
                WAIT,
                |now| now[node].sum(MESSAGES_TOTAL, &[(LABEL_DIRECTION, "in")]) > 0.0,
            )
            .await;
    }
    fleet.settle().await;

    let before = fleet.metrics().await;
    let settled = incompressible(12, 200 * 1024);
    fleet.node(0).bn().publish(&column, &settled).await;
    for node in [1, 2] {
        fleet
            .wait_for_metrics("both hosts to read the second one's chunks", WAIT, |now| {
                now[node].sum(BYTES_TOTAL, &[(LABEL_DIRECTION, "in")])
                    > before[node].sum(BYTES_TOTAL, &[(LABEL_DIRECTION, "in")])
            })
            .await;
    }
    fleet.settle().await;

    for (node, now) in fleet.metrics().await.iter().enumerate() {
        assert_eq!(
            now.sum(UNKNOWN_TOPIC_ID_TOTAL, &[]) - before[node].sum(UNKNOWN_TOPIC_ID_TOTAL, &[]),
            0.0,
            "node {node} is still naming an id its peers do not know"
        );
    }
}

/// §5.4's whole reason for existing, measured: a 200 KB block leaves the origin as about two
/// block-equivalents, one stripe per region, however many hosts are in them, and each host of
/// the striped region passes on about one block-equivalent. Fanning the block out whole would
/// have cost the origin one copy per host, which is the eleven this fleet has and the two
/// hundred the deployment §2 describes does.
#[tokio::test(flavor = "multi_thread")]
async fn striped_block_costs_the_origin_two_block_equivalents_and_each_host_one() {
    let block = topic("beacon_block");
    let mut fleet = Fleet::builder()
        .regions(&[("eu", 10), ("us", 2)])
        .config(|settings| settings.stripe_min_recipients = 2)
        .start()
        .await;
    for node in fleet.nodes() {
        node.subscribe(&block).await;
    }
    fleet.wait_full_mesh(WAIT).await;
    fleet.settle().await;
    let out = |scrape: &Scrape| scrape.sum(BYTES_TOTAL, &[(LABEL_DIRECTION, "out")]);
    let before = fleet.metrics().await;

    let payload = incompressible(13, 200 * 1024);
    fleet.node(0).bn().publish(&block, &payload).await;

    for node in 1..10 {
        fleet
            .wait_for_metrics(
                "every host of the origin's region to pass its chunks on",
                WAIT,
                |now| out(&now[node]) - out(&before[node]) > 0.0,
            )
            .await;
    }
    fleet.settle().await;

    // The gossipsub wire form is what the sidecar splits, and snappy leaves an incompressible
    // payload about as long as it started, so the block-equivalent this is measured in is the
    // published length give or take the framing.
    let block_bytes = payload.len() as f64;
    let now = fleet.metrics().await;
    let origin = (out(&now[0]) - out(&before[0])) / block_bytes;
    assert!(
        (2.0..2.4).contains(&origin),
        "the origin sent {origin} block-equivalents"
    );
    for node in 1..10 {
        let host = (out(&now[node]) - out(&before[node])) / block_bytes;
        assert!(
            (0.8..1.2).contains(&host),
            "node {node} sent {host} block-equivalents"
        );
    }
}

/// How many messages a node has put back together from chunks, which is the `_count` of the
/// `reconstruct_seconds` histogram.
fn reassembled(scrape: &Scrape) -> f64 {
    scrape.sum(&format!("{RECONSTRUCT_SECONDS}_count"), &[])
}

/// The chunks one message of `bytes` is cut into at `parity_ratio`, rounded generously: the
/// sidecar splits the gossipsub wire form, and snappy leaves an incompressible payload a few
/// bytes longer than it started.
fn chunks_per_message(bytes: usize, parity_ratio: f64) -> usize {
    let data = (bytes + 64).div_ceil(2048).max(1);
    data + ((parity_ratio * data as f64).ceil() as usize).max(1)
}

/// §5.4 end to end, which is what the whole large class exists for: a block one beacon node
/// validated is cut up, spread over the region a chunk per host, passed on once by each of them
/// and put back together on every host, whose beacon node imports it exactly once. Until the
/// reassembler landed the chunks were counted, forwarded and dropped, so this is the scenario
/// that says striping delivers.
///
/// Nothing is asserted about `parity_used_total` here. A message is put back together from the
/// first k chunks that arrive, and a host reads its own assignment before the forwards, so a
/// parity chunk lands among the first k whenever the arrival order is not the index order. The
/// counter says the codec was needed, which is a weaker thing than a host having been down.
#[tokio::test(flavor = "multi_thread")]
async fn block_striped_across_region_is_published_once_on_every_node() {
    let block = topic("beacon_block");
    let hosts = 5;
    let mut fleet = Fleet::builder()
        .regions(&[("eu", hosts)])
        .config(|settings| settings.stripe_min_recipients = 2)
        .start()
        .await;
    for node in fleet.nodes() {
        node.subscribe(&block).await;
    }
    fleet.wait_full_mesh(WAIT).await;

    let payload = incompressible(21, 200 * 1024);
    fleet.node(0).bn().publish(&block, &payload).await;

    fleet
        .wait_for(
            "every other beacon node to import the block",
            WAIT,
            |fleet| (1..hosts).all(|node| fleet.node(node).bn().count(&block, &payload) == 1),
        )
        .await;
    fleet.settle().await;
    for node in 1..hosts {
        assert_eq!(
            fleet.node(node).bn().count(&block, &payload),
            1,
            "node {node}"
        );
    }
    assert_eq!(
        fleet.node(0).bn().count(&block, &payload),
        0,
        "the origin was published its own block"
    );
    let now = fleet.metrics().await;
    for (node, scrape) in now.iter().enumerate().skip(1) {
        assert_eq!(reassembled(scrape), 1.0, "node {node}");
        // What `OverlayWinRateFalling` divides: a block the overlay brought counts on the
        // overlay's side of `first_seen_total`, or the alert reads "never wins" on a striping
        // fleet that is working (§12, D08).
        assert!(
            scrape.sum(
                FIRST_SEEN_TOTAL,
                &[(LABEL_CLASS, "large"), (LABEL_SOURCE, SOURCE_OVERLAY)]
            ) > 0.0,
            "node {node} won a block the win rate cannot see"
        );
    }
    assert_eq!(
        reassembled(&now[0]),
        0.0,
        "the origin reassembled its own block"
    );
}

/// §5.4 step 4: parity exists for the host that is not there. One host of the region is cut off
/// from the rest of it, so the chunks the origin striped to it never reach anybody else, and
/// every other host still ends up with the block because the parity chunks stand in for what it
/// was carrying. The origin keeps the cut host in its live view, which is what makes it a stripe
/// target whose chunks go nowhere rather than a host the assignment skips.
#[tokio::test(flavor = "multi_thread")]
async fn block_still_completes_when_one_stripe_host_is_down() {
    let block = topic("beacon_block");
    let hosts = 5;
    let mut fleet = Fleet::builder()
        .regions(&[("eu", hosts)])
        .config(|settings| {
            settings.stripe_min_recipients = 2;
            settings.parity_ratio = 1.0;
        })
        .start()
        .await;
    for node in fleet.nodes() {
        node.subscribe(&block).await;
    }
    fleet.wait_full_mesh(WAIT).await;
    fleet.partition(&[hosts - 1], &[1, 2, 3]).await;

    let payload = incompressible(22, 100 * 1024);
    fleet.node(0).bn().publish(&block, &payload).await;

    fleet
        .wait_for(
            "the rest of the region to import the block",
            WAIT,
            |fleet| (1..hosts - 1).all(|node| fleet.node(node).bn().count(&block, &payload) == 1),
        )
        .await;
    fleet.settle().await;
    let now = fleet.metrics().await;
    for (node, scrape) in now.iter().enumerate().take(hosts - 1).skip(1) {
        assert_eq!(
            fleet.node(node).bn().count(&block, &payload),
            1,
            "node {node}"
        );
        assert!(
            scrape.sum(PARITY_USED_TOTAL, &[]) > 0.0,
            "node {node} completed without the parity it should have needed"
        );
    }
}

/// DX-N5 scenario 10 and D19: two beacon nodes take the same block off public gossip, and their
/// sidecars do not see the same region, so the two stripes overlap without matching. Every host
/// still publishes the block once, and reads at most two stripes' worth of chunks, because the
/// second copy of an index is stored nowhere and passed on nowhere.
///
/// Neither origin can hear the other, which is what makes them two origins rather than one: a
/// sidecar that had already put the block together would find its own beacon node's copy in its
/// seen cache and fan out nothing.
#[tokio::test(flavor = "multi_thread")]
async fn two_origins_with_divergent_live_views_publish_once_with_at_most_2k_plus_m_chunks_received()
{
    let block = topic("beacon_block");
    let hosts = 5;
    let mut fleet = Fleet::builder()
        .regions(&[("eu", hosts)])
        .config(|settings| settings.stripe_min_recipients = 2)
        .start()
        .await;
    for node in fleet.nodes() {
        node.subscribe(&block).await;
    }
    fleet.wait_full_mesh(WAIT).await;
    // One origin sees neither the other origin nor the last host, so the two assignments run
    // over different pools and neither origin is a target of the other.
    fleet.partition(&[0], &[1, hosts - 1]).await;
    let before = fleet.metrics().await;

    let payload = incompressible(23, 100 * 1024);
    fleet.node(0).bn().publish(&block, &payload).await;
    fleet.node(1).bn().publish(&block, &payload).await;

    fleet
        .wait_for(
            "every host that is not an origin to import it",
            WAIT,
            |fleet| (2..hosts).all(|node| fleet.node(node).bn().count(&block, &payload) == 1),
        )
        .await;
    fleet.settle().await;
    let stripe = chunks_per_message(payload.len(), 0.1);
    let now = fleet.metrics().await;
    for (node, scrape) in now.iter().enumerate() {
        assert!(
            fleet.node(node).bn().count(&block, &payload) <= 1,
            "node {node} imported the block twice"
        );
        let chunks =
            scrape.sum(CHUNKS_RECEIVED_TOTAL, &[]) - before[node].sum(CHUNKS_RECEIVED_TOTAL, &[]);
        assert!(
            chunks <= 2.0 * stripe as f64,
            "node {node} read {chunks} chunks of a {stripe} chunk message"
        );
    }
    for (origin, scrape) in now.iter().enumerate().take(2) {
        assert!(
            reassembled(scrape) <= 1.0,
            "origin {origin} reassembled more than the one stripe it could hear"
        );
    }
}

/// DX-N5 scenario 16, the parity half: a third of a region goes away in the middle of a slot,
/// taking the chunks the origin striped to it with them, and the hosts that are left put the
/// block together from parity without asking anyone for anything. The repair half of this
/// scenario, where parity alone is not enough, arrives with T-082; `repair_requests_total`
/// reading zero here is what says parity did the work on its own.
#[tokio::test(flavor = "multi_thread")]
async fn one_third_of_a_region_lost_mid_slot_completes_via_parity_or_repair_before_the_deadline() {
    let block = topic("beacon_block");
    let hosts = 6;
    let mut fleet = Fleet::builder()
        .regions(&[("eu", hosts)])
        .config(|settings| {
            settings.stripe_min_recipients = 2;
            settings.parity_ratio = 1.0;
        })
        .start()
        .await;
    for node in fleet.nodes() {
        node.subscribe(&block).await;
    }
    fleet.wait_full_mesh(WAIT).await;
    fleet.partition(&[4, 5], &[1, 2, 3]).await;

    let payload = incompressible(24, 100 * 1024);
    fleet.node(0).bn().publish(&block, &payload).await;

    fleet
        .wait_for("the two thirds still talking to import it", WAIT, |fleet| {
            (1..4).all(|node| fleet.node(node).bn().count(&block, &payload) == 1)
        })
        .await;
    fleet.settle().await;
    let now = fleet.metrics().await;
    for (node, scrape) in now.iter().enumerate().take(4).skip(1) {
        assert!(
            scrape.sum(PARITY_USED_TOTAL, &[]) > 0.0,
            "node {node} did not need the parity a third of the region was carrying"
        );
        assert_eq!(
            scrape.sum(REPAIR_REQUESTS_TOTAL, &[]),
            0.0,
            "node {node} asked for chunks parity had already covered"
        );
    }
}

/// §5.6 on a whole fleet: a stripe host stops talking to the rest of its region in the middle of
/// a transfer, so the chunks the origin sent it reach nobody else, and the shipped tenth of
/// parity is nowhere near enough to cover what it was carrying. Every host that is left asks a
/// peer for exactly the indices it is short of and hands its beacon node the block once.
///
/// The host is cut from the region rather than stopped, because a host the origin no longer sees
/// is one the assignment skips and there is nothing to repair; what repair exists for is the host
/// that is still a stripe target when the block is cut up and is gone by the time its chunks
/// should have been passed on.
#[tokio::test(flavor = "multi_thread")]
async fn block_completes_via_repair_when_a_stripe_host_dies_mid_transfer() {
    let block = topic("beacon_block");
    let hosts = 5;
    let mut fleet = Fleet::builder()
        .regions(&[("eu", hosts)])
        .config(|settings| settings.stripe_min_recipients = 2)
        .start()
        .await;
    for node in fleet.nodes() {
        node.subscribe(&block).await;
    }
    fleet.wait_full_mesh(WAIT).await;
    fleet.partition(&[hosts - 1], &[1, 2, 3]).await;

    let payload = incompressible(25, 100 * 1024);
    fleet.node(0).bn().publish(&block, &payload).await;

    fleet
        .wait_for(
            "the rest of the region to import the block",
            WAIT,
            |fleet| (1..hosts - 1).all(|node| fleet.node(node).bn().count(&block, &payload) == 1),
        )
        .await;
    fleet.settle().await;
    let now = fleet.metrics().await;
    for (node, scrape) in now.iter().enumerate().take(hosts - 1).skip(1) {
        assert_eq!(
            fleet.node(node).bn().count(&block, &payload),
            1,
            "node {node}"
        );
        assert!(
            scrape.sum(REPAIR_REQUESTS_TOTAL, &[(LABEL_OUTCOME, "completed")]) > 0.0,
            "node {node} finished the block without repairing it"
        );
    }
}
