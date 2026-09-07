//! The system-level properties of a running fleet (T-051). Every test here drives whole
//! sidecars: the wiring `fleet-overlay run` builds, with only the beacon node replaced.

use fleet_overlay::metrics::{
    FIRST_SEEN_TOTAL, LABEL_CLASS, LABEL_DIRECTION, LABEL_PEER, LABEL_REASON, LABEL_SOURCE,
    MESSAGES_TOTAL, PUBLISH_SUPPRESSED_TOTAL, REASON_INJECT_OFF, SOURCE_OVERLAY,
};
use harness::{Fleet, Scrape, WAIT, topic};

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
