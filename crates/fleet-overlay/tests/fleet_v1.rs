//! The system-level properties of a running fleet (T-051). Every test here drives whole
//! sidecars: the wiring `fleet-overlay run` builds, with only the beacon node replaced.

use harness::{Fleet, WAIT, topic};

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
