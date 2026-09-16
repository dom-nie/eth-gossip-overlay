//! The sidecar as the only lookup peer for a block it delivered (T-101, R1.1, D42).
//!
//! Lighthouse seeds a parent lookup with the child's sender and nobody else
//! (`block_lookups/mod.rs:175-189` at v8.2.2), because a public forwarder has provably imported
//! the parent. It re-requests the same peer at once on `ResourceUnavailable`
//! (`single_block_lookup.rs:609-618`) and drops the lookup and the child on the fourth failure
//! (`mod.rs:657-661`). With the by-root cache off the sidecar refuses every request, so a block
//! it delivers whose parent the node lacks is dropped before any public peer can join the lookup.
//!
//! The fake plays the node's side of that here: it is offered the child and, as Lighthouse
//! would, asks the sidecar for the parent four times. What the node itself does after the
//! fourth refusal, and what it does once the sidecar declines to be the sender, runs on the
//! matrix against a following-chain node (`matrix.rs`, `MATRIX_FOLLOWING_CHAIN=1`).

use eth_gossip_overlay::metrics::{
    FIRST_SEEN_TOTAL, LABEL_CLASS, LABEL_REASON, LABEL_SOURCE, PUBLISH_SUPPRESSED_TOTAL,
    REASON_PARENT_UNKNOWN, SOURCE_OVERLAY,
};
use harness::{Fleet, WAIT, topic};
use overlay_bn::testutil::{RpcAnswer, fulu_block};

mod harness;

/// Where `parent_root` sits in a `SignedBeaconBlock`: past the offset to `message`, the
/// signature, `slot` and `proposer_index`.
const PARENT_ROOT: std::ops::Range<usize> = 116..148;

/// T-101 test 1, the reproduction on the fake. Node 0's beacon node validated a block whose
/// parent node 1's beacon node has never reported imported. Red on the code this ticket found:
/// node 1's sidecar offers the block, the node asks it for the parent four times and is refused
/// every time, and Lighthouse drops the child (`sync_lookups_dropped_total{reason=
/// "TooManyAttempts"}`). Green once the sidecar keeps the block back and counts it.
#[tokio::test(flavor = "multi_thread")]
async fn a_block_whose_parent_the_node_lacks_is_dropped_by_lighthouse_after_four_refusals() {
    let block = topic("beacon_block");
    let mut fleet = Fleet::builder().regions(&[("eu", 2)]).start().await;
    for node in fleet.nodes() {
        node.subscribe(&block).await;
    }
    fleet.wait_full_mesh(WAIT).await;
    let parent = [0x11; 32];
    let mut child = fulu_block(4_242).ssz;
    child[PARENT_ROOT].copy_from_slice(&parent);

    fleet.node(0).bn().publish(&block, &child).await;

    fleet
        .wait_for_metrics(
            "node 1 to take the block in over the overlay",
            WAIT,
            |scrapes| {
                scrapes[1].sum(
                    FIRST_SEEN_TOTAL,
                    &[(LABEL_CLASS, "large"), (LABEL_SOURCE, SOURCE_OVERLAY)],
                ) > 0.0
            },
        )
        .await;
    fleet.settle().await;
    let offered = fleet.node(1).bn().count(&block, &child);
    // Lighthouse's side: a node offered a block whose parent it lacks asks the sender for the
    // parent, one attempt at a time, and gives up after the fourth refusal.
    let mut refusals = 0;
    for _ in 0..4 * offered {
        if let RpcAnswer::Error(text) = fleet.node(1).bn().lookup_block(parent).await
            && text.contains("ResourceUnavailable")
        {
            refusals += 1;
        }
    }
    assert_eq!(
        offered, 0,
        "node 1's beacon node was offered a block whose parent it has not imported; it asked \
         its sidecar for the parent four times and was refused {refusals} times, so Lighthouse \
         drops the lookup and the child with it"
    );
    let scrape = fleet.node(1).metrics().await;
    assert_eq!(
        scrape.sum(
            PUBLISH_SUPPRESSED_TOTAL,
            &[
                (LABEL_CLASS, "large"),
                (LABEL_REASON, REASON_PARENT_UNKNOWN)
            ],
        ),
        1.0
    );
}
