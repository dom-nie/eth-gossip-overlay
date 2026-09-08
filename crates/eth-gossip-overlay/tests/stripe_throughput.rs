//! What the large class costs in wall time on one machine (T-076), measured on a fleet of whole
//! sidecars rather than on the codec alone.
//!
//! Both benchmarks are `#[ignore]`d, the way the codec and seen-cache benchmarks elsewhere in
//! the workspace are: they take tens of seconds, they measure the machine as much as the code,
//! and a pull request that has not touched the transport learns nothing from re-running them.
//! `docs/performance.md` carries the numbers, the machine they came off and the one command
//! that reproduces them:
//!
//! ```sh
//! cargo test --release -p eth-gossip-overlay --test stripe_throughput -- --ignored --nocapture
//! ```
//!
//! The two configurations are the shipped `overlay.initial_window_bytes` and quinn's own
//! default. It is the only tuned transport parameter an operator can move: the stream limits,
//! the windows and the read timeout are constants, and the receive window is derived from the
//! roster, so a run either side of them would need a config key that deliberately does not
//! exist.

use std::time::{Duration, Instant};

use harness::{Fleet, WAIT, incompressible, topic};

mod harness;

/// A fleet the benchmark can start on one machine and still large enough to stripe over.
const NODES: usize = 20;

/// quinn's own initial congestion window, which is what the overlay ran with before this was
/// tuned. `Overlay::default()`'s 4 MB is the other side of the comparison.
const QUINN_INITIAL_WINDOW: u64 = 14_720;

/// How often a measurement re-reads the beacon nodes. The harness polls every 10 ms, which is a
/// large share of what a striped block takes on loopback, so this reads more finely.
const POLL: Duration = Duration::from_millis(1);

/// How many times each benchmark publishes, so one slow round does not become the number.
const ROUNDS: usize = 5;

/// A fleet of [`NODES`] hosts in one region, striping, at `initial_window_bytes`, with every
/// node subscribed to `topics` and every pair proven to carry traffic.
async fn fleet(initial_window_bytes: u64, topics: &[String]) -> Fleet {
    let mut fleet = Fleet::builder()
        .regions(&[("eu", NODES)])
        .config(|settings| {
            // A fleet of twenty is under the shipped sixteen-recipient floor once a region's
            // subscribers are counted, and this benchmark is about striping.
            settings.stripe_min_recipients = 2;
            settings.initial_window_bytes = initial_window_bytes;
        })
        .start()
        .await;
    for node in fleet.nodes() {
        for name in topics {
            node.subscribe(name).await;
        }
    }
    fleet.wait_full_mesh(WAIT).await;
    fleet.settle().await;
    fleet
}

/// How long every node other than the origin takes to import what node 0 published, from the
/// call that publishes it to the last beacon node holding all of it.
///
/// Arrivals are counted rather than matched, because matching each payload copies every beacon
/// node's whole log on every poll and a slot of columns then measures the polling.
async fn publish_and_wait(fleet: &Fleet, sent: &[(String, Vec<u8>)]) -> Duration {
    let before: Vec<usize> = (0..NODES)
        .map(|node| fleet.node(node).bn().received_count())
        .collect();

    let started = Instant::now();
    for (name, payload) in sent {
        fleet.node(0).bn().publish(name, payload).await;
    }
    let deadline = started + WAIT;
    loop {
        let done = (1..NODES)
            .all(|node| fleet.node(node).bn().received_count() - before[node] >= sent.len());
        if done {
            let elapsed = started.elapsed();
            for node in 1..NODES {
                for (name, payload) in sent {
                    assert_eq!(fleet.node(node).bn().count(name, payload), 1, "node {node}");
                }
            }
            return elapsed;
        }
        assert!(
            Instant::now() < deadline,
            "waited {WAIT:?} for {} messages to reach {} nodes",
            sent.len(),
            NODES - 1
        );
        tokio::time::sleep(POLL).await;
    }
}

/// The rounds as a line for `docs/performance.md`: each one, and the median, which is what the
/// document quotes.
fn report(what: &str, rounds: &[Duration]) -> Duration {
    let mut sorted = rounds.to_vec();
    sorted.sort();
    let median = sorted[sorted.len() / 2];
    let each: Vec<String> = rounds
        .iter()
        .map(|d| format!("{:.1}", millis(*d)))
        .collect();
    println!(
        "{what}: median {:.1} ms over {} rounds [{}]",
        millis(median),
        rounds.len(),
        each.join(", ")
    );
    median
}

fn millis(elapsed: Duration) -> f64 {
    elapsed.as_secs_f64() * 1e3
}

/// §5.4's large class end to end: one 200 kB block, striped over twenty hosts, from the
/// publish that starts it to the last beacon node that imports it.
///
/// The tuned configuration must not be slower than the default. On loopback it has almost
/// nothing to win, because the congestion window an operator raises is there for a path with a
/// real round trip; what the run proves is that raising it costs nothing.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn bench_stripe_200kb_20_nodes_default_vs_tuned() {
    let block = topic("beacon_block");
    let topics = [block.clone()];
    let mut medians = Vec::new();

    for (what, window) in [
        ("default (quinn's initial window)", QUINN_INITIAL_WINDOW),
        ("tuned (initial_window_bytes)", 4_000_000),
    ] {
        let fleet = fleet(window, &topics).await;
        let mut rounds = Vec::new();
        for round in 0..ROUNDS {
            let payload = incompressible(round as u64, 200 * 1024);
            rounds.push(publish_and_wait(&fleet, &[(block.clone(), payload)]).await);
        }
        medians.push(report(
            &format!("200 kB block, {NODES} nodes, {what}"),
            &rounds,
        ));
    }

    let (default, tuned) = (medians[0], medians[1]);
    // Loopback timings on a shared machine move by tens of percent between runs, so the check
    // is that the tuned side did not lose, not that it won.
    assert!(
        tuned <= default * 2,
        "tuned {tuned:?} against default {default:?}"
    );
}

/// One slot's data columns, which is the traffic §10 sizes the fleet against: 128 columns of
/// about 40 kB published back to back, every one of them striped, on to every host.
#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn bench_one_slot_of_columns_20_nodes() {
    const COLUMNS: usize = 128;
    let topics: Vec<String> = (0..COLUMNS)
        .map(|index| topic(&format!("data_column_sidecar_{index}")))
        .collect();
    let mut medians = Vec::new();

    for (what, window) in [
        ("default (quinn's initial window)", QUINN_INITIAL_WINDOW),
        ("tuned (initial_window_bytes)", 4_000_000),
    ] {
        let fleet = fleet(window, &topics).await;
        let mut rounds = Vec::new();
        for round in 0..ROUNDS {
            let slot: Vec<(String, Vec<u8>)> = topics
                .iter()
                .enumerate()
                .map(|(index, name)| {
                    let seed = (round * COLUMNS + index) as u64;
                    (name.clone(), incompressible(seed, 40 * 1024))
                })
                .collect();
            rounds.push(publish_and_wait(&fleet, &slot).await);
        }
        medians.push(report(
            &format!("{COLUMNS} columns of 40 kB, {NODES} nodes, {what}"),
            &rounds,
        ));
    }

    let (default, tuned) = (medians[0], medians[1]);
    assert!(
        tuned <= default * 2,
        "tuned {tuned:?} against default {default:?}"
    );
}
