//! Asking a peer for the chunks a message never got, on a stream of its own (§5.6, D23, D24).
//!
//! One task per host, not per peer: repair is about a message rather than about a connection,
//! and the peers to ask come from which of them sent a chunk of it (D23). Every tick the task
//! asks [`Scheduler`] what to do, then does it. The scheduler is pure and the task is all the
//! network there is.
//!
//! # The reassembler's lock is never held across an `await`
//!
//! [`Scheduler::tick`] is not `async`. It takes the lock inside `incomplete_older_than`, copies
//! out the incomplete list with its missing indices and its senders, drops the lock and returns
//! plain values. Only then does this module open a stream. A future holding the guard could not
//! be awaited even if someone wrote one, because the guard never leaves that call.
//!
//! # Nothing is asked of a peer that did not advertise `REPAIR`
//!
//! The candidate list is filtered by the negotiated feature bits, so a peer one release behind
//! is never sent a frame it would read as an unknown type, and never has to answer one (D29). A
//! message whose only senders are such peers is given up on at once rather than stalling until
//! the budget runs out, which is what makes public gossip the backup rather than the wait.

use std::time::Duration;

use overlay_core::msgid::MessageId;
use overlay_core::protocol::{MAX_FRAME_BYTES, features};
use overlay_core::repair::{
    ColumnKey, ColumnRequest, Decision, Outcome, REPAIR_TICK, Request, Scheduler,
};
use overlay_core::roster::{Hostname, Region};
use overlay_core::wire::{self, Frame, Read, RepairReq, RepairResp};
use tokio::sync::watch;
use tokio::task::{JoinHandle, JoinSet};

use crate::manager::{LivePeer, LiveView};
use crate::receive::{Deps, RepairSink};

/// Starts the repair scheduler for this host. It ends when the task is aborted, which is what a
/// shutdown does to every other task the sidecar owns.
///
/// `deadline` is `classes.large.repair_deadline_ms` on the channel T-043's reload writes, read
/// afresh on every tick so a change takes hold on the next one.
pub fn spawn(deps: Deps, deadline: watch::Receiver<Duration>) -> JoinHandle<()> {
    tokio::spawn(run(deps, deadline))
}

/// Which repair an attempt answered, so one [`JoinSet`] carries both forms.
enum Answered {
    Message(MessageId, Outcome),
    Column(ColumnKey, Outcome),
}

async fn run(deps: Deps, deadline: watch::Receiver<Duration>) {
    let mut scheduler = Scheduler::default();
    let mut attempts: JoinSet<Answered> = JoinSet::new();
    let mut tick = tokio::time::interval(REPAIR_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        while let Some(finished) = attempts.try_join_next() {
            match finished {
                Ok(Answered::Message(msg_id, outcome)) => {
                    deps.stats.repair_request(outcome);
                    scheduler.answered(&msg_id);
                }
                Ok(Answered::Column(key, outcome)) => {
                    deps.stats.repair_request(outcome);
                    scheduler.answered_column(&key);
                }
                Err(_) => continue,
            }
        }
        // One snapshot per tick, which is also one read of every peer's smoothed round trip:
        // the estimate a candidate list is sorted by is the one taken when the list was built.
        let view = deps.relaying.live.live();
        let now = deps.clock.now();
        let decided = scheduler.tick(
            &deps.reassembler,
            *deadline.borrow(),
            |peer| reachable(&view, peer),
            now,
        );
        // The columns the beacon node is short of, on the same tick and against the same live
        // view. What the tracker holds came from the node's own event stream, so this is the one
        // read in the loop that no peer can influence (§6.4, MD-06).
        let in_flight = deps
            .custody
            .column_set(deps.reassembler.in_flight_columns());
        let gaps = deps.custody.gaps(*deadline.borrow(), now, &in_flight);
        let columns = scheduler.tick_columns(
            &gaps,
            deps.custody.threshold(),
            &in_flight,
            &in_region_by_rtt(&view, &deps.node.region),
            now,
        );
        for decision in decided.into_iter().chain(columns) {
            match decision {
                Decision::GaveUp(msg_id) => {
                    tracing::debug!(%msg_id, "nobody left to ask for this message");
                    deps.stats.repair_request(Outcome::GaveUp);
                }
                Decision::GaveUpColumn((_, index)) => {
                    tracing::debug!(index, "nobody left to ask for this column");
                    deps.stats.repair_request(Outcome::GaveUp);
                }
                Decision::AskColumn(request) => match view.get(&request.peer) {
                    Some(peer) => {
                        attempts.spawn(column_attempt(deps.clone(), peer.clone(), request));
                    }
                    None => {
                        deps.stats.repair_request(Outcome::Timeout);
                        scheduler.answered_column(&(request.block_root, request.index));
                    }
                },
                Decision::Ask(request) => match view.get(&request.peer) {
                    Some(peer) => {
                        attempts.spawn(attempt(deps.clone(), peer.clone(), request));
                    }
                    // The candidate came out of this very snapshot, so this is unreachable
                    // today; treating it as an attempt that answered nothing keeps the message
                    // moving to the next candidate if that ever stops being true.
                    None => {
                        deps.stats.repair_request(Outcome::Timeout);
                        scheduler.answered(&request.msg_id);
                    }
                },
            }
        }
    }
}

/// Who a column can be asked for, in the order to ask them (D23): live in-region peers that
/// advertised `REPAIR` (D29), by round trip.
///
/// Nothing announces who holds a column, so unlike the chunk path there is no shorter list than
/// this one. A peer that does not hold it answers `not_found` at once rather than costing an
/// attempt's timeout, which is what makes asking down the list cheap.
fn in_region_by_rtt(view: &LiveView, region: &Region) -> Vec<(Hostname, Duration)> {
    let mut peers: Vec<(Hostname, Duration)> = view
        .in_region(region)
        .into_iter()
        .filter(|(_, peer)| peer.negotiated.allows(features::REPAIR))
        .map(|(hostname, peer)| (hostname.clone(), peer.rtt))
        .collect();
    peers.sort_by_key(|(_, rtt)| *rtt);
    peers
}

/// The round trip to `peer`, or `None` for one that must not be asked: a peer that has left the
/// live set, and a peer that never advertised `REPAIR` (D29).
fn reachable(view: &LiveView, peer: &Hostname) -> Option<Duration> {
    let live = view.get(peer)?;
    live.negotiated.allows(features::REPAIR).then_some(live.rtt)
}

/// One attempt, held to the timeout the request carries: four round trips to this peer, clamped
/// (D24). The timeout covers the whole exchange rather than each read, which is what makes three
/// attempts fit inside the total budget however the peer behaves.
async fn attempt(deps: Deps, peer: LivePeer, request: Request) -> Answered {
    let asked = Frame::RepairReq(RepairReq::Missing {
        msg_id: request.msg_id,
        missing: request.missing.clone(),
    });
    let outcome = tokio::time::timeout(
        request.timeout,
        exchange(&deps, &peer, &request.peer, &asked),
    )
    .await
    .unwrap_or(Outcome::Timeout);
    Answered::Message(request.msg_id, outcome)
}

/// One attempt at a column nobody has sent a chunk of, held to the same timeout (D24, T-087).
///
/// What comes back is the same `CHUNK` frames a chunk repair is answered with, so it goes
/// through the same reassembler and the same completion. The requester has no message id for
/// the column until the chunks name one, and the id it is handed is checked against the payload
/// like every other (T-074). Nothing ties that payload to the `(block_root, index)` asked for,
/// though: a peer can answer with some other message it holds, and what stops that mattering is
/// that the answer still has to be a payload on a topic this beacon node subscribes to, that
/// the node validates it before importing it, and that only the node's own event stream can say
/// the column has arrived (MD-06). An answer this host cannot use leaves the column owed and the
/// next candidate is asked.
async fn column_attempt(deps: Deps, peer: LivePeer, request: ColumnRequest) -> Answered {
    let key = (request.block_root, request.index);
    // A column index is a subnet index and reaches here from a `data_column_sidecar_{i}` topic,
    // which parses into a `u8`, so this cannot narrow. One that did would name a column no peer
    // could be asked for, which is the same to the scheduler as a peer that does not hold it.
    let Ok(index) = u8::try_from(request.index) else {
        return Answered::Column(key, Outcome::NotFound);
    };
    let asked = Frame::RepairReq(RepairReq::Column {
        block_root: request.block_root,
        index,
    });
    let outcome = tokio::time::timeout(
        request.timeout,
        exchange(&deps, &peer, &request.peer, &asked),
    )
    .await
    .unwrap_or(Outcome::Timeout);
    Answered::Column(key, outcome)
}

/// The exchange itself: the request out, the chunks and the trailer back.
///
/// Each chunk goes into the reassembler as it arrives rather than after the trailer, so an
/// answer cut short by the timeout still leaves this host with what did arrive. A chunk off this
/// stream is guarded exactly as one off any other: `rs::supports` refuses a header the codec
/// would panic on, and a header contradicting the chunks this host holds is refused too, because
/// the answer goes through the same `on_chunk` and not around it (T-074).
///
/// A peer that answers with chunks that do not put the message back together is
/// [`Outcome::NotFound`] like one that has nothing: to the requester the two are the same, a
/// candidate that could not finish the job, and the next one is asked.
async fn exchange(deps: &Deps, peer: &LivePeer, name: &Hostname, asked: &Frame) -> Outcome {
    let Ok((mut send, mut recv)) = peer.connection.open_bi().await else {
        return Outcome::Timeout;
    };
    if wire::write_frame(&mut send, asked).await.is_err() {
        return Outcome::Timeout;
    }
    let _ = send.finish();

    let sink = RepairSink::new(deps, name, peer);
    let mut completed = false;
    loop {
        match wire::read_frame(&mut recv, MAX_FRAME_BYTES).await {
            Ok(Read::Frame(Frame::Chunk { chunk, .. })) => completed |= sink.take(chunk),
            Ok(Read::Frame(Frame::RepairResp(RepairResp::NotFound))) => return Outcome::NotFound,
            Ok(Read::Frame(Frame::RepairResp(RepairResp::Chunks(chunks)))) => {
                for chunk in chunks {
                    completed |= sink.take(chunk);
                }
                break;
            }
            // A frame that does not belong on this stream, and a type from a newer release,
            // cost the frame and not the answer (D10).
            Ok(_) => continue,
            Err(error) => {
                tracing::debug!(peer = %name, %error, "a repair answer ended early");
                break;
            }
        }
    }
    match completed {
        true => Outcome::Completed,
        false => Outcome::NotFound,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use bytes::{Bytes, BytesMut};
    use overlay_core::config;
    use overlay_core::msgid;
    use overlay_core::rs::{self, Params};
    use overlay_core::topic::{Class, Topic};
    use overlay_core::wire::{ChunkFlags, MAX_PAYLOAD_BYTES, encode_stream};

    use super::*;
    use crate::manager::PeerInfo;
    use crate::testutil::{
        Builder, DECODED_BLOCK, DECODED_SLOT, NodeKind, SETTLE, TestCluster, eventually,
        subscriptions, topic,
    };
    use overlay_core::topic::table::TopicId;

    /// A gossipsub payload of about `bytes` that snappy cannot shrink much, so the message is
    /// really cut into several chunks.
    fn large_payload(bytes: usize) -> Bytes {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let raw: Vec<u8> = (0..bytes)
            .map(|_| {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                (state >> 33) as u8
            })
            .collect();
        Bytes::from(snap::raw::Encoder::new().compress_vec(&raw).unwrap())
    }

    /// Node 1 with a sidecar and node 0 as a peer of the test's own, which has written every
    /// chunk of a striped block but one and then answers nothing at all.
    async fn one_chunk_short(block: &Topic) -> (TestCluster, PeerInfo) {
        let mut cluster = Builder::new(&[NodeKind::Bare, NodeKind::Manager])
            .start()
            .await;
        cluster.start_sidecar(1, subscriptions(&[block], &[]));
        let peer = cluster
            .dial_announcing(
                0,
                1,
                &cluster.self_hello(0),
                vec![(TopicId::new(1), block.to_string())],
            )
            .await;

        let payload = large_payload(8 * 1024);
        let split = Params::for_len(payload.len(), 2048, 0.10).unwrap();
        let msg_id = msgid::compute(&block.to_string(), &payload, MAX_PAYLOAD_BYTES).id;
        let chunks = rs::encode(&payload, split);
        let mut stream = peer.connection.open_uni().await.unwrap();
        let mut out = BytesMut::new();
        for index in 0..split.k - 1 {
            out.extend_from_slice(&encode_stream(&Frame::Chunk {
                flags: ChunkFlags::NONE,
                chunk: overlay_core::wire::Chunk {
                    msg_id,
                    topic_id: 1,
                    k: split.k,
                    m: split.m,
                    index,
                    total_len: split.total_len,
                    data: chunks[usize::from(index)].clone(),
                },
            }));
        }
        stream.write_all(&out).await.unwrap();
        stream.finish().unwrap();
        (cluster, peer)
    }

    /// D24's attempt timeout doing its job: the only peer that could answer says nothing, so the
    /// attempt ends at four round trips clamped rather than holding the message open, and the
    /// counter says which of the four ways it ended.
    #[tokio::test(flavor = "multi_thread")]
    async fn repair_attempt_times_out_and_is_counted() {
        let block = topic("beacon_block");
        let (cluster, _peer) = one_chunk_short(&block).await;

        eventually("the attempt to time out", || {
            cluster.stats(1).repair_requests(Outcome::Timeout) > 0
        })
        .await;
    }

    /// §5.6 end to end. One host of a region is cut off from the rest of it mid-transfer, so the
    /// chunks the origin striped to it reach nobody else and the tenth of parity cannot cover
    /// what it was carrying. Every host that is left asks a peer for what it is missing and puts
    /// the block together, and its beacon node is handed the block once.
    #[tokio::test(flavor = "multi_thread")]
    async fn end_to_end_missing_chunks_are_repaired_and_message_published_once() {
        let block = topic("beacon_block");
        let hosts = 5;
        let mut cluster = Builder::new(&[NodeKind::Manager; 5])
            .fanout(striping_fanout())
            .start()
            .await;
        // The last host keeps its connection to the origin and loses the rest of the region, so
        // its chunks arrive and are forwarded nowhere.
        cluster.set_roster_for(hosts - 1, &[0, hosts - 1]);
        for node in 1..hosts - 1 {
            cluster.set_roster_for(node, &[0, 1, 2, 3]);
        }
        for node in 0..hosts {
            cluster.start_sidecar(node, subscriptions(&[&block], &[]));
        }
        eventually("the cut region to settle", || {
            (1..hosts - 1).all(|node| cluster.live(node).len() == 3)
                && cluster.live(0).len() == hosts - 1
        })
        .await;

        let payload = large_payload(64 * 1024);
        assert!(cluster.from_bn(0, &block, &payload));

        eventually("the rest of the region to publish the block", || {
            (1..hosts - 1).all(|node| cluster.published(node).len() == 1)
        })
        .await;
        tokio::time::sleep(SETTLE).await;
        for node in 1..hosts - 1 {
            assert_eq!(cluster.published(node).len(), 1, "node {node}");
            assert_eq!(cluster.published(node)[0].payload, payload, "node {node}");
            assert!(
                cluster.stats(node).repair_requests(Outcome::Completed) > 0,
                "node {node} completed without asking anyone"
            );
        }
        assert_eq!(
            Class::of(block.kind(), payload.len()),
            Class::Large,
            "the message has to be one that gets striped at all"
        );
    }

    /// A region of five is well under the shipped threshold, so a test about striping lowers it
    /// the way T-072's do.
    fn striping_fanout() -> config::Fanout {
        let mut fanout = config::Fanout::default();
        fanout.large.stripe_min_recipients = 2;
        fanout
    }

    /// The propagation vector MD-06 named, closed at the responder. Node 1 holds two payloads
    /// that both claim to be a column of one block: one its own beacon node reported verifying,
    /// and one that is nothing but bytes a peer sent it. Node 0 is genuinely short of both and
    /// asks for both. It gets the real one and publishes it, and it never sees the forgery, so
    /// a forged sidecar cannot travel host to host on the back of a repair request.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_repair_answer_cannot_be_a_payload_a_peer_minted() {
        let verified = topic("data_column_sidecar_0");
        let minted = topic("data_column_sidecar_1");
        let root = DECODED_BLOCK.block_root();
        let mut cluster = Builder::new(&[NodeKind::Manager; 2]).start().await;
        for node in 0..2 {
            cluster.start_sidecar(node, subscriptions(&[&verified, &minted], &[]));
        }
        eventually("the pair to connect", || cluster.live(0).len() == 1).await;

        let real = large_payload(8 * 1024);
        let forged = large_payload(8 * 1024);
        for (column, payload) in [(&verified, &real), (&minted, &forged)] {
            let id = msgid::compute(&column.to_string(), payload, MAX_PAYLOAD_BYTES).id;
            cluster.recent(1).insert(
                id,
                column.clone(),
                payload.clone(),
                Some(payload),
                Instant::now(),
            );
        }
        // Node 1's beacon node verified column 0 of this block and has never mentioned column 1.
        cluster.custody(1).on_column(DECODED_SLOT, 0, root);
        // Node 0's beacon node accepted the block and is short of both columns.
        cluster
            .custody(0)
            .on_block(DECODED_SLOT, root, Instant::now());

        eventually("node 0 to publish the column node 1 can vouch for", || {
            !cluster.published(0).is_empty()
        })
        .await;
        tokio::time::sleep(SETTLE).await;
        let published = cluster.published(0);
        assert_eq!(published.len(), 1, "{published:?}");
        assert_eq!(published[0].payload, real);
    }

    /// §6.4 end to end. One host's beacon node has the block and three of its four custody
    /// columns; the fourth exists on one peer only and reached this host by no path at all, so
    /// there is no message id for it anywhere and the chunk path has nothing to work with. Past
    /// the deadline the host names the column by its block root and its index, asks its region
    /// in round-trip order until a peer holds it, and hands the column to its beacon node once.
    #[tokio::test(flavor = "multi_thread")]
    async fn column_repair_end_to_end_publishes_missing_column() {
        let block = topic("beacon_block");
        let columns: Vec<Topic> = (0..4)
            .map(|i| topic(&format!("data_column_sidecar_{i}")))
            .collect();
        let wanted: Vec<&Topic> = std::iter::once(&block).chain(columns.iter()).collect();
        let mut cluster = Builder::new(&[NodeKind::Manager; 4]).start().await;
        for node in 0..4 {
            cluster.start_sidecar(node, subscriptions(&wanted, &[]));
        }
        eventually("the cluster to pair", || {
            (0..4).all(|node| cluster.live(node).len() == 3)
        })
        .await;

        // The column nobody fanned out: node 1's beacon node handed it over, and no other host
        // has ever seen a byte of it.
        let root = DECODED_BLOCK.block_root();
        let missing = large_payload(8 * 1024);
        let missing_id = msgid::compute(&columns[2].to_string(), &missing, MAX_PAYLOAD_BYTES).id;
        cluster.recent(1).insert(
            missing_id,
            columns[2].clone(),
            missing.clone(),
            Some(&missing),
            Instant::now(),
        );
        cluster.custody(1).on_column(DECODED_SLOT, 2, root);
        eventually("node 1 to announce its id for the missing column", || {
            let own = crate::hello::lock(cluster.topics(1));
            own.table
                .get(&columns[2])
                .is_some_and(|id| own.announcer.told(&cluster.hostname(0), id))
        })
        .await;

        // Node 0's beacon node accepted the block and has three of the four columns.
        cluster
            .custody(0)
            .on_block(DECODED_SLOT, root, Instant::now());
        for index in [0, 1, 3] {
            cluster.custody(0).on_column(DECODED_SLOT, index, root);
        }

        eventually("node 0 to publish the column it never saw", || {
            !cluster.published(0).is_empty()
        })
        .await;
        tokio::time::sleep(SETTLE).await;
        let published = cluster.published(0);
        assert_eq!(published.len(), 1, "{published:?}");
        assert_eq!(published[0].payload, missing);
        assert!(
            cluster
                .stats(0)
                .repair_requests(Form::Column, Outcome::Completed)
                > 0
        );
    }
}
