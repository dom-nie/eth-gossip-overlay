//! Telling every live peer what this host's beacon node wants, and keeping what each of them
//! says it wants.
//!
//! One task per live peer owns that peer's control stream, the stream HELLO travelled on
//! (T-025). It is the only reader of it anywhere: a second one would take frames out of the
//! order they were sent in, and the order is the whole reason a `SUBS` may name ids a
//! `TOPIC_ADD` bound moments earlier. The same task writes what this host owes the peer, so a
//! peer that stops reading holds up nothing but its own frames.
//!
//! # What each side does
//!
//! Outbound, on every change the mirror reports (T-014) and once when a peer comes up: intern
//! the local subscription set, send the `TOPIC_ADD`s that peer has not been told, then the
//! bitmap over the advertised set. In that order, because a bit means nothing until the id it
//! stands for has a topic.
//!
//! Inbound: `SUBS` replaces the peer's bitmap and `TOPIC_ADD` extends its table, both under one
//! short lock per frame, so a route plan reading the live view never waits on the network. A
//! `TOPIC_ADD` the peer's table refuses closes the connection with
//! [`CloseCode::ProtocolError`]: an id bound twice means this host's copy of the peer's table
//! and the peer's own have drifted, and nothing decoded against it afterwards can be trusted,
//! while a binding past the HELLO snapshot's cap is a peer growing this host's memory rather
//! than announcing topics (R2.2).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use overlay_core::roster::Hostname;
use overlay_core::subs::{self, Bitmap, PeerState};
use overlay_core::topic::SubscriptionSets;
use overlay_core::topic::table::{OwnTopicTable, TopicId, on_changed};
use overlay_core::wire::{Frame, Read};
use tokio::sync::{mpsc, watch};
use tokio::task::{AbortHandle, JoinHandle, JoinSet};

use crate::hello::{ControlRecv, ControlSend, OwnTopics};
use crate::manager::{CloseCode, ManagerStats, PeerEvent, PeerInfo};

/// The one gauge this path owns, until T-041's registry exists. `()` counts nothing.
pub trait SubsStats: ManagerStats {
    /// `bn_subscriptions`: how many topics this host's beacon node is subscribed to, which is
    /// the size of the advertised set and so the number of bits every `SUBS` this host sends
    /// carries (§12).
    fn bn_subscriptions(&self, topics: usize);
}

impl SubsStats for () {
    fn bn_subscriptions(&self, _: usize) {}
}

/// Starts the exchange, which owns the manager's peer events from here on: it is the consumer
/// [`ConnectionManager::spawn`](crate::manager::ConnectionManager::spawn) sends them to, and the
/// only thing that ever reads a control stream.
pub fn spawn(
    events: mpsc::Receiver<PeerEvent>,
    sets: watch::Receiver<SubscriptionSets>,
    topics: Arc<Mutex<OwnTopics>>,
    stats: Arc<dyn SubsStats>,
) -> JoinHandle<()> {
    tokio::spawn(run(events, sets, topics, stats))
}

/// One task per live peer, started on [`PeerEvent::Up`] and stopped on
/// [`PeerEvent::Down`]. Aborting is enough to stop one: everything it holds belongs to a
/// connection that is already gone.
async fn run(
    mut events: mpsc::Receiver<PeerEvent>,
    mut sets: watch::Receiver<SubscriptionSets>,
    topics: Arc<Mutex<OwnTopics>>,
    stats: Arc<dyn SubsStats>,
) {
    let mut peers: HashMap<Hostname, AbortHandle> = HashMap::new();
    let mut tasks = JoinSet::new();
    stats.bn_subscriptions(sets.borrow_and_update().advertised.len());
    loop {
        tokio::select! {
            event = events.recv() => match event {
                Some(PeerEvent::Up(info)) => {
                    let hostname = info.hostname.clone();
                    let task = tasks.spawn(peer(info, sets.clone(), topics.clone(), stats.clone()));
                    if let Some(replaced) = peers.insert(hostname, task) {
                        replaced.abort();
                    }
                }
                Some(PeerEvent::Down(hostname, _)) => {
                    if let Some(task) = peers.remove(&hostname) {
                        task.abort();
                    }
                }
                None => break,
            },
            changed = sets.changed() => {
                if changed.is_err() {
                    break;
                }
                stats.bn_subscriptions(sets.borrow_and_update().advertised.len());
            }
        }
        while tasks.try_join_next().is_some() {}
    }
    tasks.shutdown().await;
}

/// One peer, for as long as its connection lasts. The two halves of the control stream are two
/// futures of one task rather than two tasks: either direction ending means the connection is
/// over, and a `select!` here says so without a channel between them.
async fn peer(
    info: PeerInfo,
    sets: watch::Receiver<SubscriptionSets>,
    topics: Arc<Mutex<OwnTopics>>,
    stats: Arc<dyn SubsStats>,
) {
    let PeerInfo {
        hostname,
        connection,
        control,
        state,
        ..
    } = info;
    let (send, recv) = control.split();
    tokio::select! {
        () = announce(&hostname, send, sets, &topics) => {}
        () = read(&hostname, recv, &state, &connection, stats.as_ref()) => {}
    }
}

/// Sends what the peer is owed now, and again on every change the mirror reports. It ends when
/// the mirror is gone or the peer stopped taking frames, either of which leaves nothing to say.
async fn announce(
    peer: &Hostname,
    mut send: ControlSend,
    mut sets: watch::Receiver<SubscriptionSets>,
    topics: &Mutex<OwnTopics>,
) {
    let mut interned = crate::hello::lock(topics).interned();
    loop {
        // The borrow ends before the first write: it is a read lock on the mirror's value, and
        // holding one across a network write would stall the mirror behind a slow peer.
        let frames = owed(peer, &sets.borrow_and_update(), topics);
        for frame in frames {
            if let Err(error) = send.write_frame(&frame).await {
                tracing::debug!(%peer, %error, "control stream stopped taking frames");
                return;
            }
        }
        // Two things put a binding in this table: the mirror, and a relay interning a topic it
        // was asked to carry (MD-04). A loop that waited on the mirror alone would leave the
        // second unannounced for as long as the beacon node's subscriptions held still.
        let woken = tokio::select! {
            changed = sets.changed() => changed.is_ok(),
            minted = interned.changed() => minted.is_ok(),
        };
        if !woken {
            return;
        }
    }
}

/// The frames `peer` is owed for the subscription set as it stands: the bindings it has not been
/// told, then the bitmap those ids are read against. Built under one lock and with nothing
/// awaited, so the mirror's next change is never held up by a peer's flow control.
fn owed(peer: &Hostname, sets: &SubscriptionSets, topics: &Mutex<OwnTopics>) -> Vec<Frame> {
    let mut own = crate::hello::lock(topics);
    let OwnTopics {
        table, announcer, ..
    } = &mut *own;
    let mut frames = match on_changed(sets, [peer], table, announcer) {
        Ok(owed) => owed.into_iter().flat_map(|(_, frames)| frames).collect(),
        Err(error) => {
            tracing::error!(%peer, %error, "cannot announce topics this host has no id left for");
            Vec::new()
        }
    };
    frames.push(subs_frame(sets, table));
    frames
}

/// The bitmap frame: `advertised` and never `local`, because the extra column topics T-015
/// subscribes to are ones this beacon node publishes and does not want (D06).
fn subs_frame(sets: &SubscriptionSets, table: &OwnTopicTable) -> Frame {
    Frame::Subs {
        bitmap: subs::advertised(sets, table).encode(),
    }
}

/// Reads the peer's control stream until the connection ends or the peer breaks the protocol.
async fn read(
    peer: &Hostname,
    mut recv: ControlRecv,
    peer_state: &Mutex<PeerState>,
    connection: &quinn::Connection,
    stats: &dyn SubsStats,
) {
    loop {
        match recv.read_frame().await {
            Ok(Read::Frame(Frame::Subs { bitmap })) => {
                state(peer_state).bitmap = Bitmap::decode(&bitmap);
            }
            Ok(Read::Frame(Frame::TopicAdd { id, topic })) => {
                let applied = state(peer_state).table.apply_add(TopicId::new(id), &topic);
                if let Err(error) = applied {
                    tracing::warn!(%peer, %error, "closing a peer over a topic table this host refuses");
                    CloseCode::ProtocolError.close(connection);
                    return;
                }
            }
            // A frame that belongs on another carrier. Nothing here can act on it, and a
            // release that gives it a meaning on this stream will be a later minor (D29).
            Ok(Read::Frame(other)) => {
                tracing::debug!(%peer, frame = ?other.frame_type(), "frame that does not belong on a control stream");
            }
            Ok(Read::Unknown(_)) => stats.unknown_frame_type(peer),
            Err(error) => {
                tracing::debug!(%peer, %error, "control stream ended");
                return;
            }
        }
    }
}

/// A peer's state, recovering the guard from a poisoned lock rather than propagating the panic.
/// Nothing between a lock and its release can panic, so the state is whole; refusing to answer
/// for every other peer because one task died holding this one would take the overlay down for
/// an unrelated reason.
pub(crate) fn state(peer: &Mutex<PeerState>) -> MutexGuard<'_, PeerState> {
    peer.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    use bytes::Bytes;
    use overlay_core::subs::Bitmap;
    use overlay_core::topic::table::TopicId;
    use overlay_core::topic::{SubscriptionSets, Topic};
    use overlay_core::wire::{Frame, MAX_TOPIC_SNAPSHOT_ENTRIES, Read};
    use tokio::sync::{mpsc, watch};

    use crate::hello;
    use crate::hello::OwnTopics;
    use crate::manager::{CloseCode, PeerInfo, RECONNECT_MIN};
    use crate::testlog::LOG;
    use crate::testutil::{Builder, CountingStats, NodeKind, TestCluster, WAIT, eventually};
    use crate::tls::Role;

    fn topic(name: &str) -> Topic {
        Topic::parse(&format!("/eth2/6a95a1a9/{name}/ssz_snappy")).unwrap()
    }

    /// What the mirror reports when the beacon node is subscribed to `advertised` and this
    /// sidecar has no column topics of its own beyond them (T-014).
    fn advertising(advertised: &[&Topic]) -> SubscriptionSets {
        let set = advertised.iter().map(|topic| (*topic).clone()).collect();
        SubscriptionSets {
            advertised: set,
            local: advertised.iter().map(|topic| (*topic).clone()).collect(),
        }
    }

    fn bits(ids: &[u16]) -> Bytes {
        let mut bitmap = Bitmap::new();
        for id in ids {
            bitmap.set(TopicId::new(*id));
        }
        bitmap.encode()
    }

    /// A manager with the exchange running on it, and one peer per entry in `snapshots` that
    /// the test drives by hand. The manager is the highest hostname in the cluster, so it dials
    /// nobody: every connection is one the test made, and what comes back is the peer's own end
    /// of the control stream, which is what a sibling would be reading and writing.
    async fn exchange(
        snapshots: &[&[(TopicId, &str)]],
        sets: SubscriptionSets,
    ) -> (
        TestCluster,
        watch::Sender<SubscriptionSets>,
        Vec<PeerInfo>,
        usize,
    ) {
        let mut kinds = vec![NodeKind::Bare; snapshots.len()];
        kinds.push(NodeKind::Manager);
        let manager = snapshots.len();
        let mut cluster = Builder::new(&kinds).start().await;

        let (sender, receiver) = watch::channel(sets);
        super::spawn(
            cluster.take_events(manager),
            receiver,
            cluster.topics(manager).clone(),
            Arc::new(()),
        );

        let mut peers = Vec::new();
        for (index, snapshot) in snapshots.iter().enumerate() {
            let connection = cluster.dial(index, manager).await.unwrap();
            let announced = snapshot
                .iter()
                .map(|(id, topic)| (*id, (*topic).to_owned()))
                .collect();
            peers.push(
                hello::perform(
                    connection,
                    Role::Dial,
                    &cluster.self_hello(index),
                    &cluster.hostname(manager),
                    announced,
                    WAIT,
                    &(),
                )
                .await
                .unwrap(),
            );
        }
        (cluster, sender, peers, manager)
    }

    /// The next frame this host sent the peer, failing the test rather than hanging when none
    /// comes.
    async fn next_frame(peer: &mut PeerInfo) -> Frame {
        match tokio::time::timeout(WAIT, peer.control.read_frame()).await {
            Ok(Ok(Read::Frame(frame))) => frame,
            other => panic!("no frame on the control stream: {other:?}"),
        }
    }

    /// A peer that has just finished HELLO knows nothing about what this host wants, and
    /// nothing else will happen until the beacon node's subscriptions next change. Without this
    /// the pair is connected and routes nothing to each other, possibly for a whole epoch.
    #[tokio::test(flavor = "multi_thread")]
    async fn subs_is_sent_to_a_newly_connected_peer_after_hello() {
        let block = topic("beacon_block");
        let (_cluster, _sets, mut peers, _) = exchange(&[&[]], advertising(&[&block])).await;

        assert_eq!(
            next_frame(&mut peers[0]).await,
            Frame::TopicAdd {
                id: 0,
                topic: block.to_string()
            }
        );
        assert_eq!(
            next_frame(&mut peers[0]).await,
            Frame::Subs { bitmap: bits(&[0]) }
        );
    }

    /// MD-04: a relay interns a topic it is asked to carry, and the only thing that can put the
    /// binding on the wire is the intern itself. This host's own subscriptions never change
    /// here, so a loop that woke on the mirror alone would leave the id unannounced for as long
    /// as the beacon node's set held still, which on a settled fleet is for ever.
    #[tokio::test(flavor = "multi_thread")]
    async fn topic_interned_outside_the_mirror_is_announced_to_an_established_peer() {
        let block = topic("beacon_block");
        let carried = topic("beacon_attestation_9");
        let (cluster, _sets, mut peers, manager) = exchange(&[&[]], advertising(&[&block])).await;
        assert_eq!(
            next_frame(&mut peers[0]).await,
            Frame::TopicAdd {
                id: 0,
                topic: block.to_string()
            }
        );
        assert_eq!(
            next_frame(&mut peers[0]).await,
            Frame::Subs { bitmap: bits(&[0]) }
        );

        let id = hello::lock(cluster.topics(manager))
            .intern(&carried)
            .unwrap();

        assert_eq!(
            next_frame(&mut peers[0]).await,
            Frame::TopicAdd {
                id: id.get(),
                topic: carried.to_string()
            }
        );
    }

    /// Every live peer hears about a change, because the bitmap is the only thing that makes a
    /// sibling send anything: one that missed it would keep routing on the set before it.
    #[tokio::test(flavor = "multi_thread")]
    async fn subs_frame_is_sent_to_every_live_peer_on_change() {
        let block = topic("beacon_block");
        let (_cluster, sets, mut peers, _) =
            exchange(&[&[], &[]], SubscriptionSets::default()).await;
        for peer in &mut peers {
            assert_eq!(
                next_frame(peer).await,
                Frame::Subs {
                    bitmap: Bytes::new()
                }
            );
        }

        sets.send_replace(advertising(&[&block]));

        for peer in &mut peers {
            assert_eq!(
                next_frame(peer).await,
                Frame::TopicAdd {
                    id: 0,
                    topic: block.to_string()
                }
            );
            assert_eq!(next_frame(peer).await, Frame::Subs { bitmap: bits(&[0]) });
        }
    }

    /// The control stream is ordered and this host announces an id before it sets the bit, so
    /// the normal path never produces it. A peer is free to, though, and a bitmap read against
    /// a table that has not caught up must be kept rather than dropped: throwing it away would
    /// leave the peer looking unsubscribed until its beacon node next changed anything.
    #[tokio::test(flavor = "multi_thread")]
    async fn subs_arriving_before_topic_add_for_its_ids_is_still_applied() {
        let block = topic("beacon_block");
        let (cluster, _sets, mut peers, manager) =
            exchange(&[&[]], SubscriptionSets::default()).await;
        let host = cluster.hostname(0);

        peers[0]
            .control
            .write_frame(&Frame::Subs { bitmap: bits(&[7]) })
            .await
            .unwrap();
        peers[0]
            .control
            .write_frame(&Frame::TopicAdd {
                id: 7,
                topic: block.to_string(),
            })
            .await
            .unwrap();

        eventually("the peer to become a subscriber", || {
            cluster.live(manager).subscribed(&host, &block)
        })
        .await;
    }

    /// The beacon node going away takes its host out of every sibling's routing (§9). The
    /// mirror reports an empty set, this host advertises an empty bitmap, and the sibling stops
    /// counting it as a subscriber. The overlay connection is untouched: the host is still there
    /// to forward for everyone else.
    #[tokio::test(flavor = "multi_thread")]
    async fn empty_set_produces_empty_bitmap_and_peer_stops_being_a_subscriber() {
        let block = topic("beacon_block");
        let mut cluster = TestCluster::start(2).await;
        let (subscribed, watching) = watch::channel(advertising(&[&block]));
        let (_idle, idle_watching) = watch::channel(SubscriptionSets::default());
        super::spawn(
            cluster.take_events(0),
            watching,
            cluster.topics(0).clone(),
            Arc::new(()),
        );
        super::spawn(
            cluster.take_events(1),
            idle_watching,
            cluster.topics(1).clone(),
            Arc::new(()),
        );
        let host = cluster.hostname(0);
        eventually("the subscribed host to be one", || {
            cluster.live(1).subscribers(&block) == vec![&host]
        })
        .await;

        subscribed.send_replace(SubscriptionSets::default());

        eventually("the subscriber to stop being one", || {
            cluster.live(1).subscribers(&block).is_empty()
        })
        .await;
        assert!(cluster.live(1).get(&host).is_some());
    }

    /// T-025 left an admitted dial proven, because HELLO is a round trip that an acceptor about
    /// to refuse a key never answers. A peer that pairs and is then closed for a protocol error
    /// is what that leaves: the fault is in what the peer says rather than in the path, so a
    /// redial at the 500 ms floor would pair again, read the same frame again and close again,
    /// for as long as both hosts are up.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_peer_whose_topic_add_conflicts_is_not_redialled_at_the_floor() {
        let mark = LOG.len();
        let mut cluster = Builder::new(&[NodeKind::Manager, NodeKind::ConflictingTopicAdd])
            .start()
            .await;
        let (_sets, watching) = watch::channel(SubscriptionSets::default());
        super::spawn(
            cluster.take_events(0),
            watching,
            cluster.topics(0).clone(),
            Arc::new(()),
        );
        let peer = cluster.hostname(1);

        eventually("the backoff to grow past its floor", || {
            cluster
                .retry_at(0, &peer)
                .is_some_and(|at| at > Instant::now() + RECONNECT_MIN)
        })
        .await;

        let closes = LOG
            .since(mark)
            .lines()
            .filter(|line| {
                line.contains(peer.0.as_str()) && line.contains("topic table this host refuses")
            })
            .count();
        assert!(closes > 1, "the peer was closed {closes} times");
    }

    /// HELLO refuses a snapshot past `MAX_TOPIC_SNAPSHOT_ENTRIES`, and the `TOPIC_ADD`s that
    /// come after it are held to the same line: a peer streaming bindings past it is growing
    /// this host's copy of its table rather than announcing topics, and is closed the way one
    /// whose HELLO tried the same is (R2.2).
    #[tokio::test(flavor = "multi_thread")]
    async fn topic_add_past_the_snapshot_cap_closes_the_connection() {
        let (cluster, _sets, mut peers, manager) =
            exchange(&[&[]], SubscriptionSets::default()).await;
        let host = cluster.hostname(0);
        let name = |id: usize| format!("/eth2/{id:08x}/beacon_block/ssz_snappy");
        let binding = |id: usize| Frame::TopicAdd {
            id: id as u16,
            topic: name(id),
        };

        for id in 0..MAX_TOPIC_SNAPSHOT_ENTRIES {
            peers[0].control.write_frame(&binding(id)).await.unwrap();
        }
        // The stream is ordered, so the last id turning up in the live view says every
        // binding before it was taken without complaint.
        let last = MAX_TOPIC_SNAPSHOT_ENTRIES - 1;
        peers[0]
            .control
            .write_frame(&Frame::Subs {
                bitmap: bits(&[last as u16]),
            })
            .await
            .unwrap();
        let last_topic = Topic::parse(&name(last)).unwrap();
        eventually("every binding up to the cap to be applied", || {
            cluster.live(manager).subscribed(&host, &last_topic)
        })
        .await;
        assert_eq!(peers[0].connection.close_reason(), None);

        peers[0]
            .control
            .write_frame(&binding(MAX_TOPIC_SNAPSHOT_ENTRIES))
            .await
            .unwrap();

        eventually("the connection to close", || {
            peers[0].connection.close_reason().is_some()
        })
        .await;
        match peers[0].connection.close_reason() {
            Some(quinn::ConnectionError::ApplicationClosed(closed)) => {
                assert_eq!(closed.error_code, CloseCode::ProtocolError.code());
            }
            other => panic!("closed for {other:?}"),
        }
    }

    /// The gauge an operator watches to see that the beacon node link is alive at all: the size
    /// of the advertised set, which is the number of bits every `SUBS` carries. It follows the
    /// mirror and not the peers, so a host with nothing connected still reports it.
    #[tokio::test(flavor = "multi_thread")]
    async fn bn_subscriptions_gauge_follows_the_advertised_set() {
        let (_events, incoming) = mpsc::channel(1);
        let (sets, watching) = watch::channel(advertising(&[&topic("beacon_block")]));
        let stats = Arc::new(CountingStats::default());
        super::spawn(
            incoming,
            watching,
            Arc::new(Mutex::new(OwnTopics::default())),
            stats.clone(),
        );
        eventually("the gauge to report the first set", || {
            stats.bn_subscriptions() == Some(1)
        })
        .await;

        sets.send_replace(advertising(&[
            &topic("beacon_block"),
            &topic("beacon_attestation_3"),
        ]));

        eventually("the gauge to follow the change", || {
            stats.bn_subscriptions() == Some(2)
        })
        .await;
    }
}
