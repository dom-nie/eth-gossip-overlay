//! Telling every live peer what this host's beacon node wants, and keeping what each of them
//! says it wants.

use std::sync::{Mutex, MutexGuard};

use overlay_core::subs::PeerState;

/// A peer's state, recovering the guard from a poisoned lock rather than propagating the panic.
/// Nothing between a lock and its release can panic, so the state is whole; refusing to answer
/// for every other peer because one task died holding this one would take the overlay down for
/// an unrelated reason.
pub(crate) fn state(peer: &Mutex<PeerState>) -> MutexGuard<'_, PeerState> {
    peer.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bytes::Bytes;
    use overlay_core::subs::Bitmap;
    use overlay_core::topic::table::TopicId;
    use overlay_core::topic::{SubscriptionSets, Topic};
    use overlay_core::wire::{Frame, Read};
    use tokio::sync::watch;

    use super::*;
    use crate::hello;
    use crate::manager::PeerInfo;
    use crate::testutil::{Builder, NodeKind, TestCluster, WAIT};
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
}
