//! Which peers a message goes to, and how.
//!
//! Every sender works that out from its own live view, because no node is special and there is
//! nothing to ask (§3). The answer is an enum and not a list of hosts so that the send path
//! (T-032) matches on one thing however the class ends up being carried.
//!
//! The default plan is the whole message to every live peer whose beacon node is subscribed to
//! the topic (§5.4), in hostname order and this host aside, or [`RoutePlan::Nothing`] when that
//! leaves nobody. A small-class message crossing to a region large enough to be worth the hop
//! gets [`RoutePlan::SmallRelayed`] instead: the region's own subscribers reached through a few
//! of its hosts rather than one WAN copy each (D20, D36). A message the caller has split into
//! chunks gets [`RoutePlan::Large`]: one stripe or one whole delivery per region, each built
//! from this host's own view of that region (§5.4, D18).
//!
//! `class`, `chunked` and `cfg` are what tell those apart. A message nobody has chunked goes out
//! whole however large it is, and so does a small one under `small.cross_region: direct`.

use std::collections::{BTreeMap, BTreeSet};

use overlay_core::config::{Fanout, SmallCrossRegion};
use overlay_core::msgid::MessageId;
use overlay_core::roster::{Hostname, Region, SelfIdentity};
use overlay_core::rs::Params;
use overlay_core::topic::{Class, Topic};
use overlay_core::{relay, stripe};

use crate::manager::{LivePeer, LiveView};
use crate::subs;

/// What a sender does with one message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoutePlan {
    /// The whole message to each of these hosts, in hostname order.
    Direct(Vec<Hostname>),
    /// A small-class batch to `direct` as usual, and to `relays` with the `RELAY` bit set so
    /// each of them fans it out inside its own region (D11).
    SmallRelayed {
        /// The subscribers this host reaches itself: its own region, and every remote region
        /// too small for the relay hop to pay for itself. In hostname order.
        direct: Vec<Hostname>,
        /// The hosts that carry the batch for the rest of their region, in region and then
        /// hostname order. None of them need be subscribed to the topic (D20).
        relays: Vec<Hostname>,
    },
    /// One plan per region that holds a live subscriber, in region order (§5.4).
    Large(Vec<RegionPlan>),
    /// No live peer wants it, so it goes nowhere.
    Nothing,
}

/// A large message the caller has already cut into chunks (T-071), which is what asking for a
/// stripe means. The pair travels together because neither half answers on its own: the id is
/// what two origins rotate the same way, and the split is what says how many chunks there are
/// to place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chunked {
    /// The message id, whose first eight bytes rotate the stripe (D18).
    pub id: MessageId,
    /// How the message was split; `k + m` is how many hosts the stripe places.
    pub split: Params,
}

/// How one region takes a large message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegionPlan {
    /// The whole message to each of these hosts, in hostname order. The region holds fewer
    /// subscribers than `stripe_min_recipients`, and a stripe over a handful of hosts costs
    /// more in chunk headers and streams than the copies it saves (§5.4).
    Whole {
        /// Who takes the message whole.
        targets: Vec<Hostname>,
    },
    /// Chunk `i` to `targets_per_chunk[i]`, the assignment D18 fixes. Each host forwards what
    /// it was sent to the rest of its own region, so the stripe is one hop of two and the
    /// second never leaves `region` (§5.4, T-073).
    Stripe {
        /// The region this stripe covers, as its hosts declared it (D15).
        region: Region,
        /// Where each chunk goes, `k + m` long.
        targets_per_chunk: Vec<Hostname>,
    },
}

/// The plan for a message on `topic`, from the live set as it stood when `view` was taken. Pure:
/// it reads its arguments and nothing else, so the hard part of routing is a function a test can
/// ask a question of.
///
/// `chunked` is what turns a large message into a stripe: it carries the id the assignment is
/// rotated by and the split that says how many chunks there are (T-071). A message routed
/// without it goes out whole however large it is, which is every small-class message and every
/// message from a sender that cannot chunk one yet.
///
/// The recipients come off the view here rather than from [`LiveView::subscribers`], which
/// hands back borrowed names: cloning those into the plan would cost a second `Vec` on the path
/// every message takes.
pub fn route(
    topic: &Topic,
    class: Class,
    chunked: Option<Chunked>,
    view: &LiveView,
    self_id: &SelfIdentity,
    cfg: &Fanout,
) -> RoutePlan {
    let subscribed = |peer: &LivePeer| subs::state(&peer.state).subscribed(topic);
    let others = || {
        view.iter()
            .filter(|(hostname, _)| **hostname != self_id.hostname)
    };
    if class == Class::Large
        && let Some(chunked) = chunked
    {
        return striped(
            chunked,
            others(),
            &subscribed,
            cfg.large.stripe_min_recipients,
        );
    }
    let relaying: BTreeSet<&Region> =
        match class == Class::Small && cfg.small.cross_region == SmallCrossRegion::Relays {
            true => relaying_regions(view, self_id, &subscribed, cfg.small.relay_min_remote_hosts),
            false => BTreeSet::new(),
        };
    let direct: Vec<Hostname> = others()
        .filter(|(_, peer)| subscribed(peer) && !relaying.contains(&peer.region))
        .map(|(hostname, _)| hostname.clone())
        .collect();
    let relays: Vec<Hostname> = relaying
        .into_iter()
        .flat_map(|region| {
            relay::select(
                &self_id.hostname,
                &pool(view, self_id, region),
                cfg.small.relays_per_remote_region,
            )
        })
        .collect();
    match (direct.is_empty(), relays.is_empty()) {
        (true, true) => RoutePlan::Nothing,
        (_, true) => RoutePlan::Direct(direct),
        _ => RoutePlan::SmallRelayed { direct, relays },
    }
}

/// One plan per region that holds a live subscriber, in region order: this host's own region
/// without this host, and every other region striped into directly, because a stripe crosses
/// the WAN once already and a relay would only add a hop to it (§5.4).
///
/// A region takes the message whole below `stripe_min_recipients` and as a stripe at or above
/// it. The stripe runs over the region's subscribers alone (D18): a chunk sent to a host whose
/// beacon node discards the topic is a chunk that bought nothing, which is the opposite of the
/// rule [`pool`] applies to relays, and deliberately so.
fn striped<'a>(
    chunked: Chunked,
    peers: impl Iterator<Item = (&'a Hostname, &'a LivePeer)>,
    subscribed: &impl Fn(&LivePeer) -> bool,
    stripe_min_recipients: usize,
) -> RoutePlan {
    let mut per_region: BTreeMap<&Region, Vec<Hostname>> = BTreeMap::new();
    for (hostname, peer) in peers.filter(|(_, peer)| subscribed(peer)) {
        per_region
            .entry(&peer.region)
            .or_default()
            .push(hostname.clone());
    }
    if per_region.is_empty() {
        return RoutePlan::Nothing;
    }
    let chunks = usize::from(chunked.split.k) + usize::from(chunked.split.m);
    RoutePlan::Large(
        per_region
            .into_iter()
            .map(
                |(region, hosts)| match hosts.len() >= stripe_min_recipients {
                    true => RegionPlan::Stripe {
                        region: region.clone(),
                        targets_per_chunk: stripe::assign(&chunked.id, &hosts, chunks),
                    },
                    false => RegionPlan::Whole { targets: hosts },
                },
            )
            .collect(),
    )
}

/// The remote regions whose subscribers are reached through relays: the ones holding at least
/// `relay_min_remote_hosts` of them. Below that the WAN copies saved do not pay for the extra
/// in-region hop, so the region is sent to directly (D36).
fn relaying_regions<'a>(
    view: &'a LiveView,
    self_id: &SelfIdentity,
    subscribed: &impl Fn(&LivePeer) -> bool,
    relay_min_remote_hosts: usize,
) -> BTreeSet<&'a Region> {
    let mut per_region: BTreeMap<&Region, usize> = BTreeMap::new();
    for (_, peer) in view
        .iter()
        .filter(|(hostname, _)| **hostname != self_id.hostname)
        .filter(|(_, peer)| peer.region != self_id.region && subscribed(peer))
    {
        *per_region.entry(&peer.region).or_default() += 1;
    }
    per_region
        .into_iter()
        .filter(|(_, subscribers)| *subscribers >= relay_min_remote_hosts)
        .map(|(region, _)| region)
        .collect()
}

/// The hosts of `region` a relay may be chosen from: every live one that has told this host
/// what it wants, in hostname order. Subscription to the topic is not part of it, because a
/// relay fans the batch out for its region and need not want anything in it itself (D20).
fn pool(view: &LiveView, self_id: &SelfIdentity, region: &Region) -> Vec<Hostname> {
    view.in_region(region)
        .into_iter()
        .filter(|(hostname, _)| **hostname != self_id.hostname)
        .filter(|(_, peer)| !subs::state(&peer.state).bitmap.is_empty())
        .map(|(hostname, _)| hostname.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use overlay_core::config::{Fanout, LargeFanout, SmallCrossRegion, SmallFanout};
    use overlay_core::msgid::MessageId;
    use overlay_core::roster::{Hostname, Region, SelfIdentity};
    use overlay_core::rs::Params;
    use overlay_core::subs::PeerState;
    use overlay_core::topic::{Class, Topic};

    use super::{Chunked, RegionPlan, RoutePlan, route};
    use crate::manager::LiveView;
    use crate::testutil::{Builder, NodeKind, REGION, WAIT, peer_state, view};

    fn host(name: &str) -> Hostname {
        Hostname(name.to_owned())
    }

    fn topic(name: &str) -> Topic {
        Topic::parse(&format!("/eth2/6a95a1a9/{name}/ssz_snappy")).unwrap()
    }

    /// A fanout that relays the small class into a remote region of `min_remote_hosts` or more,
    /// through `per_region` of its hosts.
    fn relaying(min_remote_hosts: usize, per_region: usize) -> Fanout {
        Fanout {
            small: SmallFanout {
                relay_min_remote_hosts: min_remote_hosts,
                relays_per_remote_region: per_region,
                ..SmallFanout::default()
            },
            ..Fanout::default()
        }
    }

    /// A fanout that stripes a region holding `min_recipients` or more subscribers.
    fn striping(min_recipients: usize) -> Fanout {
        Fanout {
            large: LargeFanout {
                stripe_min_recipients: min_recipients,
                ..LargeFanout::default()
            },
            ..Fanout::default()
        }
    }

    /// A message split into `k + m` chunks, whose id rotates a stripe by `rotation`: its first
    /// eight bytes little-endian are the number the assignment takes the remainder of (D18).
    /// The two chunk counts are all a route plan reads; what is in a chunk is T-073's.
    fn chunked(rotation: u64, k: u16, m: u16) -> Chunked {
        let mut id = [0u8; 20];
        id[..8].copy_from_slice(&rotation.to_le_bytes());
        Chunked {
            id: MessageId(id),
            split: Params {
                k,
                m,
                chunk_bytes: 2048,
                total_len: u32::from(k) * 2048,
            },
        }
    }

    /// A live view with each peer in the region named beside it, which is the region it declared
    /// in its HELLO and the one its second hop would fan out in (D15).
    fn view_in(connection: &quinn::Connection, peers: Vec<(&str, &str, PeerState)>) -> LiveView {
        let regions: Vec<(Hostname, Region)> = peers
            .iter()
            .map(|(name, region, _)| (host(name), Region((*region).to_owned())))
            .collect();
        let mut live = view(
            connection,
            peers
                .into_iter()
                .map(|(name, _, state)| (host(name), state))
                .collect(),
        );
        for (hostname, region) in regions {
            live.0
                .get_mut(&hostname)
                .expect("the peer this view was built from")
                .region = region;
        }
        live
    }

    /// The host doing the routing, which is in no view unless a test puts it there.
    fn me() -> SelfIdentity {
        SelfIdentity {
            hostname: host("bn-me"),
            region: Region(REGION.to_owned()),
            site: None,
        }
    }

    /// The one connection every peer in a hand-built view shares. A [`LivePeer`] holds one and a
    /// routing question never reads it, so the cluster that opened it is gone by the time the
    /// view exists.
    ///
    /// [`LivePeer`]: crate::manager::LivePeer
    async fn connection() -> quinn::Connection {
        let cluster = Builder::new(&[NodeKind::Bare, NodeKind::Bare])
            .start()
            .await;
        tokio::time::timeout(WAIT, cluster.connected_pair(0, 1))
            .await
            .unwrap()
            .0
    }

    /// The set a message goes to: every live peer whose beacon node wants the topic (§5.4). The
    /// sender works it out from its own view, with nothing coordinating the answer (§3).
    #[tokio::test(flavor = "multi_thread")]
    async fn routes_to_every_live_peer_subscribed_to_the_topic() {
        let connection = connection().await;
        let block = topic("beacon_block");
        let (first, second) = (host("bn-a"), host("bn-b"));
        let live = view(
            &connection,
            vec![
                (first.clone(), peer_state(&[(1, &block)], &[1])),
                (second.clone(), peer_state(&[(4, &block)], &[4])),
            ],
        );

        let plan = route(&block, Class::Large, None, &live, &me(), &Fanout::default());

        assert_eq!(plan, RoutePlan::Direct(vec![first, second]));
    }

    /// A peer whose beacon node wants other topics but not this one is not a recipient: the copy
    /// would cost the WAN a message the far end drops (§5.4).
    #[tokio::test(flavor = "multi_thread")]
    async fn excludes_peers_not_subscribed() {
        let connection = connection().await;
        let (block, attestation) = (topic("beacon_block"), topic("beacon_attestation_3"));
        let (wants_it, wants_other) = (host("bn-a"), host("bn-b"));
        let live = view(
            &connection,
            vec![
                (wants_it.clone(), peer_state(&[(1, &block)], &[1])),
                (
                    wants_other.clone(),
                    peer_state(&[(1, &attestation), (2, &block)], &[1]),
                ),
            ],
        );

        let plan = route(&block, Class::Large, None, &live, &me(), &Fanout::default());

        assert_eq!(plan, RoutePlan::Direct(vec![wants_it]));
    }

    /// The sender is never a recipient of its own message, whatever the view says. A host has
    /// nothing to connect to itself with, so its own name in the live set means a roster that
    /// lists it twice, and sending there would hand the message back to the beacon node it came
    /// from.
    #[tokio::test(flavor = "multi_thread")]
    async fn excludes_self_even_if_self_appears_in_view() {
        let connection = connection().await;
        let block = topic("beacon_block");
        let peer = host("bn-a");
        let live = view(
            &connection,
            vec![
                (peer.clone(), peer_state(&[(1, &block)], &[1])),
                (me().hostname, peer_state(&[(1, &block)], &[1])),
            ],
        );

        let plan = route(&block, Class::Large, None, &live, &me(), &Fanout::default());

        assert_eq!(plan, RoutePlan::Direct(vec![peer]));
    }

    /// Nobody to send to is its own plan and not an empty list, so the send path has one thing
    /// to match on rather than a `Direct` it has to check the length of. A live peer that wants
    /// another topic and a fleet where every sibling is down both end here (§9).
    #[tokio::test(flavor = "multi_thread")]
    async fn empty_recipient_set_is_nothing() {
        let connection = connection().await;
        let (block, attestation) = (topic("beacon_block"), topic("beacon_attestation_3"));
        let live = view(
            &connection,
            vec![(host("bn-a"), peer_state(&[(1, &attestation)], &[1]))],
        );

        let plan = route(&block, Class::Large, None, &live, &me(), &Fanout::default());

        assert_eq!(plan, RoutePlan::Nothing);
        assert_eq!(
            route(
                &block,
                Class::Large,
                None,
                &LiveView::default(),
                &me(),
                &Fanout::default()
            ),
            RoutePlan::Nothing
        );
    }

    /// The order is part of the answer, not an accident of how the peers connected. T-072 turns
    /// this list into a stripe by rotating it, so two origins with the same live view have to
    /// produce the same list for their chunks to deduplicate on arrival (§5.4).
    #[tokio::test(flavor = "multi_thread")]
    async fn targets_are_sorted_by_hostname() {
        let connection = connection().await;
        let block = topic("beacon_block");
        let names = ["bn-c", "bn-a", "bn-b"];
        let live = view(
            &connection,
            names
                .iter()
                .map(|name| (host(name), peer_state(&[(1, &block)], &[1])))
                .collect(),
        );

        let plan = route(&block, Class::Large, None, &live, &me(), &Fanout::default());

        assert_eq!(
            plan,
            RoutePlan::Direct(vec![host("bn-a"), host("bn-b"), host("bn-c")])
        );
    }

    /// A peer that has paired and announced its topic ids but has not sent a `SUBS` yet wants
    /// nothing until it says so. Its bitmap is empty, and an empty bitmap is the same answer as
    /// a beacon node that is down (§9), which is the safe way round: the alternative sends it
    /// every topic it named.
    #[tokio::test(flavor = "multi_thread")]
    async fn peer_without_any_subs_frame_yet_is_excluded() {
        let connection = connection().await;
        let block = topic("beacon_block");
        let (subscriber, silent) = (host("bn-a"), host("bn-b"));
        let live = view(
            &connection,
            vec![
                (subscriber.clone(), peer_state(&[(1, &block)], &[1])),
                (silent, peer_state(&[(1, &block)], &[])),
            ],
        );

        let plan = route(&block, Class::Large, None, &live, &me(), &Fanout::default());

        assert_eq!(plan, RoutePlan::Direct(vec![subscriber]));
    }

    /// §5.4: a small-class batch crosses the WAN to a few hosts of the remote region, which fan
    /// it out inside it, while the origin's own region is reached directly as ever. The three
    /// hosts of `us` are exactly `relay_min_remote_hosts`, so the region is big enough for the
    /// relay hop to be worth its copies (D36), and the two that carry it are the window
    /// `fnv1a64("bn-me") % 3` opens at (D20).
    #[tokio::test(flavor = "multi_thread")]
    async fn route_small_class_yields_in_region_direct_and_remote_relays() {
        let connection = connection().await;
        let subnet = topic("beacon_attestation_7");
        let live = view_in(
            &connection,
            vec![
                ("bn-eu-a", "eu", peer_state(&[(1, &subnet)], &[1])),
                ("bn-us-01", "us", peer_state(&[(1, &subnet)], &[1])),
                ("bn-us-02", "us", peer_state(&[(1, &subnet)], &[1])),
                ("bn-us-03", "us", peer_state(&[(1, &subnet)], &[1])),
            ],
        );

        let plan = route(&subnet, Class::Small, None, &live, &me(), &relaying(3, 2));

        assert_eq!(
            plan,
            RoutePlan::SmallRelayed {
                direct: vec![host("bn-eu-a")],
                relays: vec![host("bn-us-02"), host("bn-us-03")],
            }
        );
    }

    /// A remote region with only a handful of subscribers is sent to directly: three WAN copies
    /// saved would not pay for the millisecond the relay hop costs every attestation in them
    /// (D36). The plan is the plain `Direct` a one-region fleet gets.
    #[tokio::test(flavor = "multi_thread")]
    async fn route_remote_region_below_relay_min_remote_hosts_is_direct() {
        let connection = connection().await;
        let subnet = topic("beacon_attestation_7");
        let live = view_in(
            &connection,
            vec![
                ("bn-eu-a", "eu", peer_state(&[(1, &subnet)], &[1])),
                ("bn-us-01", "us", peer_state(&[(1, &subnet)], &[1])),
                ("bn-us-02", "us", peer_state(&[(1, &subnet)], &[1])),
            ],
        );

        let plan = route(&subnet, Class::Small, None, &live, &me(), &relaying(3, 2));

        assert_eq!(
            plan,
            RoutePlan::Direct(vec![host("bn-eu-a"), host("bn-us-01"), host("bn-us-02")])
        );
    }

    /// `small.cross_region: direct` is the switch that turns relaying off for an operator whose
    /// WAN egress turns out not to matter (§5.4). Every subscriber gets its own copy however
    /// large its region is.
    #[tokio::test(flavor = "multi_thread")]
    async fn route_in_direct_mode_yields_all_remote_subscribers() {
        let connection = connection().await;
        let subnet = topic("beacon_attestation_7");
        let live = view_in(
            &connection,
            vec![
                ("bn-us-01", "us", peer_state(&[(1, &subnet)], &[1])),
                ("bn-us-02", "us", peer_state(&[(1, &subnet)], &[1])),
                ("bn-us-03", "us", peer_state(&[(1, &subnet)], &[1])),
            ],
        );
        let direct = Fanout {
            small: SmallFanout {
                cross_region: SmallCrossRegion::Direct,
                ..relaying(3, 2).small
            },
            ..Fanout::default()
        };

        let plan = route(&subnet, Class::Small, None, &live, &me(), &direct);

        assert_eq!(
            plan,
            RoutePlan::Direct(vec![host("bn-us-01"), host("bn-us-02"), host("bn-us-03")])
        );
    }

    /// §5.4: a region with a handful of subscribers takes the message whole. A stripe over so
    /// few hosts costs a chunk header and a stream apiece and saves the origin nothing, and it
    /// is what keeps a tiny fleet or a rare topic on the path v1 shipped.
    #[tokio::test(flavor = "multi_thread")]
    async fn route_large_below_min_recipients_is_whole() {
        let connection = connection().await;
        let block = topic("beacon_block");
        let live = view_in(
            &connection,
            vec![
                ("bn-eu-a", "eu", peer_state(&[(1, &block)], &[1])),
                ("bn-eu-b", "eu", peer_state(&[(1, &block)], &[1])),
            ],
        );

        let plan = route(
            &block,
            Class::Large,
            Some(chunked(0, 2, 1)),
            &live,
            &me(),
            &striping(3),
        );

        assert_eq!(
            plan,
            RoutePlan::Large(vec![RegionPlan::Whole {
                targets: vec![host("bn-eu-a"), host("bn-eu-b")],
            }])
        );
    }

    /// §5.4 step 2: a region big enough to be worth it takes one chunk per host, round robin in
    /// hostname order from where the message id points. Two origins with the same live view
    /// therefore send the same chunk to the same host, and the second copy deduplicates on
    /// arrival instead of costing the region a second delivery.
    #[tokio::test(flavor = "multi_thread")]
    async fn route_large_at_or_above_min_recipients_is_stripe() {
        let connection = connection().await;
        let block = topic("beacon_block");
        let live = view_in(
            &connection,
            vec![
                ("bn-eu-a", "eu", peer_state(&[(1, &block)], &[1])),
                ("bn-eu-b", "eu", peer_state(&[(1, &block)], &[1])),
                ("bn-eu-c", "eu", peer_state(&[(1, &block)], &[1])),
            ],
        );

        let plan = route(
            &block,
            Class::Large,
            Some(chunked(1, 2, 1)),
            &live,
            &me(),
            &striping(3),
        );

        assert_eq!(
            plan,
            RoutePlan::Large(vec![RegionPlan::Stripe {
                region: Region("eu".to_owned()),
                targets_per_chunk: vec![host("bn-eu-b"), host("bn-eu-c"), host("bn-eu-a")],
            }])
        );
    }

    /// The origin already holds the message it is striping, so it is not one of the hosts its
    /// own region's stripe runs over. Were it counted, the rotation would land elsewhere and
    /// one chunk would be assigned to nobody.
    #[tokio::test(flavor = "multi_thread")]
    async fn route_large_excludes_self_from_own_region_stripe() {
        let connection = connection().await;
        let block = topic("beacon_block");
        let live = view_in(
            &connection,
            vec![
                ("bn-eu-a", "eu", peer_state(&[(1, &block)], &[1])),
                ("bn-eu-b", "eu", peer_state(&[(1, &block)], &[1])),
                ("bn-eu-c", "eu", peer_state(&[(1, &block)], &[1])),
                (&me().hostname.0, "eu", peer_state(&[(1, &block)], &[1])),
            ],
        );

        let plan = route(
            &block,
            Class::Large,
            Some(chunked(3, 2, 1)),
            &live,
            &me(),
            &striping(3),
        );

        assert_eq!(
            plan,
            RoutePlan::Large(vec![RegionPlan::Stripe {
                region: Region("eu".to_owned()),
                targets_per_chunk: vec![host("bn-eu-a"), host("bn-eu-b"), host("bn-eu-c")],
            }])
        );
    }

    /// §5.4: one stripe per region, the origin's own included, each built from this host's own
    /// view of that region. A cross-region stripe goes straight into the other region, so the
    /// plan names its hosts and not a relay of theirs, and a region nobody in wants the topic
    /// gets no plan at all.
    #[tokio::test(flavor = "multi_thread")]
    async fn route_large_produces_one_plan_per_region_with_live_subscribers_including_own() {
        let connection = connection().await;
        let (block, attestation) = (topic("beacon_block"), topic("beacon_attestation_3"));
        let live = view_in(
            &connection,
            vec![
                ("bn-ap-01", "ap", peer_state(&[(1, &attestation)], &[1])),
                ("bn-eu-a", "eu", peer_state(&[(1, &block)], &[1])),
                ("bn-us-01", "us", peer_state(&[(1, &block)], &[1])),
                ("bn-us-02", "us", peer_state(&[(1, &block)], &[1])),
            ],
        );

        let plan = route(
            &block,
            Class::Large,
            Some(chunked(0, 2, 1)),
            &live,
            &me(),
            &Fanout::default(),
        );

        assert_eq!(
            plan,
            RoutePlan::Large(vec![
                RegionPlan::Whole {
                    targets: vec![host("bn-eu-a")],
                },
                RegionPlan::Whole {
                    targets: vec![host("bn-us-01"), host("bn-us-02")],
                },
            ])
        );
    }

    /// A fleet in one region is one stripe, which is the shape an operator running a single
    /// datacenter gets and the shape §5.4's two regions are each half of.
    #[tokio::test(flavor = "multi_thread")]
    async fn route_large_single_region_fleet_produces_one_plan() {
        let connection = connection().await;
        let block = topic("beacon_block");
        let live = view_in(
            &connection,
            vec![
                ("bn-eu-a", "eu", peer_state(&[(1, &block)], &[1])),
                ("bn-eu-b", "eu", peer_state(&[(1, &block)], &[1])),
            ],
        );

        let plan = route(
            &block,
            Class::Large,
            Some(chunked(0, 1, 1)),
            &live,
            &me(),
            &striping(2),
        );

        assert_eq!(
            plan,
            RoutePlan::Large(vec![RegionPlan::Stripe {
                region: Region("eu".to_owned()),
                targets_per_chunk: vec![host("bn-eu-a"), host("bn-eu-b")],
            }])
        );
    }

    /// D18: the stripe runs over the region's subscribers, not over everything live in it. A
    /// column chunk sent to a host whose beacon node discards the column is a chunk that bought
    /// nothing, and it would leave a hole in the region's copy of the message. This is the one
    /// rule striping and relay selection disagree on, and it is why the pool a relay is taken
    /// from is built separately.
    #[tokio::test(flavor = "multi_thread")]
    async fn unsubscribed_hosts_are_not_in_the_stripe() {
        let connection = connection().await;
        let (block, attestation) = (topic("beacon_block"), topic("beacon_attestation_3"));
        let live = view_in(
            &connection,
            vec![
                ("bn-eu-a", "eu", peer_state(&[(1, &block)], &[1])),
                ("bn-eu-b", "eu", peer_state(&[(1, &attestation)], &[1])),
                ("bn-eu-c", "eu", peer_state(&[(1, &block)], &[1])),
                ("bn-eu-d", "eu", peer_state(&[(1, &block)], &[1])),
            ],
        );

        let plan = route(
            &block,
            Class::Large,
            Some(chunked(0, 2, 1)),
            &live,
            &me(),
            &striping(3),
        );

        assert_eq!(
            plan,
            RoutePlan::Large(vec![RegionPlan::Stripe {
                region: Region("eu".to_owned()),
                targets_per_chunk: vec![host("bn-eu-a"), host("bn-eu-c"), host("bn-eu-d")],
            }])
        );
    }

    /// v1 sends both classes the same way, so the class changes nothing about the plan. T-072
    /// rewrites this test: a large message becomes a stripe over the same peers, and the two
    /// answers stop matching.
    #[tokio::test(flavor = "multi_thread")]
    async fn class_does_not_change_v1_plan() {
        let connection = connection().await;
        let block = topic("beacon_block");
        let peer = host("bn-a");
        let live = view(&connection, vec![(peer, peer_state(&[(1, &block)], &[1]))]);

        let small = route(&block, Class::Small, None, &live, &me(), &Fanout::default());
        let large = route(&block, Class::Large, None, &live, &me(), &Fanout::default());

        assert_eq!(small, RoutePlan::Direct(vec![host("bn-a")]));
        assert_eq!(small, large);
    }
}
