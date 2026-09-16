//! Topic strings to the 16-bit ids that stand in for them on the wire. A topic string runs
//! forty to sixty bytes and a small-class message is about 240, so repeating the string on
//! every batch entry and every chunk header would spend a fifth of the small class on saying
//! the same thing over and over; two bytes spend nothing. Fork digests keep the set of topics
//! open-ended, so the table cannot be compiled in either.
//!
//! # Each sender owns its ids
//!
//! Nothing is negotiated. A host hands out ids from its own [`OwnTopicTable`], puts that table
//! in its HELLO and a `TOPIC_ADD` for every binding it makes later, and encodes every frame it
//! sends with those ids. A receiver keeps one [`PeerTopicTable`] per peer and decodes a frame
//! with the table belonging to whoever sent it.
//!
//! Suppose `alpha` interned `beacon_block` first and `beacon_attestation_3` second, while
//! `beta` happened to do it the other way round. `alpha` calls the block topic 0 and `beta`
//! calls it 1, and neither is wrong: topic id 0 on a chunk from `alpha` is read against
//! `alpha`'s table and is a block, while the same 0 from `beta` is read against `beta`'s table
//! and is an attestation. The two can never disagree, because an id is never read outside the
//! table that minted it.
//!
//! # Announced before anything can travel on them
//!
//! [`on_changed`] interns the whole local subscription set ([`SubscriptionSets::local`],
//! `local_subscriptions()` in D12) on every `Changed` from the mirror (T-014), not the
//! advertised set. The difference is the extra data column topics T-015 subscribes to: a
//! beacon node publishes every column of its own proposal but subscribes only to the ones it
//! custodies, so a sibling needs the id of a column topic that the SUBS bitmap never mentions,
//! the bitmap carrying `advertised` alone (D06). Interning eagerly is what puts those ids in
//! front of the chunks that use them. Nothing is ever added inline on first use: the send path
//! asks [`OwnTopicTable::get`] and never `intern`, so a frame can only leave with an id its
//! peers already hold.
//!
//! # When an id arrives too late anyway
//!
//! A frame whose id [`PeerTopicTable::resolve`] does not know is dropped and counted as
//! `unknown_topic_id_total{peer}`. One race outlives the eager announcement: at sidecar start
//! the control stream and the data streams are read by different tasks, so a batch can reach
//! the decoder ahead of the `TOPIC_ADD` that explains it. That window is small class only and
//! public gossip is the backup, which is why D12 took the metric over inline adds. If the
//! canary ever sees the counter above zero, the recorded fallback is to park an unknown-id
//! frame for 100 ms and look again, not to let a sender mint ids mid-flight.

use std::collections::HashMap;
use std::fmt;

use crate::roster::Hostname;
use crate::topic::{SubscriptionSets, Topic, TopicError};
use crate::wire::{Frame, MAX_TOPIC_SNAPSHOT_ENTRIES};

/// How many topics one table holds, so ids run from 0 to 65,534 and `u16::MAX` is never
/// assigned. A fleet across a fork transition interns a few hundred, so the ceiling is there to
/// bound what a peer can make this host allocate, not because anyone reaches it.
pub const CAPACITY: usize = u16::MAX as usize;

/// A topic's id in one table. Two bytes instead of the fifty a topic string takes, which is what
/// keeps a batch entry or a chunk header small (§5.4). An id means nothing on its own: it is
/// only ever read against the table of the peer that assigned it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TopicId(u16);

impl TopicId {
    /// The id a peer put on the wire.
    pub fn new(raw: u16) -> Self {
        Self(raw)
    }

    /// The two bytes that go on the wire.
    pub fn get(self) -> u16 {
        self.0
    }
}

impl fmt::Display for TopicId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The ids this host assigns, and the only table its own frames are encoded with.
#[derive(Clone, Debug, Default)]
pub struct OwnTopicTable {
    /// Id to topic string, already in the form the wire wants, so announcing a topic never
    /// formats one.
    topics: Vec<String>,
    /// The reverse direction, keyed by the parsed topic rather than its string, so the send
    /// path looks an id up without formatting one either.
    ids: HashMap<Topic, TopicId>,
}

impl OwnTopicTable {
    /// An empty table, which is what a sidecar starts with before the mirror reports anything.
    pub fn new() -> Self {
        Self::default()
    }

    /// The id for `topic`, and whether this call is what minted it. Interning is idempotent,
    /// so the mirror hands the whole subscription set over on every change and only the
    /// additions come back new. It fails only once every id is spent.
    pub fn intern(&mut self, topic: &Topic) -> Result<(TopicId, bool), TableFull> {
        if let Some(&id) = self.ids.get(topic) {
            return Ok((id, false));
        }
        if self.topics.len() >= CAPACITY {
            return Err(TableFull);
        }
        let id = TopicId(self.topics.len() as u16);
        self.topics.push(topic.to_string());
        self.ids.insert(topic.clone(), id);
        Ok((id, true))
    }

    /// The id already bound to `topic`, or `None`. The send path uses this rather than
    /// [`Self::intern`]: an id nobody has been told about yet is useless on a frame, so a miss
    /// here means the message waits for the announcement instead of inventing an id (D12).
    pub fn get(&self, topic: &Topic) -> Option<TopicId> {
        self.ids.get(topic).copied()
    }

    /// The bindings from `start` on, in id order. Ids are handed out in order and never
    /// reused, so an index into `topics` is also a count of what a peer has been told, and
    /// [`CAPACITY`] is what keeps it inside a `u16`.
    fn entries_from(&self, start: usize) -> impl Iterator<Item = (TopicId, &str)> {
        self.topics
            .iter()
            .enumerate()
            .skip(start)
            .map(|(index, topic)| (TopicId(index as u16), topic.as_str()))
    }
}

/// The table has no id left to assign.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("topic table is full at {CAPACITY} entries")]
pub struct TableFull;

/// The ids one peer has assigned, and the only table that peer's frames are decoded with.
#[derive(Clone, Debug, Default)]
pub struct PeerTopicTable {
    /// The parse is stored beside the id, so a receiver reads the class and kind off a frame
    /// without parsing the topic string again.
    by_id: HashMap<TopicId, Topic>,
    /// The reverse direction, which the router needs to ask whether a peer has an id for a
    /// topic at all before anything is sent on it.
    by_topic: HashMap<Topic, TopicId>,
}

impl PeerTopicTable {
    /// An empty table, which is what a connection holds until the peer's HELLO arrives.
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes the whole table a peer announced in its HELLO, entry by entry and under the same
    /// rules as [`Self::apply_add`].
    pub fn apply_snapshot<S: AsRef<str>>(
        &mut self,
        entries: impl IntoIterator<Item = (TopicId, S)>,
    ) -> Result<(), PeerTableError> {
        for (id, topic) in entries {
            self.apply_add(id, topic.as_ref())?;
        }
        Ok(())
    }

    /// Takes one binding a peer announced in a `TOPIC_ADD`.
    pub fn apply_add(&mut self, id: TopicId, topic: &str) -> Result<(), PeerTableError> {
        let parsed = Topic::parse(topic).map_err(|err| PeerTableError::Unparsable(id, err))?;
        if let Some(held) = self.by_id.get(&id) {
            return if *held == parsed {
                Ok(())
            } else {
                Err(PeerTableError::Conflict(id))
            };
        }
        self.by_id.insert(id, parsed.clone());
        self.by_topic.insert(parsed, id);
        Ok(())
    }

    /// The topic `id` stands for. `None` means the peer has not announced it, and the frame
    /// that carried it is dropped and counted as `unknown_topic_id_total`.
    pub fn resolve(&self, id: TopicId) -> Option<&Topic> {
        self.by_id.get(&id)
    }

    /// The id this peer uses for `topic`, if it has one.
    pub fn id_of(&self, topic: &Topic) -> Option<TopicId> {
        self.by_topic.get(topic).copied()
    }
}

/// Why a peer's topic announcement is refused. Both are the peer breaking the protocol rather
/// than a condition to recover from, so the connection closes; T-025 owns the close code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PeerTableError {
    /// The peer bound an id it had already bound to another topic. Ids are the sender's own
    /// and it never has to reuse one, so a redefinition means its table and this one have
    /// drifted and nothing decoded against them can be trusted.
    #[error("topic id {0} is already bound to another topic")]
    Conflict(TopicId),
    /// The peer sent a string that is not a topic. `Topic::parse` is strict about shape, fork
    /// digest, encoding, name and index, so a beacon node's own topic always passes and
    /// anything that fails came from a peer that is not speaking this protocol.
    #[error("topic id {0} names a string that is not a topic: {1}")]
    Unparsable(TopicId, TopicError),
}

/// What each peer has already been told, and the only place a `TOPIC_ADD` is built.
#[derive(Clone, Debug, Default)]
pub struct Announcer {
    /// How many of the own table's ids each peer has been told. Ids are handed out in order and
    /// never withdrawn, so one count per peer says which bindings are still owed.
    told: HashMap<Hostname, usize>,
}

impl Announcer {
    /// An announcer that has told nobody anything.
    pub fn new() -> Self {
        Self::default()
    }

    /// The whole table, as a peer's HELLO carries it. T-025 sends what this returns and nothing
    /// else, and records it with [`Self::hello_sent`] once it has gone.
    pub fn snapshot(&self, table: &OwnTopicTable) -> Vec<(TopicId, String)> {
        table
            .entries_from(0)
            .map(|(id, topic)| (id, topic.to_owned()))
            .collect()
    }

    /// Records that `peer` has been told the first `sent` bindings, where `sent` is the length
    /// of a snapshot that really reached it.
    ///
    /// Counting what was sent rather than reading the table again is what keeps the record
    /// honest in both directions. The mirror interns from another task, so a count taken from
    /// the table would include whatever landed after the snapshot was built and those ids would
    /// never be announced to that peer at all. And a HELLO that failed records nothing, so a
    /// peer whose second connection was refused (D15) is still owed everything its surviving
    /// connection has not been sent. Either mistake ends the same way: frames carrying ids the
    /// peer was never told, dropped as `unknown_topic_id_total`.
    pub fn hello_sent(&mut self, peer: &Hostname, sent: usize) {
        self.told.insert(peer.clone(), sent);
    }

    /// Whether `peer` has already been told what `id` stands for. A relay asks before it names
    /// an id on a frame: [`OwnTopicTable::intern`] binds one the instant it is called, and an
    /// entry sent under a binding the peer has not had yet is one it drops and counts as
    /// `unknown_topic_id_total`, which D12 nominated as the alarm for a different fault (MD-04).
    pub fn told(&self, peer: &Hostname, id: TopicId) -> bool {
        self.told
            .get(peer)
            .is_some_and(|told| usize::from(id.get()) < *told)
    }

    /// The bindings `peer` has not been told, which this call records as told. T-027 puts them
    /// on that peer's control stream.
    pub fn announce(&mut self, peer: &Hostname, table: &OwnTopicTable) -> Vec<Frame> {
        let told = self.told.entry(peer.clone()).or_default();
        let frames: Vec<Frame> = table
            .entries_from(*told)
            .map(|(id, topic)| Frame::TopicAdd {
                id: id.get(),
                topic: topic.to_owned(),
            })
            .collect();
        *told += frames.len();
        frames
    }
}

/// Answers the mirror's `Changed` (T-014): interns everything the sidecar subscribes to and
/// returns what each live peer is owed, leaving out the peers that are owed nothing. T-027
/// writes the frames to the control streams.
///
/// It reads `local` and not `advertised` because the extra data column topics T-015 adds are
/// the ones an own proposal's chunks go out on, so their ids have to reach peers even though
/// the SUBS bitmap leaves those topics out (D06, D12).
pub fn on_changed<'a>(
    sets: &SubscriptionSets,
    peers: impl IntoIterator<Item = &'a Hostname>,
    table: &mut OwnTopicTable,
    announcer: &mut Announcer,
) -> Result<Vec<(&'a Hostname, Vec<Frame>)>, TableFull> {
    for topic in &sets.local {
        table.intern(topic)?;
    }
    Ok(peers
        .into_iter()
        .map(|peer| (peer, announcer.announce(peer, table)))
        .filter(|(_, owed)| !owed.is_empty())
        .collect())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    const DIGEST: [u8; 4] = [0x6a, 0x95, 0xa1, 0xa9];

    fn column(index: u8) -> Topic {
        Topic::data_column(DIGEST, index)
    }

    fn host(name: &str) -> Hostname {
        Hostname(name.to_owned())
    }

    fn topic_add(id: u16, index: u8) -> Frame {
        Frame::TopicAdd {
            id,
            topic: column(index).to_string(),
        }
    }

    #[test]
    fn intern_assigns_sequential_ids_starting_at_zero() {
        let mut table = OwnTopicTable::new();

        let ids: Vec<TopicId> = (0..3)
            .map(|index| table.intern(&column(index)).unwrap().0)
            .collect();

        assert_eq!(ids, [TopicId::new(0), TopicId::new(1), TopicId::new(2)]);
    }

    #[test]
    fn intern_same_topic_twice_returns_same_id_and_is_new_false() {
        let mut table = OwnTopicTable::new();

        let first = table.intern(&column(7)).unwrap();
        let second = table.intern(&column(7)).unwrap();

        assert_eq!(first, (TopicId::new(0), true));
        assert_eq!(second, (TopicId::new(0), false));
    }

    #[test]
    fn snapshot_round_trips_into_peer_table() {
        let mut own = OwnTopicTable::new();
        for index in 0..4 {
            own.intern(&column(index)).unwrap();
        }
        let mut announcer = Announcer::new();
        let mut peer = PeerTopicTable::new();

        let snapshot = announcer.snapshot(&own);
        announcer.hello_sent(&host("a"), snapshot.len());
        peer.apply_snapshot(snapshot.clone()).unwrap();

        assert_eq!(snapshot.len(), 4);
        for (id, text) in snapshot {
            let topic = Topic::parse(&text).unwrap();

            assert_eq!(peer.resolve(id), Some(&topic));
            assert_eq!(peer.id_of(&topic), Some(id));
        }
    }

    #[test]
    fn apply_add_with_conflicting_string_is_conflict_error() {
        let mut peer = PeerTopicTable::new();
        peer.apply_add(TopicId::new(3), &column(0).to_string())
            .unwrap();

        let refused = peer.apply_add(TopicId::new(3), &column(1).to_string());

        assert_eq!(refused, Err(PeerTableError::Conflict(TopicId::new(3))));
        assert_eq!(peer.resolve(TopicId::new(3)), Some(&column(0)));
    }

    /// The cap HELLO's snapshot already has, applied to the adds that follow it. A binding the
    /// table already holds costs nothing and is still taken at the cap, so a peer resending its
    /// table is not mistaken for one growing it.
    #[test]
    fn apply_add_past_the_snapshot_cap_is_full_error() {
        let mut peer = PeerTopicTable::new();
        let name = |id: usize| format!("/eth2/{id:08x}/beacon_block/ssz_snappy");
        for id in 0..MAX_TOPIC_SNAPSHOT_ENTRIES {
            peer.apply_add(TopicId::new(id as u16), &name(id)).unwrap();
        }
        let one_more = TopicId::new(MAX_TOPIC_SNAPSHOT_ENTRIES as u16);

        let refused = peer.apply_add(one_more, &name(MAX_TOPIC_SNAPSHOT_ENTRIES));

        assert_eq!(refused, Err(PeerTableError::Full(one_more)));
        assert_eq!(peer.resolve(one_more), None);
        assert_eq!(peer.apply_add(TopicId::new(0), &name(0)), Ok(()));
        assert_eq!(
            refused.unwrap_err().to_string(),
            format!(
                "topic id {MAX_TOPIC_SNAPSHOT_ENTRIES} is past the \
                 {MAX_TOPIC_SNAPSHOT_ENTRIES} topics a peer may bind"
            )
        );
    }

    #[test]
    fn apply_add_identical_to_existing_is_ok_idempotent() {
        let mut peer = PeerTopicTable::new();
        let text = column(5).to_string();
        peer.apply_add(TopicId::new(1), &text).unwrap();

        let again = peer.apply_add(TopicId::new(1), &text);

        assert_eq!(again, Ok(()));
        assert_eq!(peer.resolve(TopicId::new(1)), Some(&column(5)));
        assert_eq!(peer.id_of(&column(5)), Some(TopicId::new(1)));
    }

    #[test]
    fn apply_add_with_a_string_that_is_not_a_topic_is_unparsable_error() {
        let mut peer = PeerTopicTable::new();

        let refused = peer.apply_add(TopicId::new(0), "/eth2/6a95a1a9/beacon_block/ssz");

        assert_eq!(
            refused,
            Err(PeerTableError::Unparsable(
                TopicId::new(0),
                TopicError::Encoding
            ))
        );
        assert_eq!(peer.resolve(TopicId::new(0)), None);
    }

    #[test]
    fn resolve_unknown_id_is_none() {
        let mut peer = PeerTopicTable::new();
        peer.apply_add(TopicId::new(0), &column(0).to_string())
            .unwrap();

        assert_eq!(peer.resolve(TopicId::new(1)), None);
        assert_eq!(peer.id_of(&column(9)), None);
    }

    #[test]
    fn errors_name_the_id_or_the_limit_they_are_about() {
        let mut peer = PeerTopicTable::new();
        peer.apply_add(TopicId::new(9), &column(0).to_string())
            .unwrap();

        let conflict = peer
            .apply_add(TopicId::new(9), &column(1).to_string())
            .unwrap_err();
        let unparsable = peer.apply_add(TopicId::new(4), "beacon_block").unwrap_err();

        assert_eq!(
            conflict.to_string(),
            "topic id 9 is already bound to another topic"
        );
        assert_eq!(
            unparsable.to_string(),
            "topic id 4 names a string that is not a topic: expected /eth2/<fork_digest>/<name>/ssz_snappy"
        );
        assert_eq!(
            TableFull.to_string(),
            "topic table is full at 65535 entries"
        );
    }

    /// 65,535 written out rather than [`CAPACITY`]: a test that names the constant follows it
    /// wherever it goes and so cannot see the ceiling move.
    #[test]
    fn table_full_at_65535_returns_error() {
        let mut own = OwnTopicTable::new();
        let every_column_of_every_digest = (0..=u8::MAX).flat_map(|digest| {
            (0..=u8::MAX).map(move |index| Topic::data_column([digest, 0, 0, 0], index))
        });
        let mut interned = 0;

        for topic in every_column_of_every_digest {
            if own.intern(&topic).is_err() {
                break;
            }
            interned += 1;
        }

        assert_eq!(interned, 65_535);
        assert_eq!(own.entries_from(0).count(), 65_535);
    }

    #[test]
    fn announcer_yields_each_new_id_exactly_once_per_peer() {
        let mut own = OwnTopicTable::new();
        let mut announcer = Announcer::new();
        own.intern(&column(0)).unwrap();
        own.intern(&column(1)).unwrap();

        let first = announcer.announce(&host("a"), &own);

        assert_eq!(first, [topic_add(0, 0), topic_add(1, 1)]);
        assert!(announcer.announce(&host("a"), &own).is_empty());
        assert_eq!(
            announcer.announce(&host("b"), &own),
            [topic_add(0, 0), topic_add(1, 1)]
        );

        own.intern(&column(2)).unwrap();

        assert_eq!(announcer.announce(&host("a"), &own), [topic_add(2, 2)]);
    }

    #[test]
    fn announcer_for_new_peer_after_hello_yields_nothing() {
        let mut own = OwnTopicTable::new();
        let mut announcer = Announcer::new();
        own.intern(&column(0)).unwrap();
        own.intern(&column(1)).unwrap();

        let hello = announcer.snapshot(&own);
        announcer.hello_sent(&host("c"), hello.len());

        assert_eq!(hello.len(), 2);
        assert!(announcer.announce(&host("c"), &own).is_empty());

        own.intern(&column(2)).unwrap();

        assert_eq!(announcer.announce(&host("c"), &own), [topic_add(2, 2)]);
    }

    /// The mirror interns from its own task, so a topic can appear between the snapshot and the
    /// record. What is recorded is the length of what was sent, so the newcomer is still owed
    /// rather than counted as already announced.
    #[test]
    fn a_topic_interned_after_the_hello_snapshot_is_still_announced() {
        let mut own = OwnTopicTable::new();
        let mut announcer = Announcer::new();
        own.intern(&column(0)).unwrap();

        let hello = announcer.snapshot(&own);
        own.intern(&column(1)).unwrap();
        announcer.hello_sent(&host("d"), hello.len());

        assert_eq!(hello, [(TopicId::new(0), column(0).to_string())]);
        assert_eq!(announcer.announce(&host("d"), &own), [topic_add(1, 1)]);
    }

    /// A snapshot that never reached its peer records nothing. A HELLO can fail after the
    /// snapshot is built, and the peer it was for keeps whatever connection it had; recording at
    /// the read would leave those ids announced to nobody.
    #[test]
    fn a_snapshot_that_is_never_sent_leaves_the_peer_owed_everything() {
        let mut own = OwnTopicTable::new();
        let mut announcer = Announcer::new();
        own.intern(&column(0)).unwrap();
        own.intern(&column(1)).unwrap();

        let hello = announcer.snapshot(&own);

        assert_eq!(hello.len(), 2);
        assert_eq!(
            announcer.announce(&host("e"), &own),
            [topic_add(0, 0), topic_add(1, 1)]
        );
    }

    #[test]
    fn changed_local_set_produces_topic_add_for_new_topics_only_including_extra_columns() {
        let block = Topic::parse("/eth2/6a95a1a9/beacon_block/ssz_snappy").unwrap();
        let extra = column(4);
        let sets = SubscriptionSets {
            advertised: BTreeSet::from([block.clone()]),
            local: BTreeSet::from([block.clone(), extra.clone()]),
        };
        assert!(!sets.advertised.contains(&extra));
        let peers = [host("a"), host("b")];
        let mut own = OwnTopicTable::new();
        let mut announcer = Announcer::new();

        let owed = on_changed(&sets, peers.iter(), &mut own, &mut announcer).unwrap();

        let expected = vec![
            Frame::TopicAdd {
                id: 0,
                topic: block.to_string(),
            },
            topic_add(1, 4),
        ];
        assert_eq!(owed, [(&peers[0], expected.clone()), (&peers[1], expected)]);
        assert!(
            on_changed(&sets, peers.iter(), &mut own, &mut announcer)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn get_on_unknown_topic_returns_none_and_does_not_grow_the_table() {
        let mut own = OwnTopicTable::new();
        own.intern(&column(0)).unwrap();

        assert_eq!(own.get(&column(0)), Some(TopicId::new(0)));
        assert_eq!(own.get(&column(1)), None);
        assert_eq!(own.entries_from(0).count(), 1);
    }
}
