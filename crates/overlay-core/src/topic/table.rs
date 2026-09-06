//! Topic strings to the 16-bit ids that carry them on the wire.

use std::collections::HashMap;
use std::fmt;

use crate::topic::{Topic, TopicError};

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

    /// The id for `topic`, and whether this call is what created it.
    pub fn intern(&mut self, topic: &Topic) -> Result<(TopicId, bool), TableFull> {
        if let Some(&id) = self.ids.get(topic) {
            return Ok((id, false));
        }
        let id = TopicId(self.topics.len() as u16);
        self.topics.push(topic.to_string());
        self.ids.insert(topic.clone(), id);
        Ok((id, true))
    }

    /// Every binding this host has made, as HELLO carries it. A peer that applies this knows
    /// every id this host can put on a frame at the moment the HELLO went out.
    pub fn snapshot(&self) -> Vec<(TopicId, String)> {
        self.entries_from(0)
            .map(|(id, topic)| (id, topic.to_owned()))
            .collect()
    }

    /// The bindings from `start` on, in id order. Ids are handed out in order and never
    /// reused, so an index into `topics` is also a count of what a peer has been told.
    fn entries_from(&self, start: usize) -> impl Iterator<Item = (TopicId, &str)> {
        self.topics
            .iter()
            .enumerate()
            .skip(start)
            .map(|(index, topic)| (TopicId(index as u16), topic.as_str()))
    }
}

/// The ids one peer has assigned, and the only table that peer's frames are decoded with.
#[derive(Clone, Debug, Default)]
pub struct PeerTopicTable {
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

    /// Takes the whole table a peer announced in its HELLO.
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

/// The table has no id left to assign.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("topic table is full")]
pub struct TableFull;

#[cfg(test)]
mod tests {
    use super::*;

    use crate::topic::Topic;

    const DIGEST: [u8; 4] = [0x6a, 0x95, 0xa1, 0xa9];

    fn column(index: u8) -> Topic {
        Topic::data_column(DIGEST, index)
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
        let mut peer = PeerTopicTable::new();

        peer.apply_snapshot(own.snapshot()).unwrap();

        assert_eq!(own.snapshot().len(), 4);
        for (id, text) in own.snapshot() {
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
}
