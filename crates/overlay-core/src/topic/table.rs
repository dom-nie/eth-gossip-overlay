//! Topic strings to the 16-bit ids that carry them on the wire.

use std::collections::HashMap;

use crate::topic::Topic;

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
}
