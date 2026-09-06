//! The subscription bitmap a sidecar advertises, and what it keeps of every peer's.
//!
//! A message goes only to peers whose beacon node is subscribed to its topic (§5.4), so every
//! host has to know what every other host wants. Saying it as topic strings would cost a few
//! kilobytes per peer per change; saying it as one bit per topic costs the few dozen bytes a
//! `SUBS` frame carries.
//!
//! # Whose ids the bits are
//!
//! The bitmap is indexed by the **sender's** own topic ids (D13), the same ids its frames carry,
//! because those are the only ids it can assign. Asking whether peer `P` wants topic `T` is
//! therefore two steps: look `T` up in `P`'s table to get `P`'s id for it, then test that bit in
//! `P`'s bitmap. `T` almost certainly has a different id here, and that difference never has to
//! be reconciled because neither id is ever read against the other's table.
//!
//! # What goes in it
//!
//! Only [`SubscriptionSets::advertised`], never `local`. The extra data column topics T-015
//! subscribes to are interned and announced so that an own proposal's chunks have ids (D12), but
//! the beacon node never asked for those columns and a sibling that sent them would be sending
//! traffic nobody wants (D06).

use bytes::Bytes;

use crate::topic::table::{OwnTopicTable, PeerTopicTable, TopicId};
use crate::topic::{SubscriptionSets, Topic};

/// One bit per topic id, dense from id 0. A fleet across a fork transition interns a few
/// hundred topics, so the whole thing is a handful of words and a `Vec<u64>` beats anything
/// cleverer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Bitmap(Vec<u64>);

impl Bitmap {
    /// A bitmap with nothing set, which is what a sidecar advertises while its beacon node is
    /// down (§9).
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the bit for `id`, growing to reach it.
    pub fn set(&mut self, id: TopicId) {
        let (word, bit) = position(id);
        if self.0.len() <= word {
            self.0.resize(word + 1, 0);
        }
        self.0[word] |= 1 << bit;
    }

    /// Whether the bit for `id` is set. An id past the end is not set, which is what a peer
    /// whose set is smaller than this host's looks like.
    pub fn test(&self, id: TopicId) -> bool {
        let (word, bit) = position(id);
        self.0.get(word).is_some_and(|word| word & (1 << bit) != 0)
    }

    /// Every id whose bit is set, in ascending order.
    pub fn iter_set(&self) -> impl Iterator<Item = TopicId> + '_ {
        self.0.iter().enumerate().flat_map(|(word, bits)| {
            (0..u64::BITS as usize)
                .filter(move |bit| bits & (1 << bit) != 0)
                // An id is a `u16`, so a bit past that range belongs to no topic any table can
                // name and there is nothing to report for it.
                .filter_map(move |bit| u16::try_from(word * u64::BITS as usize + bit).ok())
                .map(TopicId::new)
        })
    }

    /// The bytes a `SUBS` frame carries: the words little-endian, with the trailing zero bytes
    /// left off. The frame's own length prefix is what says how many came, so a host that
    /// subscribes to eight topics sends one byte and not the width of its widest id.
    pub fn encode(&self) -> Bytes {
        let mut out: Vec<u8> = self.0.iter().flat_map(|word| word.to_le_bytes()).collect();
        let used = out.iter().rposition(|byte| *byte != 0);
        out.truncate(used.map_or(0, |last| last + 1));
        Bytes::from(out)
    }

    /// The bitmap a peer sent. Any length decodes: the bytes are its bits and a partial trailing
    /// word is zero-filled, so this host never has to agree with the peer about how wide a
    /// bitmap is.
    pub fn decode(bytes: &[u8]) -> Self {
        Self(
            bytes
                .chunks(size_of::<u64>())
                .map(|chunk| {
                    let mut word = [0u8; size_of::<u64>()];
                    word[..chunk.len()].copy_from_slice(chunk);
                    u64::from_le_bytes(word)
                })
                .collect(),
        )
    }
}

/// Everything one peer has told this host about what it wants: the ids it assigns and which of
/// them its beacon node is subscribed to. The two only mean anything together, and they arrive
/// on the same ordered stream, so they are kept and locked as one thing.
#[derive(Debug, Default)]
pub struct PeerState {
    /// The peer's own topic ids, from its HELLO snapshot and every `TOPIC_ADD` since.
    pub table: PeerTopicTable,
    /// Its latest bitmap over those ids. Empty until the peer's first `SUBS`, so a peer that
    /// has not said what it wants yet is sent nothing rather than everything.
    pub bitmap: Bitmap,
}

impl PeerState {
    /// The state a connection starts with: the table the peer's HELLO carried, and no bitmap.
    pub fn new(table: PeerTopicTable) -> Self {
        Self {
            table,
            bitmap: Bitmap::new(),
        }
    }

    /// Whether the peer's beacon node wants `topic`, which is the question every send path asks
    /// before it builds a frame (§5.4).
    pub fn subscribed(&self, topic: &Topic) -> bool {
        self.table
            .id_of(topic)
            .is_some_and(|id| self.bitmap.test(id))
    }
}

/// The bitmap this host advertises: one bit per topic in `advertised`, at the id `table` gives
/// it. A topic with no id yet contributes no bit, which cannot happen once the same change has
/// been through [`on_changed`](crate::topic::table::on_changed): it interns the whole local set,
/// and `advertised` is part of it.
pub fn advertised(sets: &SubscriptionSets, table: &OwnTopicTable) -> Bitmap {
    let mut bitmap = Bitmap::new();
    for id in sets.advertised.iter().filter_map(|topic| table.get(topic)) {
        bitmap.set(id);
    }
    bitmap
}

/// The word holding `id`'s bit, and which bit of it.
fn position(id: TopicId) -> (usize, u32) {
    let id = u32::from(id.get());
    ((id / u64::BITS) as usize, id % u64::BITS)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use proptest::prelude::*;

    use super::*;

    fn bitmap(ids: impl IntoIterator<Item = u16>) -> Bitmap {
        let mut bitmap = Bitmap::new();
        for id in ids {
            bitmap.set(TopicId::new(id));
        }
        bitmap
    }

    proptest! {
        /// A bit is set for the id it was set for and for no other, and the ids come back in
        /// order. The router asks both questions of every peer's bitmap on every message.
        #[test]
        fn bitmap_set_test_and_iter_round_trip(
            set in prop::collection::btree_set(0u16..2048, 0..64),
            probes in prop::collection::vec(0u16..2048, 0..64),
        ) {
            let bitmap = bitmap(set.iter().copied());

            for probe in probes {
                prop_assert_eq!(bitmap.test(TopicId::new(probe)), set.contains(&probe));
            }
            let listed: BTreeSet<u16> = bitmap.iter_set().map(TopicId::get).collect();
            prop_assert_eq!(listed, set);
        }
    }

    /// The payload a `SUBS` frame carries. A bitmap goes out on every change to every peer, so
    /// it has to cost about what the topics it names cost: 200 subscriptions is a beacon node
    /// on a busy fork transition, and 25 bytes is a quarter of one topic string.
    #[test]
    fn bitmap_encoding_round_trips_and_is_compact() {
        let bitmap = bitmap(0..200);

        let encoded = bitmap.encode();

        assert_eq!(Bitmap::decode(&encoded), bitmap);
        assert_eq!(encoded.len(), 200usize.div_ceil(8));
        assert_eq!(Bitmap::decode(&Bitmap::new().encode()), Bitmap::new());
    }

    fn topic(name: &str) -> Topic {
        Topic::parse(&format!("/eth2/6a95a1a9/{name}/ssz_snappy")).unwrap()
    }

    /// The lookup every send path makes, in the peer's own ids and never in this host's: a bit
    /// is only an answer once the peer has said which topic that id stands for.
    #[test]
    fn subscribed_is_true_only_for_a_topic_the_peer_bound_and_set() {
        let (block, attestation) = (topic("beacon_block"), topic("beacon_attestation_3"));
        let mut table = PeerTopicTable::new();
        table
            .apply_add(TopicId::new(7), &block.to_string())
            .unwrap();
        table
            .apply_add(TopicId::new(9), &attestation.to_string())
            .unwrap();
        let mut state = PeerState::new(table);

        state.bitmap.set(TopicId::new(7));

        assert!(state.subscribed(&block));
        assert!(!state.subscribed(&attestation));
        assert!(!state.subscribed(&topic("beacon_aggregate_and_proof")));
        assert!(!PeerState::default().subscribed(&block));
    }

    /// D06 in one assertion. The extra column topics T-015 subscribes to are in `local` so that
    /// they are interned and announced (D12), and out of the bitmap because the beacon node
    /// never asked for those columns: a sibling reading them as wanted would send this host
    /// every column of every block.
    #[test]
    fn advertised_bitmap_holds_the_advertised_set_and_not_the_local_extras() {
        let (block, column) = (topic("beacon_block"), topic("data_column_sidecar_9"));
        let mut table = OwnTopicTable::new();
        let mut sets = SubscriptionSets::default();
        sets.advertised.insert(block.clone());
        sets.local.insert(block.clone());
        sets.local.insert(column.clone());
        for topic in &sets.local {
            table.intern(topic).unwrap();
        }

        let bitmap = advertised(&sets, &table);

        assert_eq!(
            bitmap.iter_set().collect::<Vec<_>>(),
            vec![table.get(&block).unwrap()]
        );
        assert!(!bitmap.test(table.get(&column).unwrap()));
    }
}
