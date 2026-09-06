//! The subscription bitmap a sidecar advertises, and what it keeps of every peer's.

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use proptest::prelude::*;

    use super::*;
    use crate::topic::table::TopicId;

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
}
