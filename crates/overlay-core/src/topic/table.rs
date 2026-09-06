//! Topic strings to the 16-bit ids that carry them on the wire.

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
}
