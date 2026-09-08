//! Which host each chunk of a large message goes to (§5.4, D18).

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msgid::MessageId;
    use crate::roster::Hostname;

    fn host(name: &str) -> Hostname {
        Hostname(name.to_owned())
    }

    /// A region's live subscribed hosts, in the hostname order the caller sorts them into.
    fn hosts(count: usize) -> Vec<Hostname> {
        (1..=count).map(|n| host(&format!("bn-{n:02}"))).collect()
    }

    /// An id whose first eight bytes little-endian are `rotation`, which is the number the
    /// assignment takes the remainder of (D18).
    fn msg_id(rotation: u64) -> MessageId {
        let mut id = [0u8; 20];
        id[..8].copy_from_slice(&rotation.to_le_bytes());
        MessageId(id)
    }

    /// The worked example in [`assign`]'s own doc comment: five hosts, seven chunks, and an id
    /// that lands the rotation on 3. Chunk 0 goes to the fourth host and the round robin runs
    /// from there, wrapping at the end of the region.
    #[test]
    fn assign_is_round_robin_in_sorted_order_from_the_rotation_offset() {
        let targets = assign(&msg_id(3), &hosts(5), 7);

        assert_eq!(
            targets,
            vec![
                host("bn-04"),
                host("bn-05"),
                host("bn-01"),
                host("bn-02"),
                host("bn-03"),
                host("bn-04"),
                host("bn-05"),
            ]
        );
    }
}
