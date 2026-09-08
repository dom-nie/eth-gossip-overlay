//! The payloads of large messages this host has just taken, kept long enough to answer a peer's
//! repair request for one (§5.6).
//!
//! Repair needs two things and this is the second of them. Who to ask comes free from the chunks
//! that already arrived, which the reassembler records as it goes (D23); nothing announces what a
//! host holds and there is no `HAVE` frame. What is left is the bytes, and the seen cache keeps
//! only ids, so a large message is kept whole here for as long as a peer can still ask for it.
//!
//! Two places insert, both on a large-class first arrival: T-016 as a message arrives from the
//! beacon node, and T-074's reassembler when a striped message completes.
//!
//! A column is asked for by `(block_root, index)` rather than by message id, because a host that
//! never saw the column has no id for it (T-083). The index that answers that question is part of
//! the entry, so it goes when the entry goes.
//!
//! `now` is a parameter rather than a clock of its own, so nothing here reads a time the caller
//! did not give it: both insert sites already hold the injected clock, and a test drives expiry
//! from a `FakeClock` of its own.

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;

    use crate::msgid::MessageId;
    use crate::recent::RecentLarge;
    use crate::time::{Clock, FakeClock};
    use crate::topic::Topic;

    const TOPIC: &str = "/eth2/6a95a1a9/beacon_block/ssz_snappy";

    fn id(byte: u8) -> MessageId {
        MessageId([byte; 20])
    }

    fn topic() -> Topic {
        Topic::parse(TOPIC).expect("a topic in the only shape the parser takes")
    }

    /// A payload of `len` bytes, distinct per `byte` so a test can tell two of them apart.
    fn payload(byte: u8, len: usize) -> Bytes {
        Bytes::from(vec![byte; len])
    }

    fn store(max_bytes: usize) -> RecentLarge {
        RecentLarge::new(Duration::from_secs(60), max_bytes)
    }

    #[test]
    fn recent_store_returns_inserted_payload() {
        let clock = FakeClock::new();
        let mut recent = store(1024);

        recent.insert(id(1), topic(), payload(1, 200), clock.now());

        assert_eq!(recent.get(&id(1)), Some((topic(), payload(1, 200))));
        assert_eq!(recent.get(&id(2)), None);
    }

    #[test]
    fn recent_store_evicts_oldest_when_over_byte_bound() {
        let clock = FakeClock::new();
        let mut recent = store(250);

        for byte in [1, 2, 3] {
            recent.insert(id(byte), topic(), payload(byte, 100), clock.now());
            clock.advance(Duration::from_secs(1));
        }

        assert_eq!(recent.get(&id(1)), None);
        assert!(recent.get(&id(2)).is_some());
        assert!(recent.get(&id(3)).is_some());
    }

    #[test]
    fn recent_store_entries_expire_after_ttl() {
        let clock = FakeClock::new();
        let mut recent = store(1024);
        recent.insert(id(1), topic(), payload(1, 200), clock.now());

        clock.advance(Duration::from_secs(60) - Duration::from_millis(1));
        recent.gc(clock.now());
        assert!(recent.get(&id(1)).is_some());

        clock.advance(Duration::from_millis(1));
        recent.gc(clock.now());
        assert_eq!(recent.get(&id(1)), None);
    }

    /// Room for two payloads and three inserts of two ids. A repeat that charged the bound again
    /// would push the first one out.
    #[test]
    fn second_insert_of_the_same_id_does_not_double_count_bytes() {
        let clock = FakeClock::new();
        let mut recent = store(200);

        recent.insert(id(1), topic(), payload(1, 100), clock.now());
        recent.insert(id(1), topic(), payload(1, 100), clock.now());
        recent.insert(id(2), topic(), payload(2, 100), clock.now());

        assert!(recent.get(&id(1)).is_some());
        assert!(recent.get(&id(2)).is_some());
    }

    #[test]
    fn column_identity_resolves_to_the_message_and_expires_with_it() {
        let clock = FakeClock::new();
        let mut recent = store(1024);
        let root = [7; 32];
        recent.insert(id(1), topic(), payload(1, 200), clock.now());

        recent.index_column(root, 42, id(1));
        assert_eq!(recent.get_by_column(root, 42), Some(id(1)));
        assert_eq!(recent.get_by_column(root, 41), None);

        clock.advance(Duration::from_secs(60));
        recent.gc(clock.now());

        assert_eq!(recent.get_by_column(root, 42), None);
        assert_eq!(recent.get(&id(1)), None);
    }
}
