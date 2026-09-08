//! When to ask a peer for the chunks a message is still missing, who to ask, and what for
//! (§5.6, D23, D24).
//!
//! Everything here is a decision and nothing here is a socket: one tick reads the reassembler,
//! answers what to do about each message past its deadline, and hands that back to the transport
//! task that opens the streams. The lock the reassembler holds is taken and released inside
//! [`Reassembler::incomplete_older_than`], and [`Scheduler::tick`] is not `async`, so a caller
//! cannot hold it across an `await` even by accident.

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;

    use super::*;
    use crate::reassemble::{ReassembleConfig, Reassembler};
    use crate::time::{Clock, FakeClock};
    use crate::topic::Topic;
    use crate::wire::Chunk;

    const TOPIC: &str = "/eth2/6a95a1a9/beacon_block/ssz_snappy";
    const DEADLINE: Duration = Duration::from_millis(250);

    fn topic() -> Topic {
        Topic::parse(TOPIC).expect("a topic in the only shape the parser takes")
    }

    fn host(name: &str) -> Hostname {
        Hostname(name.to_owned())
    }

    /// One chunk of a four-data, two-parity message. Nothing decodes it: every test here holds
    /// fewer than `k` of them, which is what makes the message one to repair.
    fn chunk(index: u16) -> Chunk {
        Chunk {
            msg_id: MessageId([9; 20]),
            topic_id: 0,
            k: 4,
            m: 2,
            index,
            total_len: 256,
            data: Bytes::from(vec![index as u8; 64]),
        }
    }

    /// A reassembler holding `indices`, each from the peer named beside it.
    fn collecting(indices: &[(u16, &str, bool)], now: Instant) -> Reassembler {
        let reassembler = Reassembler::new(ReassembleConfig::default());
        for (index, from, forwarded) in indices {
            reassembler.on_chunk(&chunk(*index), &topic(), &host(from), *forwarded, now);
        }
        reassembler
    }

    /// Every peer answers with the same round trip, which is what a test that is not about the
    /// order wants.
    fn reachable(_: &Hostname) -> Option<Duration> {
        Some(Duration::from_millis(10))
    }

    #[test]
    fn no_request_before_deadline() {
        let clock = FakeClock::new();
        let reassembler = collecting(&[(0, "a", false)], clock.now());
        let mut scheduler = Scheduler::default();

        clock.advance(DEADLINE - Duration::from_millis(1));
        assert_eq!(
            scheduler.tick(&reassembler, DEADLINE, reachable, clock.now()),
            Vec::new()
        );

        clock.advance(Duration::from_millis(1));
        assert!(matches!(
            scheduler.tick(&reassembler, DEADLINE, reachable, clock.now()).as_slice(),
            [Decision::Ask(request)] if request.peer == host("a")
        ));
    }
}
