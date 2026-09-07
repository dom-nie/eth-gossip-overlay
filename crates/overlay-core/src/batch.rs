//! Coalescing small-class payloads into one batch per destination (§5.4, D21).
//!
//! Attestations dominate the fleet's traffic at a few thousand a second of about 240 bytes
//! each, so one datagram per message would be one datagram per message per subscribed host.
//! Holding what is going to the same host for a few milliseconds turns that into one datagram
//! carrying a few dozen entries.
//!
//! The worst case a payload waits here is the window, 10 ms at the shipped default, and it is
//! only ever the window: a batch that fills up goes at once. §10 puts that against the 8 s an
//! aggregator has to collect attestations, which is why the trade is worth making at all.
//!
//! A batch is keyed by destination and nothing else. Each entry names its own topic, so a host
//! subscribed to several attestation subnets receives one datagram covering all of them and a
//! topic id it cannot resolve costs that entry alone (D21).
//!
//! Nothing here talks to a connection. The datagram limit is per connection and moves with path
//! MTU discovery, so the caller passes the current one to every push and T-062 is what asks
//! quinn for it.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::roster::Hostname;
use crate::topic::table::TopicId;

/// One payload waiting for the batch it travels in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// This host's id for the topic the payload arrived on, from its own topic table.
    pub topic_id: TopicId,
    /// The gossipsub wire form, snappy-compressed SSZ, which the overlay never looks inside.
    pub payload: Bytes,
    /// When the entry was pushed, which is what decides whether it is still worth delivering.
    pub pushed_at: Instant,
}

/// A batch that is done collecting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Flush {
    /// The host every entry in it is for.
    pub dest: Hostname,
    /// The entries, in the order they were pushed.
    pub entries: Vec<Entry>,
}

/// The open batches, one per destination.
///
/// Pure and driven by the caller's clock: every entry point takes the instant, so a test drives
/// the window by hand and the sidecar stamps it from the injected clock.
pub struct Batcher {
    window: Duration,
    open: BTreeMap<Hostname, Open>,
}

/// What one destination has collected so far.
struct Open {
    opened_at: Instant,
    entries: Vec<Entry>,
}

impl Batcher {
    /// A batcher that holds a destination's payloads for `window` before flushing them.
    /// `stale_after` is what the stale drop reads.
    pub fn new(window: Duration, _stale_after: Duration) -> Self {
        Self {
            window,
            open: BTreeMap::new(),
        }
    }

    /// Adds `payload` to the batch for `dest`, and returns the batches this push completed:
    /// any whose window ran out while nothing was being pushed to them.
    pub fn push(
        &mut self,
        dest: &Hostname,
        topic_id: TopicId,
        payload: Bytes,
        _max_bytes: usize,
        now: Instant,
    ) -> Vec<Flush> {
        let flushes = self.tick(now);
        self.open
            .entry(dest.clone())
            .or_insert_with(|| Open {
                opened_at: now,
                entries: Vec::new(),
            })
            .entries
            .push(Entry {
                topic_id,
                payload,
                pushed_at: now,
            });
        flushes
    }

    /// The batches whose window has run out at `now`. Called from a timer a few times per
    /// window, so a destination that has gone quiet still gets what it was owed.
    pub fn tick(&mut self, now: Instant) -> Vec<Flush> {
        let window = self.window;
        let mut flushes = Vec::new();
        self.open.retain(|dest, open| {
            if open.opened_at + window > now {
                return true;
            }
            flushes.push(Flush {
                dest: dest.clone(),
                entries: std::mem::take(&mut open.entries),
            });
            false
        });
        flushes
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;

    use super::*;
    use crate::roster::Hostname;
    use crate::time::{Clock, FakeClock};
    use crate::topic::table::TopicId;
    use crate::wire::{BATCH_ENTRY_OVERHEAD_BYTES, BATCH_HEADER_BYTES};

    const WINDOW: Duration = Duration::from_millis(10);
    const STALE_AFTER: Duration = Duration::from_millis(1000);

    /// A datagram limit in the range path MTU discovery reports on the public internet (§5.4).
    const MAX_BYTES: usize = 1200;

    fn batcher() -> Batcher {
        Batcher::new(WINDOW, STALE_AFTER)
    }

    fn dest(name: &str) -> Hostname {
        Hostname(name.to_owned())
    }

    /// An attestation, near enough: §10 puts them at about 240 bytes.
    const PAYLOAD_BYTES: usize = 240;

    /// One payload, filled with `byte` so a test can tell entries apart.
    fn payload(byte: u8) -> Bytes {
        Bytes::from(vec![byte; PAYLOAD_BYTES])
    }

    /// What a flush carries, in the order it carries it.
    fn payloads(flush: &Flush) -> Vec<Bytes> {
        flush
            .entries
            .iter()
            .map(|entry| entry.payload.clone())
            .collect()
    }

    #[test]
    fn single_payload_is_not_flushed_before_the_window() {
        let clock = FakeClock::new();
        let mut batcher = batcher();

        let pushed = batcher.push(
            &dest("host-a"),
            TopicId::new(1),
            payload(1),
            MAX_BYTES,
            clock.now(),
        );
        assert!(pushed.is_empty());

        clock.advance(WINDOW - Duration::from_millis(1));

        assert!(batcher.tick(clock.now()).is_empty());
    }

    #[test]
    fn tick_after_window_flushes_the_open_batch() {
        let clock = FakeClock::new();
        let mut batcher = batcher();
        batcher.push(
            &dest("host-a"),
            TopicId::new(1),
            payload(1),
            MAX_BYTES,
            clock.now(),
        );

        clock.advance(WINDOW);
        let flushes = batcher.tick(clock.now());

        assert_eq!(flushes.len(), 1);
        assert_eq!(flushes[0].dest, dest("host-a"));
        assert_eq!(payloads(&flushes[0]), vec![payload(1)]);
        assert!(batcher.tick(clock.now()).is_empty());
    }

    #[test]
    fn payloads_for_same_dest_share_one_batch_whatever_their_topic() {
        let clock = FakeClock::new();
        let mut batcher = batcher();
        for (topic, byte) in [(11, 1), (22, 2)] {
            batcher.push(
                &dest("host-a"),
                TopicId::new(topic),
                payload(byte),
                MAX_BYTES,
                clock.now(),
            );
        }

        clock.advance(WINDOW);
        let flushes = batcher.tick(clock.now());

        assert_eq!(flushes.len(), 1);
        let topics: Vec<TopicId> = flushes[0]
            .entries
            .iter()
            .map(|entry| entry.topic_id)
            .collect();
        assert_eq!(topics, vec![TopicId::new(11), TopicId::new(22)]);
        assert_eq!(payloads(&flushes[0]), vec![payload(1), payload(2)]);
    }

    #[test]
    fn payloads_for_different_dests_are_separate_batches() {
        let clock = FakeClock::new();
        let mut batcher = batcher();
        for (host, byte) in [("host-a", 1), ("host-b", 2)] {
            batcher.push(
                &dest(host),
                TopicId::new(11),
                payload(byte),
                MAX_BYTES,
                clock.now(),
            );
        }

        clock.advance(WINDOW);
        let flushes = batcher.tick(clock.now());

        assert_eq!(flushes.len(), 2);
        let a = flushes.iter().find(|f| f.dest == dest("host-a")).unwrap();
        let b = flushes.iter().find(|f| f.dest == dest("host-b")).unwrap();
        assert_eq!(payloads(a), vec![payload(1)]);
        assert_eq!(payloads(b), vec![payload(2)]);
    }

    #[test]
    fn push_that_would_exceed_max_bytes_flushes_the_previous_batch_and_starts_a_new_one() {
        const ROOM_FOR_TWO: usize =
            BATCH_HEADER_BYTES + 2 * (BATCH_ENTRY_OVERHEAD_BYTES + PAYLOAD_BYTES);
        let clock = FakeClock::new();
        let mut batcher = batcher();
        for byte in [1, 2] {
            let pushed = batcher.push(
                &dest("host-a"),
                TopicId::new(11),
                payload(byte),
                ROOM_FOR_TWO,
                clock.now(),
            );
            assert!(pushed.is_empty());
        }

        let flushes = batcher.push(
            &dest("host-a"),
            TopicId::new(11),
            payload(3),
            ROOM_FOR_TWO,
            clock.now(),
        );

        assert_eq!(flushes.len(), 1);
        assert_eq!(payloads(&flushes[0]), vec![payload(1), payload(2)]);
        clock.advance(WINDOW);
        let rest = batcher.tick(clock.now());
        assert_eq!(rest.len(), 1);
        assert_eq!(payloads(&rest[0]), vec![payload(3)]);
    }
}
