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

use crate::protocol::MAX_BATCH_ENTRIES;
use crate::roster::Hostname;
use crate::topic::table::TopicId;
use crate::wire::{BATCH_ENTRY_OVERHEAD_BYTES, BATCH_HEADER_BYTES};

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

/// How a flushed batch reaches its destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carrier {
    /// An unreliable datagram, which is what the small class is for: public gossip is the
    /// backup for anything the path drops (§5.4).
    Datagram,
    /// A stream, for the one payload that no datagram on this path can hold. It still travels
    /// alone rather than being split, because only the large class is chunked (D21).
    Stream,
}

/// A batch that is done collecting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Flush {
    /// The host every entry in it is for.
    pub dest: Hostname,
    /// The entries, in the order they were pushed, and none of them stale at the moment of the
    /// flush.
    pub entries: Vec<Entry>,
    /// What carries them.
    pub carrier: Carrier,
    /// Entries the flush left behind for having aged out, which the caller counts as
    /// `stale_dropped_total`. A batch whose entries all aged out is flushed with none of them
    /// and this above zero, so the count reaches the caller either way.
    pub stale_dropped: usize,
}

/// The open batches, one per destination.
///
/// Pure and driven by the caller's clock: every entry point takes the instant, so a test drives
/// the window by hand and the sidecar stamps it from the injected clock.
pub struct Batcher {
    window: Duration,
    stale_after: Duration,
    open: BTreeMap<Hostname, Open>,
}

/// What one destination has collected so far, and what it would encode to.
struct Open {
    opened_at: Instant,
    bytes: usize,
    entries: Vec<Entry>,
}

impl Open {
    fn new(now: Instant) -> Self {
        Self {
            opened_at: now,
            bytes: BATCH_HEADER_BYTES,
            entries: Vec::new(),
        }
    }

    /// Whether one more entry of `cost` bytes still fits a datagram of `max_bytes`, and the
    /// count the receiver agreed to read.
    fn fits(&self, cost: usize, max_bytes: usize) -> bool {
        self.bytes + cost <= max_bytes && self.entries.len() < usize::from(MAX_BATCH_ENTRIES)
    }

    fn take(&mut self, dest: &Hostname, stale_after: Duration, now: Instant) -> Flush {
        let mut entries = std::mem::take(&mut self.entries);
        let stale_dropped = strip_stale(&mut entries, stale_after, now);
        Flush {
            dest: dest.clone(),
            entries,
            carrier: Carrier::Datagram,
            stale_dropped,
        }
    }
}

impl Batcher {
    /// A batcher that holds a destination's payloads for `window` before flushing them and
    /// delivers nothing that has waited longer than `stale_after`.
    pub fn new(window: Duration, stale_after: Duration) -> Self {
        Self {
            window,
            stale_after,
            open: BTreeMap::new(),
        }
    }

    /// Removes the entries that have aged out of `entries` and answers how many went, for the
    /// caller to count as `stale_dropped_total`.
    ///
    /// A flush runs this on its way out, and T-062's sender runs it again when it dequeues one,
    /// because a flush can wait in a per-peer send lane long enough to age out on the way
    /// (D21).
    pub fn drop_stale(&self, entries: &mut Vec<Entry>, now: Instant) -> usize {
        strip_stale(entries, self.stale_after, now)
    }

    /// Adds `payload` to the batch for `dest`, and returns the batches this push completed:
    /// the one for `dest` when the payload no longer fits `max_bytes`, and any whose window ran
    /// out while nothing was being pushed to them.
    ///
    /// `max_bytes` is the destination's current datagram limit, which moves with path MTU
    /// discovery and so arrives with every push rather than at construction. A payload that
    /// would not fit a datagram of its own is flushed on the spot with [`Carrier::Stream`],
    /// which leaves the open batch collecting: the two carriers keep no order between them
    /// anyway.
    pub fn push(
        &mut self,
        dest: &Hostname,
        topic_id: TopicId,
        payload: Bytes,
        max_bytes: usize,
        now: Instant,
    ) -> Vec<Flush> {
        let mut flushes = self.tick(now);
        let cost = BATCH_ENTRY_OVERHEAD_BYTES + payload.len();
        let entry = Entry {
            topic_id,
            payload,
            pushed_at: now,
        };

        if BATCH_HEADER_BYTES + cost > max_bytes {
            flushes.push(Flush {
                dest: dest.clone(),
                entries: vec![entry],
                carrier: Carrier::Stream,
                stale_dropped: 0,
            });
            return flushes;
        }

        let mut open = self.open.remove(dest).unwrap_or_else(|| Open::new(now));
        if !open.fits(cost, max_bytes) {
            flushes.push(open.take(dest, self.stale_after, now));
            open = Open::new(now);
        }
        open.bytes += cost;
        open.entries.push(entry);
        self.open.insert(dest.clone(), open);
        flushes
    }

    /// The batches whose window has run out at `now`. Called from a timer a few times per
    /// window, so a destination that has gone quiet still gets what it was owed.
    pub fn tick(&mut self, now: Instant) -> Vec<Flush> {
        let (window, stale_after) = (self.window, self.stale_after);
        let mut flushes = Vec::new();
        self.open.retain(|dest, open| {
            if open.opened_at + window > now {
                return true;
            }
            flushes.push(open.take(dest, stale_after, now));
            false
        });
        flushes
    }
}

fn strip_stale(entries: &mut Vec<Entry>, stale_after: Duration, now: Instant) -> usize {
    let before = entries.len();
    entries.retain(|entry| entry.pushed_at + stale_after > now);
    before - entries.len()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::time::Duration;

    use bytes::Bytes;
    use proptest::prelude::*;

    use super::*;
    use crate::protocol::MAX_BATCH_ENTRIES;
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

    /// Not in the ticket's plan: `MAX_BATCH_ENTRIES` is the count a peer advertises in HELLO and
    /// refuses past, and a datagram limit high enough to reach it is a limit no test would
    /// otherwise use.
    #[test]
    fn batch_never_holds_more_than_max_batch_entries() {
        const ROOMY: usize = 1 << 20;
        let clock = FakeClock::new();
        let mut batcher = batcher();
        for _ in 0..MAX_BATCH_ENTRIES {
            let pushed = batcher.push(
                &dest("host-a"),
                TopicId::new(11),
                payload(1),
                ROOMY,
                clock.now(),
            );
            assert!(pushed.is_empty());
        }

        let flushes = batcher.push(
            &dest("host-a"),
            TopicId::new(11),
            payload(2),
            ROOMY,
            clock.now(),
        );

        assert_eq!(flushes.len(), 1);
        assert_eq!(flushes[0].entries.len(), usize::from(MAX_BATCH_ENTRIES));
    }

    #[test]
    fn payload_larger_than_max_bytes_is_flushed_alone_with_stream_carrier() {
        const ROOM_FOR_ONE: usize = BATCH_HEADER_BYTES + BATCH_ENTRY_OVERHEAD_BYTES + PAYLOAD_BYTES;
        let clock = FakeClock::new();
        let mut batcher = batcher();
        let block = Bytes::from(vec![9; ROOM_FOR_ONE]);
        batcher.push(
            &dest("host-a"),
            TopicId::new(11),
            payload(1),
            ROOM_FOR_ONE,
            clock.now(),
        );

        let flushes = batcher.push(
            &dest("host-a"),
            TopicId::new(11),
            block.clone(),
            ROOM_FOR_ONE,
            clock.now(),
        );

        assert_eq!(flushes.len(), 1);
        assert_eq!(flushes[0].carrier, Carrier::Stream);
        assert_eq!(payloads(&flushes[0]), vec![block]);

        clock.advance(WINDOW);
        let rest = batcher.tick(clock.now());
        assert_eq!(rest.len(), 1);
        assert_eq!(rest[0].carrier, Carrier::Datagram);
        assert_eq!(payloads(&rest[0]), vec![payload(1)]);
    }

    #[test]
    fn stale_payload_is_dropped_at_flush_and_counted() {
        let clock = FakeClock::new();
        let mut batcher = batcher();
        batcher.push(
            &dest("host-a"),
            TopicId::new(11),
            payload(1),
            MAX_BYTES,
            clock.now(),
        );

        clock.advance(STALE_AFTER);
        let flushes = batcher.tick(clock.now());

        assert_eq!(flushes.len(), 1);
        assert!(flushes[0].entries.is_empty());
        assert_eq!(flushes[0].stale_dropped, 1);
    }

    #[test]
    fn mixed_fresh_and_stale_payloads_flush_only_the_fresh_ones() {
        let clock = FakeClock::new();
        let mut batcher = batcher();
        batcher.push(
            &dest("host-a"),
            TopicId::new(11),
            payload(1),
            MAX_BYTES,
            clock.now(),
        );
        clock.advance(WINDOW - Duration::from_millis(1));
        batcher.push(
            &dest("host-a"),
            TopicId::new(11),
            payload(2),
            MAX_BYTES,
            clock.now(),
        );

        clock.advance(STALE_AFTER - (WINDOW - Duration::from_millis(1)));
        let flushes = batcher.tick(clock.now());

        assert_eq!(flushes.len(), 1);
        assert_eq!(payloads(&flushes[0]), vec![payload(2)]);
        assert_eq!(flushes[0].stale_dropped, 1);
    }

    #[test]
    fn drop_stale_on_a_flushed_batch_removes_only_entries_that_aged_out_since() {
        let clock = FakeClock::new();
        let mut batcher = batcher();
        batcher.push(
            &dest("host-a"),
            TopicId::new(11),
            payload(1),
            MAX_BYTES,
            clock.now(),
        );
        clock.advance(WINDOW - Duration::from_millis(1));
        batcher.push(
            &dest("host-a"),
            TopicId::new(11),
            payload(2),
            MAX_BYTES,
            clock.now(),
        );
        clock.advance(Duration::from_millis(1));
        let mut flushes = batcher.tick(clock.now());
        assert_eq!(flushes[0].entries.len(), 2);
        assert_eq!(flushes[0].stale_dropped, 0);

        clock.advance(STALE_AFTER - WINDOW);
        let dropped = batcher.drop_stale(&mut flushes[0].entries, clock.now());

        assert_eq!(dropped, 1);
        assert_eq!(payloads(&flushes[0]), vec![payload(2)]);
    }

    #[test]
    fn flush_preserves_push_order() {
        let clock = FakeClock::new();
        let mut batcher = batcher();
        for byte in 1..=4 {
            batcher.push(
                &dest("host-a"),
                TopicId::new(u16::from(byte)),
                payload(byte),
                MAX_BYTES,
                clock.now(),
            );
        }

        clock.advance(WINDOW);
        let flushes = batcher.tick(clock.now());

        assert_eq!(
            payloads(&flushes[0]),
            (1..=4).map(payload).collect::<Vec<Bytes>>()
        );
    }

    /// One step of the property test: a payload for one of three destinations, or time passing.
    #[derive(Clone, Debug)]
    enum Op {
        Push(u8, usize),
        Advance(u64),
    }

    fn ops() -> impl Strategy<Value = Vec<Op>> {
        prop::collection::vec(
            prop_oneof![
                (0u8..3, 4usize..1400).prop_map(|(host, len)| Op::Push(host, len)),
                (0u64..1500).prop_map(Op::Advance),
            ],
            0..200,
        )
    }

    /// A payload of `len` bytes that says which push it came from.
    fn tagged(nonce: u32, len: usize) -> Bytes {
        let mut payload = vec![0u8; len];
        payload[..4].copy_from_slice(&nonce.to_le_bytes());
        Bytes::from(payload)
    }

    fn nonce(payload: &Bytes) -> u32 {
        u32::from_le_bytes(payload[..4].try_into().unwrap())
    }

    fn record(flushes: Vec<Flush>, flushed: &mut Vec<u32>, stale: &mut usize) {
        for flush in flushes {
            *stale += flush.stale_dropped;
            flushed.extend(flush.entries.iter().map(|entry| nonce(&entry.payload)));
        }
    }

    proptest! {
        /// Nothing is lost and nothing is delivered twice: every payload pushed either comes
        /// back in exactly one flush or is counted stale, whatever order the pushes and the
        /// ticks arrive in. That is the whole contract T-062 relies on when it counts what it
        /// sent against what the beacon node handed over.
        #[test]
        fn property_every_pushed_payload_is_flushed_or_counted_stale_exactly_once(
            ops in ops(),
        ) {
            let clock = FakeClock::new();
            let mut batcher = batcher();
            let mut pushes = 0u32;
            let mut flushed = Vec::new();
            let mut stale = 0;

            for op in ops {
                match op {
                    Op::Push(host, len) => {
                        let flushes = batcher.push(
                            &dest(&format!("host-{host}")),
                            TopicId::new(u16::from(host)),
                            tagged(pushes, len),
                            MAX_BYTES,
                            clock.now(),
                        );
                        pushes += 1;
                        record(flushes, &mut flushed, &mut stale);
                    }
                    Op::Advance(millis) => {
                        clock.advance(Duration::from_millis(millis));
                        record(batcher.tick(clock.now()), &mut flushed, &mut stale);
                    }
                }
            }
            clock.advance(WINDOW);
            record(batcher.tick(clock.now()), &mut flushed, &mut stale);

            prop_assert_eq!(flushed.len() + stale, pushes as usize);
            let once: BTreeSet<u32> = flushed.iter().copied().collect();
            prop_assert_eq!(once.len(), flushed.len());
            prop_assert!(once.iter().all(|nonce| *nonce < pushes));
        }
    }
}
