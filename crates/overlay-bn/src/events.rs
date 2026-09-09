//! The beacon node's block event stream, which is the only place import time comes from (§12).
//!
//! `GET /eth/v1/events?topics=block` is Server-Sent Events: a frame per event, fields one to a
//! line, a blank line closing the frame. Lighthouse fires a `block` event when it has imported
//! the block, which is the moment §2 says arrival is not, so this is where the 200 to 500 ms of
//! `newPayload` and column verification becomes a number an operator can see.

use std::collections::BTreeMap;
use std::str::from_utf8;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use overlay_core::backoff::Backoff;
use overlay_core::events::{ImportEvent, Source, emit_import};
use overlay_core::roster::Hostname;
use overlay_core::time::Clock;
use serde::Deserialize;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use url::Url;

use crate::spec::SpecSnapshot;

/// One `block` event: the beacon node has imported this block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockEvent {
    /// The slot the block was proposed for.
    pub slot: u64,
    /// Its root, which is what a first-arrival record is filed under.
    pub block_root: [u8; 32],
}

/// What the sidecar counts about the event stream. The binary implements it on its metrics; a
/// caller that wants no series passes `()`.
pub trait BlockEventStats: Send + Sync {
    /// Whether the stream is connected right now.
    fn set_connected(&self, connected: bool);
    /// One import event, and whether this host had a record of the block arriving.
    fn imported(&self, matched: bool);
}

impl BlockEventStats for () {
    fn set_connected(&self, _: bool) {}
    fn imported(&self, _: bool) {}
}

/// When a block first reached this host, and over which side.
struct FirstArrival {
    /// The wall reading, which is the only form that means anything on another host.
    at: SystemTime,
    /// The same moment on the monotonic clock. The lag is measured on this one, because
    /// subtracting two wall readings gives whatever a clock step did to them in between.
    seen: Instant,
    /// The peer whose stream carried it, or `None` when the beacon node's own gossip won.
    origin: Option<Hostname>,
}

/// How many slots of arrival records to keep: long enough that a block cannot still be waiting
/// to be imported, short enough that the map stays a handful of entries.
const RETENTION_SLOTS: u64 = 8;

/// Which blocks reached this host lately, so an import event can be turned into a lag.
pub struct Arrivals {
    clock: Arc<dyn Clock>,
    spec: watch::Receiver<SpecSnapshot>,
    seen: Mutex<BTreeMap<[u8; 32], FirstArrival>>,
}

impl Arrivals {
    /// An empty keeper. `spec` is read fresh on every use, so a beacon node that reports a
    /// different `SECONDS_PER_SLOT` changes the retention window without anything reconnecting.
    pub fn new(clock: Arc<dyn Clock>, spec: watch::Receiver<SpecSnapshot>) -> Self {
        Self {
            clock,
            spec,
            seen: Mutex::new(BTreeMap::new()),
        }
    }

    /// Files the arrival of `block_root`. A block that arrives again keeps the record it already
    /// has, which is the one a lag is worth measuring from.
    pub fn arrived(&self, block_root: [u8; 32], source: &Source<'_>) {
        let arrival = FirstArrival {
            at: self.clock.wall(),
            seen: self.clock.now(),
            origin: match source {
                Source::Bn => None,
                Source::Overlay { origin } => Some((*origin).clone()),
            },
        };
        let mut seen = self.seen();
        self.prune(&mut seen, arrival.seen);
        seen.entry(block_root).or_insert(arrival);
    }

    /// Logs `event` as an import and says whether an arrival record matched it.
    pub fn imported(&self, event: &BlockEvent) -> bool {
        let now = self.clock.now();
        let mut seen = self.seen();
        self.prune(&mut seen, now);
        let arrival = seen.get(&event.block_root);
        emit_import(&ImportEvent {
            slot: event.slot,
            block_root: event.block_root,
            imported_at: self.clock.wall(),
            first_arrival_at: arrival.map(|arrival| arrival.at),
            source: arrival.map(|arrival| match &arrival.origin {
                None => Source::Bn,
                Some(origin) => Source::Overlay { origin },
            }),
            lag_ms: arrival.map(|arrival| {
                u64::try_from(now.saturating_duration_since(arrival.seen).as_millis())
                    .unwrap_or(u64::MAX)
            }),
        });
        arrival.is_some()
    }

    /// Drops the records the retention window no longer covers. Both entry points call it, so a
    /// beacon node that has stopped importing still lets the map empty out.
    fn prune(&self, seen: &mut BTreeMap<[u8; 32], FirstArrival>, now: Instant) {
        let window = Duration::from_secs(RETENTION_SLOTS * SpecSnapshot::MAINNET.seconds_per_slot);
        seen.retain(|_, arrival| now.saturating_duration_since(arrival.seen) <= window);
    }

    fn seen(&self) -> MutexGuard<'_, BTreeMap<[u8; 32], FirstArrival>> {
        // A poisoned lock is a panic in another holder. The records are still records, and
        // losing import telemetry is not worth spreading a panic into a receive path.
        self.seen.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The task that reads the beacon node's block event stream.
pub struct BlockEvents {
    /// The stream task. It runs until it is aborted.
    pub task: JoinHandle<()>,
}

impl BlockEvents {
    /// Starts reading `url`. The beacon node ends the stream on its own restart and on any
    /// hiccup between the two processes, so every end is a reconnect under `backoff` (T-013).
    #[expect(
        clippy::expect_used,
        reason = "with no TLS backend compiled in, a client can only fail to build on proxy \
                  setup, and none is configured"
    )]
    pub fn spawn(
        url: Url,
        backoff: Backoff,
        arrivals: Arc<Arrivals>,
        stats: Arc<dyn BlockEventStats>,
    ) -> Self {
        // No request timeout: this one is meant to stay open between blocks.
        let http = reqwest::Client::builder()
            .build()
            .expect("plain HTTP client");
        Self {
            task: tokio::spawn(run(http, url, backoff, arrivals, stats)),
        }
    }
}

/// One connection after another, for as long as the task lives.
async fn run(
    http: reqwest::Client,
    url: Url,
    mut backoff: Backoff,
    arrivals: Arc<Arrivals>,
    stats: Arc<dyn BlockEventStats>,
) {
    loop {
        match read(&http, &url, &arrivals, &stats).await {
            // The beacon node closed a stream it had been serving, so the next one is worth
            // trying at once. A failure gets the delay the last one earned.
            Ok(()) => backoff.reset(),
            Err(err) => tracing::debug!(%err, %url, "the beacon node's event stream failed"),
        }
        stats.set_connected(false);
        let delay = backoff.next_delay(&mut rand::rng());
        tokio::time::sleep(delay).await;
    }
}

/// One connection, until the beacon node closes it or the read fails.
async fn read(
    http: &reqwest::Client,
    url: &Url,
    arrivals: &Arrivals,
    stats: &Arc<dyn BlockEventStats>,
) -> Result<(), reqwest::Error> {
    let mut response = http.get(url.clone()).send().await?;
    stats.set_connected(true);
    let mut frames = Frames::default();
    while let Some(chunk) = response.chunk().await? {
        for event in frames.feed(&chunk) {
            stats.imported(arrivals.imported(&event));
        }
    }
    Ok(())
}

/// The `data` of a `block` event. Lighthouse writes the slot as a quoted decimal and the root
/// as `0x`-prefixed hex; `execution_optimistic` rides along and is not read.
#[derive(Deserialize)]
struct BlockData {
    slot: String,
    block: String,
}

/// The one event name the sidecar reads. Every other topic on the stream, and the comments the
/// beacon node writes to hold the connection open, are skipped.
const BLOCK: &str = "block";

/// Cuts the beacon node's byte stream into frames and reads the events out of them. A chunk
/// stops wherever the network put it, so whatever follows the last blank line waits for more.
#[derive(Default)]
struct Frames {
    buf: Vec<u8>,
}

impl Frames {
    /// Every event `chunk` completed, in the order the beacon node wrote them.
    fn feed(&mut self, chunk: &[u8]) -> Vec<BlockEvent> {
        self.buf.extend_from_slice(chunk);
        let mut events = Vec::new();
        while let Some(blank) = self.buf.windows(2).position(|pair| pair == b"\n\n") {
            let frame: Vec<u8> = self.buf.drain(..blank + 2).collect();
            if let Ok(text) = from_utf8(&frame) {
                events.extend(block_event(text));
            }
        }
        events
    }
}

/// The event one frame carries, if it is one the sidecar reads.
fn block_event(frame: &str) -> Option<BlockEvent> {
    let mut name = None;
    let mut data = None;
    for line in frame.lines() {
        // A line with no colon is not a field at all, and one whose name is empty is a comment.
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" => name = Some(value),
            "data" => data = Some(value),
            _ => {}
        }
    }
    if name != Some(BLOCK) {
        return None;
    }
    let data: BlockData = serde_json::from_str(data?).ok()?;
    Some(BlockEvent {
        slot: data.slot.parse().ok()?,
        block_root: root(&data.block)?,
    })
}

/// Reads the `0x`-prefixed 32 bytes the beacon API reports a root as.
fn root(text: &str) -> Option<[u8; 32]> {
    let digits = text.strip_prefix("0x")?.as_bytes();
    let mut root = [0; 32];
    if digits.len() != 2 * root.len() {
        return None;
    }
    for (byte, pair) in root.iter_mut().zip(digits.chunks_exact(2)) {
        *byte = u8::from_str_radix(from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(root)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use overlay_core::backoff::Backoff;
    use overlay_core::events::Source;
    use overlay_core::time::FakeClock;
    use tokio::sync::mpsc;
    use tokio::time::timeout;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::spec::{self, spec_watch};

    /// The path of the beacon node's event stream.
    const EVENTS: &str = "/eth/v1/events";

    /// What the stream is served as.
    const SSE: &str = "text/event-stream";

    /// Long enough for a reconnect on a loaded box, short enough that a client that never comes
    /// back fails the test instead of hanging it.
    const PATIENCE: Duration = Duration::from_secs(5);

    /// A stats sink that hands every import straight back to the test, in order.
    struct Imports(mpsc::UnboundedSender<bool>);

    impl BlockEventStats for Imports {
        fn set_connected(&self, _: bool) {}

        fn imported(&self, matched: bool) {
            let _ = self.0.send(matched);
        }
    }

    /// Whether the next import matched an arrival record, or a failed test if none arrives.
    async fn next(imports: &mut mpsc::UnboundedReceiver<bool>) -> Option<bool> {
        timeout(PATIENCE, imports.recv()).await.unwrap()
    }

    /// The frame Lighthouse writes for one imported block: the event name, the JSON payload and
    /// the blank line that closes the frame.
    fn frame(slot: u64, root: &str) -> String {
        format!(
            "event: block\ndata: {{\"slot\":\"{slot}\",\"block\":\"{root}\",\"execution_optimistic\":false}}\n\n"
        )
    }

    /// A block root of one repeated byte, in the `0x`-prefixed form the beacon API reports.
    fn root(byte: u8) -> String {
        format!("0x{}", format!("{byte:02x}").repeat(32))
    }

    /// An import of the block whose root is `byte` repeated.
    fn block(slot: u64, byte: u8) -> BlockEvent {
        BlockEvent {
            slot,
            block_root: [byte; 32],
        }
    }

    #[test]
    fn parses_block_event_slot_and_root() {
        let mut frames = Frames::default();

        let events = frames.feed(frame(7_654_321, &root(0xab)).as_bytes());

        assert_eq!(
            events,
            [BlockEvent {
                slot: 7_654_321,
                block_root: [0xab; 32],
            }]
        );
    }

    #[test]
    fn ignores_other_event_types_and_comments() {
        let mut frames = Frames::default();
        let stream = format!(
            ": keep-alive\n\n{}{}",
            frame(11, &root(0x11)).replace("event: block", "event: head"),
            frame(22, &root(0x22)),
        );

        let events = frames.feed(stream.as_bytes());

        assert_eq!(
            events,
            [BlockEvent {
                slot: 22,
                block_root: [0x22; 32],
            }]
        );
    }

    #[tokio::test]
    async fn reconnects_after_the_stream_closes_and_resumes_emitting() {
        let bn = MockServer::start().await;
        // The first connection carries a block this host never saw, then ends.
        Mock::given(method("GET"))
            .and(path(EVENTS))
            .respond_with(ResponseTemplate::new(200).set_body_raw(frame(11, &root(0x11)), SSE))
            .up_to_n_times(1)
            .with_priority(1)
            .mount(&bn)
            .await;
        // Every connection after it carries one this host did see.
        Mock::given(method("GET"))
            .and(path(EVENTS))
            .respond_with(ResponseTemplate::new(200).set_body_raw(frame(22, &root(0x22)), SSE))
            .with_priority(2)
            .mount(&bn)
            .await;
        let (_spec, spec) = spec_watch();
        let arrivals = Arc::new(Arrivals::new(Arc::new(FakeClock::new()), spec));
        arrivals.arrived([0x22; 32], &Source::Bn);
        let (sender, mut imports) = mpsc::unbounded_channel();

        let events = BlockEvents::spawn(
            format!("{}{EVENTS}?topics=block", bn.uri())
                .parse()
                .unwrap(),
            Backoff::new(Duration::from_millis(5), Duration::from_millis(5)),
            arrivals,
            Arc::new(Imports(sender)),
        );

        assert_eq!(next(&mut imports).await, Some(false));
        assert_eq!(next(&mut imports).await, Some(true));
        events.task.abort();
    }

    #[test]
    fn arrival_records_older_than_eight_slots_are_dropped() {
        let clock = FakeClock::new();
        let (_spec, spec) = spec_watch();
        let arrivals = Arrivals::new(Arc::new(clock.clone()), spec);
        arrivals.arrived([0x33; 32], &Source::Bn);
        clock.advance(Duration::from_secs(10));
        arrivals.arrived([0x44; 32], &Source::Bn);

        clock.advance(Duration::from_secs(90));

        // Eight slots of the 12 s default is 96 s, so the older of the two is past it.
        assert!(!arrivals.imported(&block(1, 0x33)));
        assert!(arrivals.imported(&block(2, 0x44)));
    }

    #[test]
    fn retention_follows_the_spec_snapshot() {
        let clock = FakeClock::new();
        let (sender, spec) = spec_watch();
        let arrivals = Arrivals::new(Arc::new(clock.clone()), spec);
        arrivals.arrived([0x55; 32], &Source::Bn);
        clock.advance(Duration::from_secs(50));
        assert!(arrivals.imported(&block(1, 0x55)));

        // Eight slots of six seconds is 48 s, which the record is already past.
        sender.send_replace(SpecSnapshot {
            seconds_per_slot: 6,
            ..spec::MAINNET
        });

        assert!(!arrivals.imported(&block(2, 0x55)));
    }
}
