//! The beacon node's event stream, which is where import time comes from (§12) and the only
//! thing that writes the custody tracker (§6.4, MD-06).
//!
//! `GET /eth/v1/events?topics=...` is Server-Sent Events: a frame per event, fields one to a
//! line, a blank line closing the frame. Three topics are read.
//!
//! `block` fires when the node has imported the block, which is the moment §2 says arrival is
//! not, so this is where the 200 to 500 ms of `newPayload` and column verification becomes a
//! number an operator can see.
//!
//! `block_gossip` fires inside gossip verification, after the proposer-signature check and after
//! the duplicate check, so it names a block this host's own node accepted. `data_column_sidecar`
//! fires after KZG verification and covers all four ways a column reaches the node: gossip,
//! partial-message merges, the execution layer's `getBlobs` and RPC by root. That last set is
//! why the tracker anchors here and not on the overlay's own receive path: gossipsub never
//! echoes a message back to whoever published it, so a column the sidecar handed the node
//! returns on no wire the sidecar watches, and a tracker fed from the receive path would go
//! blinder the better the overlay worked (MD-06).
//!
//! What a peer sends cannot reach any of this. That is the whole point: a payload off the wire
//! decodes without being authentic, and the state column repair acts on has to come from the
//! node that validated it.

use std::ops::ControlFlow;
use std::str::from_utf8;
use std::sync::Arc;

use overlay_core::backoff::Backoff;
use overlay_core::custody::SharedCustody;
use overlay_core::events::Arrivals;
use overlay_core::time::Clock;
use reqwest::StatusCode;
use serde::Deserialize;
use tokio::task::JoinHandle;
use url::Url;

/// One event the sidecar reads off the stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// `block`: the beacon node has imported this block.
    Imported {
        /// The slot the block was proposed for.
        slot: u64,
        /// Its root, which is what a first-arrival record is filed under.
        block_root: [u8; 32],
    },
    /// `block_gossip`: gossip verification accepted this block.
    Accepted {
        /// The slot the block was proposed for.
        slot: u64,
        /// Its root, which its columns name.
        block_root: [u8; 32],
    },
    /// `data_column_sidecar`: the beacon node has verified this column.
    Column {
        /// The slot the column's block is for.
        slot: u64,
        /// The column index, which is also its subnet.
        index: u8,
        /// The root of the block it belongs to.
        block_root: [u8; 32],
    },
    /// The stream's own notice that it fell behind and threw events away.
    Dropped(u64),
}

/// What the sidecar counts about the event stream. The binary implements it on its metrics; a
/// caller that wants no series passes `()`.
pub trait BlockEventStats: Send + Sync {
    /// Whether the stream is connected right now.
    fn set_connected(&self, connected: bool);
    /// One import event, and whether this host had a record of the block arriving.
    fn imported(&self, matched: bool);
    /// Events the beacon node threw away because this reader fell behind.
    fn lagged(&self, count: u64);
}

impl BlockEventStats for () {
    fn set_connected(&self, _: bool) {}
    fn imported(&self, _: bool) {}
    fn lagged(&self, _: u64) {}
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
        custody: SharedCustody,
        clock: Arc<dyn Clock>,
        stats: Arc<dyn BlockEventStats>,
    ) -> Self {
        // No request timeout: this one is meant to stay open between blocks.
        let http = reqwest::Client::builder()
            .build()
            .expect("plain HTTP client");
        Self {
            task: tokio::spawn(run(http, url, backoff, arrivals, custody, clock, stats)),
        }
    }
}

/// One connection after another, for as long as the task lives.
async fn run(
    http: reqwest::Client,
    url: Url,
    mut backoff: Backoff,
    arrivals: Arc<Arrivals>,
    custody: SharedCustody,
    clock: Arc<dyn Clock>,
    stats: Arc<dyn BlockEventStats>,
) {
    loop {
        let outcome = read(&http, &url, &arrivals, &custody, &clock, &stats).await;
        stats.set_connected(false);
        match outcome {
            // The beacon node closed a stream it had been serving, so the next one is worth
            // trying at once. Anything else gets the delay the last attempt earned.
            Ok(ControlFlow::Continue(())) => backoff.reset(),
            Ok(ControlFlow::Break(())) => return,
            Err(err) => tracing::debug!(%err, %url, "the beacon node's event stream failed"),
        }
        let delay = backoff.next_delay(&mut rand::rng());
        tokio::time::sleep(delay).await;
    }
}

/// One connection, until the beacon node closes it or the read fails. It breaks when the beacon
/// node has no such endpoint, which no amount of retrying will change.
async fn read(
    http: &reqwest::Client,
    url: &Url,
    arrivals: &Arrivals,
    custody: &SharedCustody,
    clock: &Arc<dyn Clock>,
    stats: &Arc<dyn BlockEventStats>,
) -> Result<ControlFlow<()>, reqwest::Error> {
    let response = http.get(url.clone()).send().await?;
    if response.status() == StatusCode::NOT_FOUND {
        tracing::warn!(
            %url,
            "the beacon node has no event stream; import telemetry and column repair are off \
             for this host"
        );
        return Ok(ControlFlow::Break(()));
    }
    // Any other refusal is worth waiting out: a beacon node that is still starting answers 503.
    let mut response = response.error_for_status()?;
    stats.set_connected(true);
    let mut frames = Frames::default();
    while let Some(chunk) = response.chunk().await? {
        for event in frames.feed(&chunk) {
            apply(&event, arrivals, custody, clock.as_ref(), stats);
        }
    }
    Ok(ControlFlow::Continue(()))
}

/// Where one event goes. This is the whole write side of the custody tracker; grep the workspace
/// for `on_block` and `on_column` and the only callers outside tests are here (MD-06).
fn apply(
    event: &Event,
    arrivals: &Arrivals,
    custody: &SharedCustody,
    clock: &dyn Clock,
    stats: &Arc<dyn BlockEventStats>,
) {
    match *event {
        Event::Imported { slot, block_root } => {
            stats.imported(arrivals.imported(slot, block_root));
        }
        Event::Accepted { slot, block_root } => custody.on_block(slot, block_root, clock.now()),
        Event::Column {
            slot,
            index,
            block_root,
        } => custody.on_column(slot, index, block_root),
        Event::Dropped(count) => {
            tracing::warn!(
                count,
                "the beacon node's event stream dropped events; column repair is idle until the \
                 next block"
            );
            stats.lagged(count);
            custody.forget();
        }
    }
}

/// The `data` of a `block` or `block_gossip` event. Lighthouse writes the slot as a quoted
/// decimal and the root as `0x`-prefixed hex; `execution_optimistic` rides along on the first
/// and is not read.
#[derive(Deserialize)]
struct BlockData {
    slot: String,
    block: String,
}

/// The `data` of a `data_column_sidecar` event. The index is quoted like the slot.
#[derive(Deserialize)]
struct ColumnData {
    slot: String,
    index: String,
    block_root: String,
}

/// The event names the sidecar reads. Every other topic on the stream is skipped, and so is
/// every comment but the one the beacon node writes when it has thrown events away.
const BLOCK: &str = "block";
const BLOCK_GOSSIP: &str = "block_gossip";
const DATA_COLUMN_SIDECAR: &str = "data_column_sidecar";

/// What Lighthouse writes as a comment when its broadcast channel lagged and this reader lost
/// events. Everything after the prefix is the count and the word `messages`.
const DROPPED: &str = "error - dropped ";

/// Cuts the beacon node's byte stream into frames and reads the events out of them. A chunk
/// stops wherever the network put it, so whatever follows the last blank line waits for more.
#[derive(Default)]
struct Frames {
    buf: Vec<u8>,
}

impl Frames {
    /// Every event `chunk` completed, in the order the beacon node wrote them.
    fn feed(&mut self, chunk: &[u8]) -> Vec<Event> {
        self.buf.extend_from_slice(chunk);
        let mut events = Vec::new();
        while let Some(blank) = self.buf.windows(2).position(|pair| pair == b"\n\n") {
            let frame: Vec<u8> = self.buf.drain(..blank + 2).collect();
            if let Ok(text) = from_utf8(&frame) {
                events.extend(event(text));
            }
        }
        events
    }
}

/// The event one frame carries, if it is one the sidecar reads.
fn event(frame: &str) -> Option<Event> {
    let mut name = None;
    let mut data = None;
    let mut comment = None;
    for line in frame.lines() {
        // A line with no colon is not a field at all, and one whose name is empty is a comment.
        let Some((field, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" => name = Some(value),
            "data" => data = Some(value),
            "" => comment = Some(value),
            _ => {}
        }
    }
    match name {
        Some(BLOCK) => {
            let data: BlockData = serde_json::from_str(data?).ok()?;
            Some(Event::Imported {
                slot: data.slot.parse().ok()?,
                block_root: root(&data.block)?,
            })
        }
        Some(BLOCK_GOSSIP) => {
            let data: BlockData = serde_json::from_str(data?).ok()?;
            Some(Event::Accepted {
                slot: data.slot.parse().ok()?,
                block_root: root(&data.block)?,
            })
        }
        Some(DATA_COLUMN_SIDECAR) => {
            let data: ColumnData = serde_json::from_str(data?).ok()?;
            Some(Event::Column {
                slot: data.slot.parse().ok()?,
                index: data.index.parse().ok()?,
                block_root: root(&data.block_root)?,
            })
        }
        Some(_) => None,
        None => dropped(comment?),
    }
}

/// The count in the beacon node's own `error - dropped n messages` comment. Every other comment,
/// the keep-alives included, is nothing to report.
fn dropped(comment: &str) -> Option<Event> {
    let rest = comment.strip_prefix(DROPPED)?;
    let count = rest.split_whitespace().next()?;
    Some(Event::Dropped(count.parse().ok()?))
}

/// Reads the `0x`-prefixed 32 bytes the beacon API reports a root as.
fn root(text: &str) -> Option<[u8; 32]> {
    let digits = text.strip_prefix("0x")?.as_bytes();
    let mut root = [0; 32];
    if digits.len() != 2 * root.len() {
        return None;
    }
    for (byte, pair) in root.iter_mut().zip(digits.as_chunks::<2>().0) {
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
    use overlay_core::time::{Clock, FakeClock};
    use overlay_core::topic::{SubscriptionSets, Topic};
    use tokio::sync::{mpsc, watch};
    use tokio::time::timeout;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::spec::spec_watch;

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

        fn lagged(&self, _: u64) {}
    }

    /// The whole stream the sidecar asks for, so a test connects the way a sidecar does.
    const TOPICS: &str = "?topics=block,block_gossip,data_column_sidecar";

    /// A tracker for a test that is not about the tracker.
    fn untracked() -> SharedCustody {
        tracking(&[])
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

    /// The frame Lighthouse writes when gossip verification accepts a block, which is after the
    /// proposer-signature check and after the duplicate check.
    fn gossip_frame(slot: u64, root: &str) -> String {
        format!("event: block_gossip\ndata: {{\"slot\":\"{slot}\",\"block\":\"{root}\"}}\n\n")
    }

    /// The frame it writes when a data column sidecar passes KZG verification, whichever of the
    /// four sources it came from.
    fn column_frame(slot: u64, index: u8, root: &str) -> String {
        format!(
            "event: data_column_sidecar\ndata: {{\"block_root\":\"{root}\",\"index\":\"{index}\",\"slot\":\"{slot}\"}}\n\n"
        )
    }

    /// A beacon node subscribed to the column subnets `indices` names.
    fn subscribed(indices: &[u8]) -> SubscriptionSets {
        let advertised = indices
            .iter()
            .map(|index| {
                Topic::parse(&format!(
                    "/eth2/6a95a1a9/data_column_sidecar_{index}/ssz_snappy"
                ))
                .expect("a topic in the only shape the parser takes")
            })
            .collect();
        SubscriptionSets {
            advertised,
            ..SubscriptionSets::default()
        }
    }

    /// A tracker over `indices`, with the two watches a real one reads.
    fn tracking(indices: &[u8]) -> SharedCustody {
        SharedCustody::new(
            spec_watch().1,
            watch::Sender::new(subscribed(indices)).subscribe(),
            Arc::new(()),
        )
    }

    /// Feeds `stream` through the reassembler and the dispatch, as one connection would.
    fn consume(stream: &str, custody: &SharedCustody, clock: &FakeClock) {
        let (_spec, spec) = spec_watch();
        let arrivals = Arc::new(Arrivals::new(Arc::new(clock.clone()), spec));
        let stats: Arc<dyn BlockEventStats> = Arc::new(());
        for event in Frames::default().feed(stream.as_bytes()) {
            apply(&event, &arrivals, custody, clock, &stats);
        }
    }

    /// The two events the tracker is built on. `block_gossip` opens the entry and fixes what the
    /// beacon node is owed; `data_column_sidecar` takes a column back out of it.
    #[test]
    fn block_gossip_and_data_column_events_reach_the_tracker() {
        let clock = FakeClock::new();
        let custody = tracking(&[0, 1]);

        consume(
            &format!(
                "{}{}",
                gossip_frame(9, &root(0xaa)),
                column_frame(9, 1, &root(0xaa))
            ),
            &custody,
            &clock,
        );

        let none = custody.column_set([]);
        let gaps = custody.gaps(Duration::ZERO, clock.now(), &none);
        assert_eq!(
            gaps.first().map(|gap| gap.missing.clone()),
            Some(vec![0]),
            "{gaps:?}"
        );
    }

    /// A reader that falls behind loses events the beacon node will not send again, so a column
    /// it holds can go on being reported missing for the rest of the slot and spend the budget
    /// the columns it really lacks need. Nothing says which events went, so the tracker forgets
    /// what it had and waits for the next block, and the beacon node's own count of what it
    /// threw away is a series rather than a line nobody reads.
    #[test]
    fn a_lagging_event_stream_idles_the_tracker_loudly() {
        let clock = FakeClock::new();
        let custody = tracking(&[0, 1]);
        let (sender, mut lagged) = mpsc::unbounded_channel();
        let stats: Arc<dyn BlockEventStats> = Arc::new(Lags(sender));
        let (_spec, spec) = spec_watch();
        let arrivals = Arc::new(Arrivals::new(Arc::new(clock.clone()), spec));
        let stream = format!(
            "{}:error - dropped 12 messages\n\n",
            gossip_frame(9, &root(0xaa))
        );

        for event in Frames::default().feed(stream.as_bytes()) {
            apply(&event, &arrivals, &custody, &clock, &stats);
        }

        let none = custody.column_set([]);
        assert_eq!(custody.gaps(Duration::ZERO, clock.now(), &none), Vec::new());
        assert_eq!(lagged.try_recv(), Ok(12));
    }

    /// A stats sink that hands every lag straight back to the test.
    struct Lags(mpsc::UnboundedSender<u64>);

    impl BlockEventStats for Lags {
        fn set_connected(&self, _: bool) {}

        fn imported(&self, _: bool) {}

        fn lagged(&self, count: u64) {
            let _ = self.0.send(count);
        }
    }

    #[test]
    fn parses_block_event_slot_and_root() {
        let mut frames = Frames::default();

        let events = frames.feed(frame(7_654_321, &root(0xab)).as_bytes());

        assert_eq!(
            events,
            [Event::Imported {
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
            [Event::Imported {
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
            format!("{}{EVENTS}{TOPICS}", bn.uri()).parse().unwrap(),
            Backoff::new(Duration::from_millis(5), Duration::from_millis(5)),
            arrivals,
            untracked(),
            Arc::new(FakeClock::new()),
            Arc::new(Imports(sender)),
        );

        assert_eq!(next(&mut imports).await, Some(false));
        assert_eq!(next(&mut imports).await, Some(true));
        events.task.abort();
    }

    #[tokio::test]
    async fn a_beacon_node_without_the_event_endpoint_is_not_retried() {
        // No mock is mounted, so every request is answered 404.
        let bn = MockServer::start().await;
        let (_spec, spec) = spec_watch();
        let arrivals = Arc::new(Arrivals::new(Arc::new(FakeClock::new()), spec));

        let events = BlockEvents::spawn(
            format!("{}{EVENTS}{TOPICS}", bn.uri()).parse().unwrap(),
            Backoff::new(Duration::from_millis(5), Duration::from_millis(5)),
            arrivals,
            untracked(),
            Arc::new(FakeClock::new()),
            Arc::new(()),
        );

        timeout(PATIENCE, events.task).await.unwrap().unwrap();
        assert_eq!(bn.received_requests().await.unwrap().len(), 1);
    }
}
