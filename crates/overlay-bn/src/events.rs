//! The beacon node's event stream, which is where import time comes from (§12) and the only
//! thing that writes the custody tracker (§6.4, MD-06).
//!
//! `GET /eth/v1/events?topics=...` is Server-Sent Events: a frame per event, fields one to a
//! line, a blank line closing the frame. Four topics are read.
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
//! `execution_payload_gossip` fires inside gossip verification of a Gloas payload envelope, once
//! per envelope, and only for a block the node has in fork choice. From the Gloas fork the
//! columns are built from that payload, so it is what starts a slot's repair deadline (MD-09).
//!
//! What a peer sends cannot reach any of this. That is the whole point: a payload off the wire
//! decodes without being authentic, and the state column repair acts on has to come from the
//! node that validated it.

use std::collections::HashSet;
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
    /// `execution_payload_gossip`: gossip verification accepted this block's payload envelope.
    Envelope {
        /// The slot of the block the envelope reveals the payload for.
        slot: u64,
        /// That block's root.
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
    ///
    /// A `url` whose `topics` leaves out one this module reads is warned about once and used as
    /// given, since a proxy in front of the node may expect exactly that URL.
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
        let missing = missing_topics(&url);
        if !missing.is_empty() {
            tracing::warn!(
                %url,
                ?missing,
                "bn.events_url does not ask for every event topic the sidecar reads, so import \
                 telemetry or column repair goes without them; add them to bn.events_url"
            );
        }
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
    let mut refusals = HashSet::new();
    loop {
        let outcome = read(
            &http,
            &url,
            &arrivals,
            &custody,
            &clock,
            &stats,
            &mut refusals,
        )
        .await;
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
///
/// Any other 4xx is retried too, but said at warn the first time each status is seen, with the
/// start of the body the node gave: a topic an older node does not know, or a URL with no
/// `topics`, would otherwise show only as `overlay_bn_events_connected` stuck at zero.
/// `refusals` holds the statuses already said.
async fn read(
    http: &reqwest::Client,
    url: &Url,
    arrivals: &Arrivals,
    custody: &SharedCustody,
    clock: &Arc<dyn Clock>,
    stats: &Arc<dyn BlockEventStats>,
    refusals: &mut HashSet<StatusCode>,
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
    let status = response.status();
    if status.is_client_error()
        && let Err(err) = response.error_for_status_ref()
    {
        if refusals.insert(status) {
            let body = response.text().await.unwrap_or_default();
            let body = &body[..body.floor_char_boundary(LOGGED_BODY_BYTES)];
            tracing::warn!(
                %url,
                %status,
                body,
                "the beacon node refused its event stream, so import telemetry and column repair \
                 are off for this host; check bn.events_url's topics against this beacon node's \
                 Lighthouse version (restart-required)"
            );
        }
        return Err(err);
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
/// for `on_block`, `on_envelope` and `on_column` and the only callers outside tests are here
/// (MD-06).
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
        Event::Envelope { slot, block_root } => {
            custody.on_envelope(slot, block_root, clock.now());
        }
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

/// The `data` of an `execution_payload_gossip` event. `builder_index` and `block_hash` ride
/// along and are not read.
#[derive(Deserialize)]
struct EnvelopeData {
    slot: String,
    block_root: String,
}

/// The event names the sidecar reads. Every other topic on the stream is skipped, and so is
/// every comment but the one the beacon node writes when it has thrown events away.
const BLOCK: &str = "block";
const BLOCK_GOSSIP: &str = "block_gossip";
const DATA_COLUMN_SIDECAR: &str = "data_column_sidecar";
const EXECUTION_PAYLOAD_GOSSIP: &str = "execution_payload_gossip";

/// Every event topic the sidecar reads, which `bn.events_url` has to ask for.
const TOPICS_READ: [&str; 4] = [
    BLOCK,
    BLOCK_GOSSIP,
    DATA_COLUMN_SIDECAR,
    EXECUTION_PAYLOAD_GOSSIP,
];

/// The topics in [`TOPICS_READ`] that `url` does not ask for. Lighthouse reads every `topics`
/// key, each a comma list.
fn missing_topics(url: &Url) -> Vec<&'static str> {
    let asked: Vec<String> = url
        .query_pairs()
        .filter(|(key, _)| key == "topics")
        .flat_map(|(_, value)| value.split(',').map(str::to_owned).collect::<Vec<String>>())
        .collect();
    TOPICS_READ
        .into_iter()
        .filter(|topic| !asked.iter().any(|asked| asked == topic))
        .collect()
}

/// How much of a refused request's body is logged. A proxy's HTML error page can run to
/// kilobytes, and the first few hundred bytes say what went wrong.
const LOGGED_BODY_BYTES: usize = 512;

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
        Some(EXECUTION_PAYLOAD_GOSSIP) => {
            let data: EnvelopeData = serde_json::from_str(data?).ok()?;
            Some(Event::Envelope {
                slot: data.slot.parse().ok()?,
                block_root: root(&data.block_root)?,
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
    use overlay_core::custody::TRACKED_BLOCKS;
    use overlay_core::events::Source;
    use overlay_core::header::Header;
    use overlay_core::time::{Clock, FakeClock};
    use overlay_core::topic::{SubscriptionSets, Topic};
    use tokio::sync::{mpsc, watch};
    use tokio::time::timeout;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::spec::{SpecSnapshot, spec_watch};

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
    const TOPICS: &str = "?topics=block,block_gossip,data_column_sidecar,execution_payload_gossip";

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

    /// A tracker over `indices`, with the two watches a real one reads and blocks nobody filed.
    fn tracking(indices: &[u8]) -> SharedCustody {
        SharedCustody::new(
            spec_watch().1,
            watch::Sender::new(subscribed(indices)).subscribe(),
            Arc::new(Arrivals::new(Arc::new(FakeClock::new()), spec_watch().1)),
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

    /// A hand-set `bn.events_url` that leaves a topic out turns off what that topic feeds, so
    /// the topics it lacks are named; the shipped default lacks none. Lighthouse takes a comma
    /// list, a repeated `topics` key or both, and a URL with no `topics` at all lacks every one.
    ///
    /// The four names are written out here rather than read from `TOPICS_READ`, so this is the
    /// test that catches a name dropped from that list: the URL with no `topics` would then
    /// lack three names instead of four.
    #[test]
    fn an_events_url_names_the_topics_it_lacks() {
        let at = |query: &str| -> Url {
            format!("http://127.0.0.1:5052/eth/v1/events{query}")
                .parse()
                .unwrap()
        };

        assert_eq!(
            missing_topics(&overlay_core::config::Config::default().bn.events_url),
            Vec::<&str>::new()
        );
        assert_eq!(
            missing_topics(&at("?topics=block,block_gossip,data_column_sidecar")),
            [EXECUTION_PAYLOAD_GOSSIP]
        );
        assert_eq!(
            missing_topics(&at(
                "?topics=block&topics=block_gossip,execution_payload_gossip&topics=data_column_sidecar"
            )),
            Vec::<&str>::new()
        );
        let every = [
            "block",
            "block_gossip",
            "data_column_sidecar",
            "execution_payload_gossip",
        ];
        assert_eq!(missing_topics(&at("?topics=head")), every);
        assert_eq!(missing_topics(&at("")), every);
    }

    /// Every name in `TOPICS_READ` is one the parser reads, so a name the parser skipped is
    /// not asked for and thrown away. This walks the list, so a name dropped from the list is
    /// not caught here; `an_events_url_names_the_topics_it_lacks` compares the list with the
    /// four names written out and catches that.
    #[test]
    fn every_topic_asked_for_is_one_the_parser_reads() {
        for name in TOPICS_READ {
            let data = match name {
                BLOCK | BLOCK_GOSSIP => format!("{{\"slot\":\"1\",\"block\":\"{}\"}}", root(0x01)),
                DATA_COLUMN_SIDECAR => format!(
                    "{{\"block_root\":\"{}\",\"index\":\"1\",\"slot\":\"1\"}}",
                    root(0x01)
                ),
                EXECUTION_PAYLOAD_GOSSIP => format!(
                    "{{\"slot\":\"1\",\"builder_index\":\"9\",\"block_hash\":\"{}\",\"block_root\":\"{}\"}}",
                    root(0x02),
                    root(0x01)
                ),
                other => panic!("{other}: no event body here; add one"),
            };

            assert!(
                event(&format!("event: {name}\ndata: {data}\n")).is_some(),
                "{name}"
            );
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

    /// A block whose bytes went past the sidecar before its `block_gossip` event, as an overlay
    /// delivery does, carries its blob count into the tracker at the event: one with no blobs
    /// opens nothing, so it takes none of the [`TRACKED_BLOCKS`] places from the blocks with
    /// blobs before it (T-127). Reading the gaps would drop it either way; the place it would
    /// have taken is what shows whether the event saw the count.
    #[test]
    fn a_blobless_block_gossip_event_opens_no_entry() {
        let clock = FakeClock::new();
        let (_spec, spec) = spec_watch();
        let arrivals = Arc::new(Arrivals::new(Arc::new(clock.clone()), spec.clone()));
        let custody = SharedCustody::new(
            spec,
            watch::Sender::new(subscribed(&[0, 1])).subscribe(),
            arrivals.clone(),
            Arc::new(()),
        );
        let with_blobs: Vec<(u64, u8)> = (1..).zip(0xb1..).take(TRACKED_BLOCKS).collect();
        let mut stream = String::new();
        for (slot, byte, blobs) in with_blobs
            .iter()
            .map(|&(slot, byte)| (slot, byte, 2))
            .chain([(9, 0xaa, 0)])
        {
            arrivals.saw(
                Some(Header::Block {
                    slot,
                    root: [byte; 32],
                    blobs,
                }),
                &Source::Bn,
            );
            stream.push_str(&gossip_frame(slot, &root(byte)));
        }
        let stats: Arc<dyn BlockEventStats> = Arc::new(());

        for event in Frames::default().feed(stream.as_bytes()) {
            apply(&event, &arrivals, &custody, &clock, &stats);
        }

        let none = custody.column_set([]);
        let gaps = custody.gaps(Duration::ZERO, clock.now(), &none);
        assert_eq!(
            gaps.iter().map(|gap| gap.block_root).collect::<Vec<_>>(),
            with_blobs
                .iter()
                .map(|&(_, byte)| [byte; 32])
                .collect::<Vec<_>>(),
            "{gaps:?}"
        );
    }

    /// The frame Lighthouse v8.3.2 writes when gossip verification accepts a payload envelope,
    /// `SseExecutionPayloadGossip` field for field (`common/eth2/src/types.rs:1221`).
    fn envelope_frame(slot: u64, root: &str) -> String {
        format!(
            "event: execution_payload_gossip\ndata: {{\"slot\":\"{slot}\",\"builder_index\":\"9\",\"block_hash\":\"0x23c03281b3168438a99a7833ceaea27982d36aa7d71b4125e92a05abf23959bc\",\"block_root\":\"{root}\"}}\n\n"
        )
    }

    /// MD-09's anchor. The builder index and the execution block hash ride along and are not
    /// read; the slot and the block root are what custody keys a block by.
    #[test]
    fn execution_payload_gossip_event_parses() {
        let events = Frames::default().feed(envelope_frame(11_511_776, &root(0xbb)).as_bytes());

        assert_eq!(
            events,
            [Event::Envelope {
                slot: 11_511_776,
                block_root: [0xbb; 32],
            }]
        );
    }

    /// On a Gloas slot `block_gossip` records the block and `execution_payload_gossip` is what
    /// starts its deadline, so the envelope event has to reach the tracker.
    #[test]
    fn execution_payload_gossip_reaches_the_tracker() {
        let clock = FakeClock::new();
        let gloas = SpecSnapshot {
            gloas_fork_epoch: 0,
            ..crate::spec::MAINNET
        };
        let custody = SharedCustody::new(
            watch::Sender::new(gloas).subscribe(),
            watch::Sender::new(subscribed(&[0, 1])).subscribe(),
            Arc::new(Arrivals::new(Arc::new(clock.clone()), spec_watch().1)),
            Arc::new(()),
        );
        let none = custody.column_set([]);

        consume(&gossip_frame(9, &root(0xaa)), &custody, &clock);
        assert_eq!(custody.gaps(Duration::ZERO, clock.now(), &none), Vec::new());

        consume(&envelope_frame(9, &root(0xaa)), &custody, &clock);
        let gaps = custody.gaps(Duration::ZERO, clock.now(), &none);
        assert_eq!(
            gaps.first().map(|gap| gap.missing.clone()),
            Some(vec![0, 1]),
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

    /// v8.3.0 dropped `kzg_commitments` and `versioned_hashes` from the `data_column_sidecar`
    /// event, leaving `SseDataColumnSidecar`'s three fields in this order at v8.3.2
    /// (`common/eth2/src/types.rs`). Only those three were ever read.
    #[test]
    fn a_v8_3_column_event_without_commitments_parses() {
        let frame = format!(
            "event: data_column_sidecar\ndata: {{\"block_root\":\"{}\",\"index\":\"127\",\"slot\":\"11511776\"}}\n\n",
            root(0xbb)
        );

        let events = Frames::default().feed(frame.as_bytes());

        assert_eq!(
            events,
            [Event::Column {
                slot: 11_511_776,
                index: 127,
                block_root: [0xbb; 32],
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

    /// A hand-set `bn.events_url` that leaves a topic out is said once at start, naming what it
    /// lacks, and is used exactly as written: the sidecar never rewrites a URL a proxy in front
    /// of the node may expect.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_events_url_missing_a_topic_is_warned_once_and_left_alone() {
        let log = &*crate::testutil::LOG;
        let bn = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(EVENTS))
            .respond_with(ResponseTemplate::new(200).set_body_raw("", SSE))
            .mount(&bn)
            .await;
        let (_spec, spec) = spec_watch();
        let arrivals = Arc::new(Arrivals::new(Arc::new(FakeClock::new()), spec));

        let events = BlockEvents::spawn(
            format!("{}{EVENTS}?topics=block", bn.uri())
                .parse()
                .unwrap(),
            Backoff::new(Duration::from_millis(5), Duration::from_millis(5)),
            arrivals,
            untracked(),
            Arc::new(FakeClock::new()),
            Arc::new(()),
        );
        timeout(PATIENCE, async {
            while bn.received_requests().await.unwrap().len() < 2 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        events.task.abort();

        let requests = bn.received_requests().await.unwrap();
        assert_eq!(requests[0].url.query(), Some("topics=block"));
        let address = bn.address().to_string();
        let text = log.text();
        let lines: Vec<&str> = text
            .lines()
            .filter(|line| line.contains(&address) && line.contains("execution_payload_gossip"))
            .collect();
        assert_eq!(lines.len(), 1, "{text}");
        assert!(lines[0].contains("WARN"), "{}", lines[0]);
        assert!(
            lines[0].contains("add them to bn.events_url"),
            "{}",
            lines[0]
        );
    }

    /// A beacon node that refuses the request, an older one that does not know a topic for
    /// one, is retried, and the refusal is said at warn once per status with that status, the
    /// start of its body and what to check, rather than left to a debug line and a connected
    /// gauge stuck at zero. A proxy's error page can be kilobytes, so only the first 512 bytes
    /// are logged, and the cut lands on a character boundary: the `é` here straddles bytes 511
    /// and 512, so a cut by byte count alone would panic inside the stream task and log nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_refused_event_stream_is_warned_once_per_status_and_retried() {
        let log = &*crate::testutil::LOG;
        let bn = MockServer::start().await;
        let body = format!(
            "unknown topic: refused_topic_t120 {}é{}",
            "x".repeat(477),
            "x".repeat(2_000)
        );
        assert!(!body.is_char_boundary(LOGGED_BODY_BYTES));
        Mock::given(method("GET"))
            .and(path(EVENTS))
            .respond_with(ResponseTemplate::new(400).set_body_string(body.clone()))
            .up_to_n_times(2)
            .mount(&bn)
            .await;
        Mock::given(method("GET"))
            .and(path(EVENTS))
            .respond_with(ResponseTemplate::new(403).set_body_string(body.clone()))
            .mount(&bn)
            .await;
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
        timeout(PATIENCE, async {
            while bn.received_requests().await.unwrap().len() < 4 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        events.task.abort();

        let text = log.text();
        let lines: Vec<&str> = text
            .lines()
            .filter(|line| line.contains("refused_topic_t120"))
            .collect();
        assert_eq!(lines.len(), 2, "{text}");
        let logged = format!(
            "body={:?}",
            &body[..body.floor_char_boundary(LOGGED_BODY_BYTES)]
        );
        for (line, status) in lines.iter().zip(["400", "403"]) {
            assert!(line.contains("WARN"), "{line}");
            assert!(line.contains(status), "{line}");
            assert!(line.contains("bn.events_url"), "{line}");
            assert!(line.contains("restart"), "{line}");
            assert!(line.contains(&logged), "{line}");
        }
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
