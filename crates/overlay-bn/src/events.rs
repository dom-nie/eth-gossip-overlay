//! The beacon node's block event stream, which is the only place import time comes from (§12).
//!
//! `GET /eth/v1/events?topics=block` is Server-Sent Events: a frame per event, fields one to a
//! line, a blank line closing the frame. Lighthouse fires a `block` event when it has imported
//! the block, which is the moment §2 says arrival is not, so this is where the 200 to 500 ms of
//! `newPayload` and column verification becomes a number an operator can see.

use std::str::from_utf8;

use serde::Deserialize;

/// One `block` event: the beacon node has imported this block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockEvent {
    /// The slot the block was proposed for.
    pub slot: u64,
    /// Its root, which is what a first-arrival record is filed under.
    pub block_root: [u8; 32],
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
    use super::*;

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
}
