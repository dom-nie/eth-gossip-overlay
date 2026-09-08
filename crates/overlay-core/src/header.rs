//! What the overlay reads out of a large gossip payload, and how it reaches the crates that
//! need it without either of them linking a consensus type (§7, D05, T-083).
//!
//! Two things want the same two numbers. The recent store indexes a column by `(block_root,
//! index)` so a peer that never saw it can ask for it, and T-044's `first_arrival` names the
//! slot and root so an operator can follow one block across the fleet. Both sit on the receive
//! path, so the payload is read once, where it is stored, and the answer is handed on.
//!
//! The decoder itself is `overlay_bn::decode::Headers` behind the `column-repair` feature, and
//! the binary is what installs it. Nothing here requires one: without a decoder every payload is
//! stored and forwarded exactly as before, no column is indexed by identity and no event carries
//! a slot, which is what lets `overlay-bn` build and emit that event with the feature off.

use crate::topic::Topic;

/// The header of a payload on one of the two topics column repair tracks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Header {
    /// A `beacon_block`.
    Block {
        /// The slot the block is for.
        slot: u64,
        /// Its block root, which is what its columns name.
        root: [u8; 32],
    },
    /// A `data_column_sidecar_{index}`.
    Column {
        /// The slot the column's block is for.
        slot: u64,
        /// The column index, which is also its subnet.
        index: u8,
        /// The root of the block the column belongs to.
        block_root: [u8; 32],
    },
}

impl Header {
    /// The slot this header is for, which both forms carry.
    pub fn slot(&self) -> u64 {
        match self {
            Self::Block { slot, .. } | Self::Column { slot, .. } => *slot,
        }
    }

    /// The block this header is about: the block itself, or the block a column belongs to.
    pub fn block_root(&self) -> [u8; 32] {
        match self {
            Self::Block { root, .. } => *root,
            Self::Column { block_root, .. } => *block_root,
        }
    }
}

/// Reads the header of a gossip payload.
pub trait HeaderDecoder: Send + Sync {
    /// The header `payload` carries on `topic`. `None` for a topic with no header worth reading
    /// and for a payload that is not the object its topic names, which is every byte a peer can
    /// make up.
    fn header(&self, topic: &Topic, payload: &[u8]) -> Option<Header>;
}
