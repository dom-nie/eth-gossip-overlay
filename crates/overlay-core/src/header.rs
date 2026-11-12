//! What the overlay reads out of a large gossip payload, and how it reaches the crates that
//! need it without either of them linking a consensus type (§7, D05, T-083).
//!
//! Two things want the same two numbers. The recent store indexes a column by `(block_root,
//! index)` so a peer that never saw it can ask for it, and T-044's `first_arrival` names the
//! slot and root so an operator can follow one block across the fleet. Both sit on the receive
//! path, so the payload is read once, where it is stored, and the answer is handed on.
//!
//! The bytes handed over are already decompressed. The receive path decompresses to compute the
//! message id (T-006) and the beacon node's own path has the payload validated, so a decoder
//! that took the wire form would decompress a second time, once per large message, on the path
//! this project exists to shorten.
//!
//! The decoder itself is `overlay_bn::decode::Headers`, and the binary is what installs it.
//! Nothing here requires one: without a decoder every payload is stored and forwarded exactly as
//! before, no column is indexed by identity and no event carries a slot.

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
        /// How many blob KZG commitments it carries. Zero means no column of it exists, so
        /// custody has nothing to wait for (T-127).
        blobs: usize,
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
    /// The header the decompressed `ssz` carries on `topic`. `None` for a topic with no header
    /// worth reading and for bytes that are not the object its topic names, which is every byte
    /// a peer can make up.
    fn header(&self, topic: &Topic, ssz: &[u8]) -> Option<Header>;
}

/// Where a `SignedBeaconBlock`'s `message` starts: past the 4-byte offset that says so and the
/// 96-byte signature, which are the whole of its fixed part.
const MESSAGE_AT: u32 = 100;

/// Where `parent_root` sits: `slot` and `proposer_index`, 8 bytes each, open every fork's
/// `BeaconBlock`, so the root follows at the same place whatever the fork or preset.
const PARENT_ROOT_AT: std::ops::Range<usize> = 116..148;

/// The parent root of the `SignedBeaconBlock` `ssz` carries, read at its fixed offset with no
/// consensus type involved (T-101, D42). `None` for bytes that are not a signed block: the
/// first offset names where `message` starts, and nothing else puts it at 100. A payload the
/// beacon node cannot decode is one it opens no parent lookup for, so there is nothing to ask
/// about it.
pub fn block_parent_root(ssz: &[u8]) -> Option<[u8; 32]> {
    if ssz.get(..4)? != MESSAGE_AT.to_le_bytes() {
        return None;
    }
    ssz.get(PARENT_ROOT_AT)?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shortest bytes that carry a parent root: the offset to `message`, then `[7; 32]`
    /// where the root sits.
    fn signed_block(message_at: u32) -> Vec<u8> {
        let mut ssz = vec![0; 148];
        ssz[..4].copy_from_slice(&message_at.to_le_bytes());
        ssz[116..148].fill(7);
        ssz
    }

    #[test]
    fn block_parent_root_reads_the_parent_at_its_fixed_offset() {
        assert_eq!(block_parent_root(&signed_block(100)), Some([7; 32]));

        // Not a signed block: nothing else puts its first offset anywhere but 100.
        assert_eq!(block_parent_root(&signed_block(101)), None);
        // One byte short of the root.
        assert_eq!(block_parent_root(&signed_block(100)[..147]), None);
    }
}
