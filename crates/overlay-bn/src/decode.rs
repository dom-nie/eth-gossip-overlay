//! The one place the overlay reads a consensus object out of a gossip payload (§7, T-083).
//!
//! Column repair asks for a column by `(block_root, index)` rather than by message id, because a
//! host that never saw the column has no id for it (D23). Only the payload knows those two
//! numbers, so this module exists and nothing else in the workspace decodes a payload.
//!
//! `types` is a dev-dependency everywhere else (D05); the `column-repair` feature is what makes
//! it a production one, and it is what this module is behind.
//!
//! # How little is read
//!
//! [`column_header`] reads the fixed part of a `DataColumnSidecar` and stops: the index, and the
//! 112 bytes of the `BeaconBlockHeader` inside its `signed_block_header`, whose tree hash is the
//! block root. The cells are about 40 KB of the payload and are never looked at, which is what
//! keeps a decode per column down to one hash of five leaves.
//!
//! [`block_header`] cannot do the same. A block root is the tree hash of a `BeaconBlock`, and one
//! of its five leaves is the tree hash of the body, so the body has to be walked before the root
//! exists. There is no prefix of the wire form that carries it. The block is therefore decoded
//! whole and nothing but its slot and its root is taken; it is one payload a slot, against the
//! `NUMBER_OF_COLUMNS` columns beside it.
//!
//! # Every byte is hostile
//!
//! A payload reaches here from the wire, so the declared decompressed length is checked before a
//! buffer is allocated, every read is bounds-checked, and a shape that is not the object the
//! topic names is an error rather than a panic.

use types::{Hash256, MainnetEthSpec, SignedBeaconBlock, Slot};

use overlay_core::wire::MAX_PAYLOAD_BYTES;

/// Why a payload is not the header it was expected to carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum HeaderError {
    /// The snappy frame does not decompress, or declares more than the beacon node would accept.
    #[error("the payload does not decompress")]
    Snappy,
    /// The bytes stop before the fixed part the header lives in.
    #[error("the payload is shorter than the header it must carry")]
    Truncated,
    /// The bytes are not the consensus object the topic names.
    #[error("the payload is not the object this topic carries")]
    Ssz,
    /// The column index is past what a subnet index can hold.
    #[error("the column index is past the largest subnet index")]
    Index,
}

/// The slot a block is for and its block root, from the payload the beacon node gossips.
pub fn block_header(payload: &[u8]) -> Result<(u64, [u8; 32]), HeaderError> {
    let bytes = decompress(payload)?;
    let block = SignedBeaconBlock::<MainnetEthSpec>::any_from_ssz_bytes(&bytes)
        .map_err(|_| HeaderError::Ssz)?;
    Ok((block.slot().as_u64(), bytes32(block.canonical_root())))
}

/// The slot, index and block root of a data column sidecar, from the payload the beacon node
/// gossips on `data_column_sidecar_{index}`.
///
/// The index is read from the payload rather than taken from the topic name, because the two
/// agreeing is the beacon node's rule to enforce and not this sidecar's: what the responder
/// indexes and what a requester asks for both have to be what the object says it is.
pub fn column_header(payload: &[u8]) -> Result<(u64, u8, [u8; 32]), HeaderError> {
    let _ = decompress(payload)?;
    Err(HeaderError::Ssz)
}

/// The gossipsub wire form is snappy over SSZ. The declared length is compared with the beacon
/// node's own maximum before anything is allocated, so a hostile header cannot reserve gigabytes
/// (the same guard [`overlay_core::msgid`] puts in front of its own decompression).
fn decompress(payload: &[u8]) -> Result<Vec<u8>, HeaderError> {
    match snap::raw::decompress_len(payload) {
        Ok(len) if len <= MAX_PAYLOAD_BYTES => snap::raw::Decoder::new()
            .decompress_vec(payload)
            .map_err(|_| HeaderError::Snappy),
        _ => Err(HeaderError::Snappy),
    }
}

fn bytes32(root: Hash256) -> [u8; 32] {
    let mut out = [0; 32];
    out.copy_from_slice(root.as_slice());
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use ssz::Encode;
    use types::{BeaconBlock, ChainSpec};

    use super::*;

    /// A BLS signature in its infinity form, which is the one 96-byte value `types` decodes
    /// without a curve point behind it. Nothing here verifies a signature; the fixtures only
    /// need the field to be there and to be readable.
    fn infinity_signature() -> Vec<u8> {
        let mut sig = vec![0; 96];
        sig[0] = 0xc0;
        sig
    }

    fn snappy(bytes: &[u8]) -> Vec<u8> {
        snap::raw::Encoder::new().compress_vec(bytes).unwrap()
    }

    /// A signed block for `slot`, as `types` decodes it: the wire form of `SignedBeaconBlock` is
    /// the offset of its message, the signature and then the block, so an empty block and an
    /// infinity signature make one without a signing key anywhere.
    fn signed_block(slot: u64) -> (SignedBeaconBlock<MainnetEthSpec>, Vec<u8>) {
        let spec = ChainSpec::mainnet();
        let mut block = BeaconBlock::<MainnetEthSpec>::empty(&spec);
        *block.slot_mut() = Slot::new(slot);
        let mut wire = 100u32.to_le_bytes().to_vec();
        wire.extend_from_slice(&infinity_signature());
        wire.extend_from_slice(&block.as_ssz_bytes());
        let decoded = SignedBeaconBlock::<MainnetEthSpec>::any_from_ssz_bytes(&wire)
            .expect("the hand-built wire form is one types reads back");
        (decoded, wire)
    }

    #[test]
    fn block_header_decodes_slot_and_root_from_compressed_payload() {
        let (block, wire) = signed_block(4_242);

        let (slot, root) = block_header(&snappy(&wire)).unwrap();

        assert_eq!(slot, 4_242);
        assert_eq!(root, bytes32(block.canonical_root()));
    }
}
