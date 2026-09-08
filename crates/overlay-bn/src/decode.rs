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

use types::{BeaconBlockHeader, Hash256, MainnetEthSpec, SignedBeaconBlock, Slot};

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

/// Where a `DataColumnSidecar`'s `signed_block_header` starts: the `index`, then the three
/// offsets of `column`, `kzg_commitments` and `kzg_proofs`.
const COLUMN_HEADER_AT: usize = 8 + 3 * 4;

/// A `BeaconBlockHeader`: slot, proposer index and three roots.
const BEACON_BLOCK_HEADER_LEN: usize = 8 + 8 + 3 * 32;

/// The fixed part up to the end of `signed_block_header`, which is the header plus a signature.
/// What follows it, the inclusion proof, is sized by a preset and is not read here.
const COLUMN_FIXED_MIN: usize = COLUMN_HEADER_AT + BEACON_BLOCK_HEADER_LEN + 96;

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
    let bytes = decompress(payload)?;
    let fixed = bytes
        .get(..COLUMN_FIXED_MIN)
        .ok_or(HeaderError::Truncated)?;
    // The first offset of an SSZ container is the length of its fixed part, so a payload whose
    // variable section starts inside the header is not a Fulu column sidecar at all. A Gloas one,
    // whose fixed part is 56 bytes, is refused here rather than read as if it were.
    let column_at = u32_at(fixed, 8) as usize;
    if column_at < COLUMN_FIXED_MIN || column_at > bytes.len() {
        return Err(HeaderError::Ssz);
    }
    let index = u8::try_from(u64_at(fixed, 0)).map_err(|_| HeaderError::Index)?;
    let header = BeaconBlockHeader {
        slot: Slot::new(u64_at(fixed, COLUMN_HEADER_AT)),
        proposer_index: u64_at(fixed, COLUMN_HEADER_AT + 8),
        parent_root: root_at(fixed, COLUMN_HEADER_AT + 16),
        state_root: root_at(fixed, COLUMN_HEADER_AT + 48),
        body_root: root_at(fixed, COLUMN_HEADER_AT + 80),
    };
    Ok((
        header.slot.as_u64(),
        index,
        bytes32(header.canonical_root()),
    ))
}

/// A slice the caller has already taken with `get`, read at `at`, so no range here can be out
/// of bounds.
fn u64_at(fixed: &[u8], at: usize) -> u64 {
    let mut eight = [0; 8];
    eight.copy_from_slice(&fixed[at..at + 8]);
    u64::from_le_bytes(eight)
}

fn u32_at(fixed: &[u8], at: usize) -> u32 {
    let mut four = [0; 4];
    four.copy_from_slice(&fixed[at..at + 4]);
    u32::from_le_bytes(four)
}

fn root_at(fixed: &[u8], at: usize) -> Hash256 {
    Hash256::from_slice(&fixed[at..at + 32])
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
    use ssz::{Decode, Encode};
    use types::{BeaconBlock, ChainSpec, DataColumnSidecarFulu};

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

    /// A column sidecar for `slot` carrying `index`, as `types` decodes it. The variable
    /// lists are empty, so all three offsets are the length of the fixed part and the wire
    /// form ends where the fixed part does: what the decoder reads is exactly what is here.
    fn column_sidecar(slot: u64, index: u64) -> (DataColumnSidecarFulu<MainnetEthSpec>, Vec<u8>) {
        const PROOF_BYTES: usize = 4 * 32;
        let fixed = COLUMN_FIXED_MIN + PROOF_BYTES;
        let header = BeaconBlockHeader {
            slot: Slot::new(slot),
            proposer_index: 11,
            parent_root: Hash256::repeat_byte(1),
            state_root: Hash256::repeat_byte(2),
            body_root: Hash256::repeat_byte(3),
        };
        let mut wire = index.to_le_bytes().to_vec();
        for _ in 0..3 {
            wire.extend_from_slice(&(fixed as u32).to_le_bytes());
        }
        wire.extend_from_slice(&header.as_ssz_bytes());
        wire.extend_from_slice(&infinity_signature());
        wire.extend_from_slice(&[0; PROOF_BYTES]);
        let decoded = DataColumnSidecarFulu::<MainnetEthSpec>::from_ssz_bytes(&wire)
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

    #[test]
    fn column_header_decodes_slot_index_and_root() {
        let (sidecar, wire) = column_sidecar(9_001, 200);

        let (slot, index, block_root) = column_header(&snappy(&wire)).unwrap();

        assert_eq!(slot, sidecar.slot().as_u64());
        assert_eq!(u64::from(index), sidecar.index);
        assert_eq!(block_root, bytes32(sidecar.block_root()));
    }

    /// Test 3 of the ticket: nothing a peer or a beacon node can send takes the process down.
    /// Every prefix of a real payload is tried twice, once as the truncated object and once as
    /// a truncated snappy frame, and each has to come back as an error.
    #[test]
    fn decoder_rejects_truncated_payload_without_panic() {
        let (_, block) = signed_block(1);
        let (_, column) = column_sidecar(1, 0);

        for wire in [&block, &column] {
            let whole = snappy(wire);
            for cut in 0..wire.len() {
                assert!(block_header(&snappy(&wire[..cut])).is_err(), "block {cut}");
                assert!(column_header(&snappy(&wire[..cut])).is_err(), "column {cut}");
            }
            for cut in 0..whole.len() {
                assert!(block_header(&whole[..cut]).is_err(), "block frame {cut}");
                assert!(column_header(&whole[..cut]).is_err(), "column frame {cut}");
            }
        }
    }
}
