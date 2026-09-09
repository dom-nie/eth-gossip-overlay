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

use overlay_core::header::{Header, HeaderDecoder};
use overlay_core::topic::{Topic, TopicKind};
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

/// `kzg_commitments_inclusion_proof`, which closes the fixed part. Its depth is four under every
/// preset Lighthouse ships, mainnet, minimal and gnosis alike, so the fixed part of a Fulu column
/// sidecar is one length on every network.
const PROOF_BYTES: usize = 4 * 32;

/// The whole fixed part: the index, the three offsets, `signed_block_header` and the inclusion
/// proof. Only the first 132 bytes of it are read, but a sidecar's first offset is exactly this,
/// which is what a payload is checked against before anything is read out of it.
const COLUMN_FIXED_LEN: usize = COLUMN_HEADER_AT + BEACON_BLOCK_HEADER_LEN + 96 + PROOF_BYTES;

/// The slot a block is for and its block root, from the payload the beacon node gossips.
///
/// This is the compressed-payload form the ticket names and the one the tests here drive; the
/// receive path holds the payload already decompressed and goes through [`Headers`] to the inner
/// function, so it decompresses once for the id and the header together (T-006).
///
/// Two things a reader should know about the numbers this produces. The fork variant is found by
/// trying each in turn, because nothing on the wire names it and the sidecar holds no fork
/// schedule. A block read as the wrong variant gives a root no column belongs to, and that costs
/// a slot of column repair rather than one request: the block opens a tracker entry under that
/// root while every real column of it files under the right one, so the entry reports its whole
/// expected set missing and the scheduler asks for up to the threshold every slot until the
/// entry ages out. And a tree hash depends on the preset, through the list lengths it merkleises
/// to, so the root is mainnet's; a network on another preset would need the preset with it,
/// which is a change to what `SpecSnapshot` carries rather than to this function.
pub fn block_header(payload: &[u8]) -> Result<(u64, [u8; 32]), HeaderError> {
    block_header_ssz(&decompress(payload)?)
}

/// The same from bytes already decompressed, which is what the receive path holds (T-006).
fn block_header_ssz(ssz: &[u8]) -> Result<(u64, [u8; 32]), HeaderError> {
    let block = SignedBeaconBlock::<MainnetEthSpec>::any_from_ssz_bytes(ssz)
        .map_err(|_| HeaderError::Ssz)?;
    Ok((block.slot().as_u64(), bytes32(block.canonical_root())))
}

/// The slot, index and block root of a data column sidecar, from the payload the beacon node
/// gossips on `data_column_sidecar_{index}`.
///
/// The compressed-payload form, as [`block_header`] is, and with the same split behind it.
///
/// The index is read from the payload rather than taken from the topic name, because the two
/// agreeing is the beacon node's rule to enforce and not this sidecar's: what the responder
/// indexes and what a requester asks for both have to be what the object says it is.
pub fn column_header(payload: &[u8]) -> Result<(u64, u8, [u8; 32]), HeaderError> {
    column_header_ssz(&decompress(payload)?)
}

/// The same from bytes already decompressed, which is what the receive path holds (T-006).
fn column_header_ssz(bytes: &[u8]) -> Result<(u64, u8, [u8; 32]), HeaderError> {
    let fixed = bytes
        .get(..COLUMN_FIXED_LEN)
        .ok_or(HeaderError::Truncated)?;
    // The first offset of an SSZ container is the length of its fixed part, and a Fulu column
    // sidecar's is [`COLUMN_FIXED_LEN`] on every preset. Anything else is not one: a Gloas
    // sidecar, whose fixed part is 56 bytes, and every payload a peer made up, both refused here
    // rather than read as if the header were where this expects it. The other two offsets are
    // read for their bounds only, which is what tells a sidecar cut short from a whole one; the
    // bytes they point at are the cells and the commitments, and nothing here looks at those.
    let bounds = [
        COLUMN_FIXED_LEN,
        u32_at(fixed, 8) as usize,
        u32_at(fixed, 12) as usize,
        u32_at(fixed, 16) as usize,
        bytes.len(),
    ];
    if !bounds.is_sorted() || bounds[1] != COLUMN_FIXED_LEN {
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

/// The two decoders behind the trait `overlay-core` holds them by, so the recent store and the
/// custody tracker reach them without either crate linking `types` (D05).
///
/// A payload that is not what its topic names is `None` and a debug line, not an error the
/// receive path acts on: the beacon node validated the message, so a disagreement here means
/// this sidecar and its node read the fork differently, and the message still travels.
#[derive(Clone, Copy, Debug, Default)]
pub struct Headers;

impl HeaderDecoder for Headers {
    fn header(&self, topic: &Topic, ssz: &[u8]) -> Option<Header> {
        match topic.kind() {
            TopicKind::BeaconBlock => match block_header_ssz(ssz) {
                Ok((slot, root)) => Some(Header::Block { slot, root }),
                Err(error) => {
                    tracing::debug!(%topic, %error, "a block payload carries no header");
                    None
                }
            },
            TopicKind::DataColumnSidecar(_) => match column_header_ssz(ssz) {
                Ok((slot, index, block_root)) => Some(Header::Column {
                    slot,
                    index,
                    block_root,
                }),
                Err(error) => {
                    tracing::debug!(%topic, %error, "a column payload carries no header");
                    None
                }
            },
            _ => None,
        }
    }
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
    use std::sync::Arc;

    use overlay_core::msgid::MessageId;
    use overlay_core::recent::{RECENT_MAX_BYTES, RECENT_TTL, RecentLarge, SharedRecentLarge};
    use overlay_core::time::{Clock, FakeClock};
    use ssz::{Decode, Encode};
    use types::{BeaconBlock, BeaconBlockFulu, ChainSpec, DataColumnSidecarFulu, EmptyBlock};

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

    /// A signed block for `slot` of the fork the network runs after Fusaka, which is the one a
    /// column sidecar belongs to.
    fn fulu_block(slot: u64) -> (SignedBeaconBlock<MainnetEthSpec>, Vec<u8>) {
        let spec = ChainSpec::mainnet();
        signed_block(BeaconBlock::Fulu(BeaconBlockFulu::empty(&spec)), slot)
    }

    /// The same for the genesis fork, which has none of Fulu's body and so is the shape the
    /// decoder is most likely to confuse it with.
    fn base_block(slot: u64) -> (SignedBeaconBlock<MainnetEthSpec>, Vec<u8>) {
        let spec = ChainSpec::mainnet();
        signed_block(BeaconBlock::<MainnetEthSpec>::empty(&spec), slot)
    }

    /// `block` at `slot`, as `types` decodes it: the wire form of `SignedBeaconBlock` is the
    /// offset of its message, the signature and then the block, so an empty block and an
    /// infinity signature make one without a signing key anywhere.
    ///
    /// The variant is asserted on the way back, because `block_header` finds the fork by trying
    /// each in turn and a fixture that took whatever came out could not tell a wrong choice from
    /// a right one.
    fn signed_block(
        mut block: BeaconBlock<MainnetEthSpec>,
        slot: u64,
    ) -> (SignedBeaconBlock<MainnetEthSpec>, Vec<u8>) {
        let fork = block.to_ref().fork_name_unchecked();
        *block.slot_mut() = Slot::new(slot);
        let mut wire = 100u32.to_le_bytes().to_vec();
        wire.extend_from_slice(&infinity_signature());
        wire.extend_from_slice(&block.as_ssz_bytes());
        let decoded = SignedBeaconBlock::<MainnetEthSpec>::any_from_ssz_bytes(&wire)
            .expect("the hand-built wire form is one types reads back");
        assert_eq!(
            decoded.fork_name_unchecked(),
            fork,
            "the decoder read the block back as a different fork"
        );
        (decoded, wire)
    }

    /// A column sidecar for `slot` carrying `index`, as `types` decodes it.
    ///
    /// It carries one real cell, one commitment and one proof, so the body behind the fixed part
    /// is the 2 KB shape a mainnet sidecar has rather than nothing: the whole point of the
    /// decoder is that it stops at the fixed part, and a fixture with an empty body would let a
    /// decoder that read the lot pass.
    fn column_sidecar(slot: u64, index: u64) -> (DataColumnSidecarFulu<MainnetEthSpec>, Vec<u8>) {
        column_sidecar_of(
            BeaconBlockHeader {
                slot: Slot::new(slot),
                proposer_index: 11,
                parent_root: Hash256::repeat_byte(1),
                state_root: Hash256::repeat_byte(2),
                body_root: Hash256::repeat_byte(3),
            },
            index,
        )
    }

    /// The same for a header a caller already has, so a block and one of its columns can name
    /// the same root the way they do on a real network.
    fn column_sidecar_of(
        header: BeaconBlockHeader,
        index: u64,
    ) -> (DataColumnSidecarFulu<MainnetEthSpec>, Vec<u8>) {
        const CELL_BYTES: usize = 2048;
        const KZG_BYTES: usize = 48;
        let offsets = [
            COLUMN_FIXED_LEN,
            COLUMN_FIXED_LEN + CELL_BYTES,
            COLUMN_FIXED_LEN + CELL_BYTES + KZG_BYTES,
        ];
        let mut wire = index.to_le_bytes().to_vec();
        for offset in offsets {
            wire.extend_from_slice(&(offset as u32).to_le_bytes());
        }
        wire.extend_from_slice(&header.as_ssz_bytes());
        wire.extend_from_slice(&infinity_signature());
        wire.extend_from_slice(&[0; PROOF_BYTES]);
        wire.extend_from_slice(&[7; CELL_BYTES]);
        wire.extend_from_slice(&[0xc0; KZG_BYTES]);
        wire.extend_from_slice(&[0xc0; KZG_BYTES]);
        let decoded = DataColumnSidecarFulu::<MainnetEthSpec>::from_ssz_bytes(&wire)
            .expect("the hand-built wire form is one types reads back");
        (decoded, wire)
    }

    #[test]
    fn block_header_decodes_slot_and_root_from_compressed_payload() {
        for (block, wire) in [base_block(4_242), fulu_block(4_242)] {
            let (slot, root) = block_header(&snappy(&wire)).unwrap();

            assert_eq!(slot, 4_242);
            assert_eq!(root, bytes32(block.canonical_root()));
        }
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
    ///
    /// Every prefix of a real payload is tried twice, once as the truncated object and once as a
    /// truncated snappy frame. A prefix is either an error or a shorter object of the same shape
    /// whose header is the one the whole payload carries, which is what a column cut at one of
    /// its own offsets is. What none of them may do is panic, or answer with a slot or a root
    /// that is not in the bytes.
    #[test]
    fn decoder_rejects_truncated_payload_without_panic() {
        let (_, block) = fulu_block(1);
        let (_, column) = column_sidecar(1, 0);
        let whole_block = block_header(&snappy(&block));
        let whole_column = column_header(&snappy(&column));

        for wire in [&block, &column] {
            let frame = snappy(wire);
            for cut in 0..wire.len() {
                let short = snappy(&wire[..cut]);
                let block_read = block_header(&short);
                let column_read = column_header(&short);
                assert!(
                    block_read.is_err() || block_read == whole_block,
                    "block {cut}"
                );
                assert!(
                    column_read.is_err() || column_read == whole_column,
                    "column {cut}"
                );
            }
            for cut in 0..frame.len() {
                assert!(block_header(&frame[..cut]).is_err(), "block frame {cut}");
                assert!(column_header(&frame[..cut]).is_err(), "column frame {cut}");
            }
        }
    }

    /// The whole of what this ticket ships, with nothing stubbed: a real column sidecar as a
    /// beacon node would gossip it, read by the decoder this crate ships and filed by the store
    /// `overlay-core` ships, under the block root the payload's own bytes hash to and the index
    /// its own bytes carry. That pair is what a peer names a column by (T-081, T-087).
    #[test]
    fn a_real_column_reaches_the_recent_store_under_its_own_identity() {
        let clock = FakeClock::new();
        let (block, _) = fulu_block(4_242);
        let (sidecar, wire) = column_sidecar_of(block.message().block_header(), 5);
        let recent = SharedRecentLarge::new(RecentLarge::new(RECENT_TTL, RECENT_MAX_BYTES))
            .with_decoder(Arc::new(Headers));
        let id = MessageId([1; 20]);
        let payload = snappy(&wire).into();

        let header = recent.insert(
            id,
            topic("data_column_sidecar_5"),
            payload,
            Some(&wire),
            clock.now(),
        );

        assert_eq!(
            header,
            Some(Header::Column {
                slot: 4_242,
                index: 5,
                block_root: bytes32(sidecar.block_root()),
            })
        );
        assert_eq!(
            recent.get_by_column(bytes32(block.canonical_root()), 5),
            Some(id),
            "the column files under the root its own block hashes to"
        );
    }

    fn topic(name: &str) -> Topic {
        Topic::parse(&format!("/eth2/6a95a1a9/{name}/ssz_snappy"))
            .expect("a topic in the only shape the parser takes")
    }

    /// The refusal the exact first offset is for. A Gloas column sidecar's fixed part is 56
    /// bytes and a Fulu one's is 356, so reading a Gloas payload as a Fulu one would take a slot
    /// out of the middle of a root; a first offset anywhere else is a payload nobody built.
    #[test]
    fn column_header_refuses_a_first_offset_that_is_not_the_fixed_part() {
        let (_, wire) = column_sidecar(1, 0);

        for offset in [56u32, 300, 400] {
            let mut other = wire.clone();
            other[8..12].copy_from_slice(&offset.to_le_bytes());
            assert_eq!(
                column_header(&snappy(&other)),
                Err(HeaderError::Ssz),
                "first offset {offset}"
            );
        }
    }
}
