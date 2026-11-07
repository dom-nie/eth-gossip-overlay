//! The one place the overlay reads a consensus object out of a gossip payload (§7, T-083).
//!
//! Column repair asks for a column by `(block_root, index)` rather than by message id, because a
//! host that never saw the column has no id for it (D23). Only the payload knows those two
//! numbers, so this module exists and nothing else in the workspace decodes a payload.
//!
//! # How little is read
//!
//! [`column_header`] reads the fixed part of a `DataColumnSidecar` and stops. Under Fulu that is
//! the index and the 112 bytes of the `BeaconBlockHeader` inside its `signed_block_header`, whose
//! tree hash is the block root; under Gloas the sidecar carries its slot and block root as plain
//! fields and nothing is hashed. The cells are about 40 KB of the payload and are never looked
//! at, which is what keeps a decode per column down to one hash of five leaves at most.
//!
//! [`block_header`] cannot do the same. A block root is the tree hash of a `BeaconBlock`, and one
//! of its five leaves is the tree hash of the body, so the body has to be walked before the root
//! exists. There is no prefix of the wire form that carries it. The block is therefore decoded
//! whole and nothing but its slot and its root is taken; it is one payload a slot, against the
//! `NUMBER_OF_COLUMNS` columns beside it.
//!
//! # Mainnet in practice
//!
//! [`column_header`] is preset-independent: the fixed part it reads is one length on every preset
//! Lighthouse ships. [`block_header`] is not, because a tree hash merkleises to list lengths the
//! preset fixes, so its root is mainnet's. On another preset the two disagree by construction and
//! the roots this module produces stop matching each other, which is why MD-06 left the custody
//! tracker to T-087 and why nothing here may act on a root beyond filing it. A network on another
//! preset needs the preset in `SpecSnapshot` before either of those changes.
//!
//! # Every byte is hostile
//!
//! A payload reaches here from the wire, so the declared decompressed length is checked before a
//! buffer is allocated, every read is bounds-checked, and a shape that is not the object the
//! topic names is an error rather than a panic. None of that makes what comes out true: a payload
//! that decodes is a payload a peer could build, and nothing here checks a signature, a proposer
//! or that any beacon node accepted the block. MD-06 is what that costs, and the only two things
//! allowed to read this module's answer are the recent store's index and T-044's arrival line.

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

/// A Gloas `DataColumnSidecar`'s fixed part: the index, the offsets of `column` and
/// `kzg_proofs`, the slot and the block root. It has no block header, commitments or proof; the
/// block root is a field of its own.
const GLOAS_COLUMN_FIXED_LEN: usize = 8 + 2 * 4 + 8 + 32;

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
///
/// The first offset of an SSZ container is the length of its fixed part, which is 356 for a Fulu
/// sidecar and 56 for a Gloas one on every preset. That tells the two layouts apart from the
/// bytes alone, without a fork schedule, and any other first offset is a payload nobody built,
/// refused rather than read as if a header were where this expects it.
fn column_header_ssz(bytes: &[u8]) -> Result<(u64, u8, [u8; 32]), HeaderError> {
    let first = bytes.get(..12).ok_or(HeaderError::Truncated)?;
    match u32_at(first, 8) as usize {
        COLUMN_FIXED_LEN => fulu_column_header(bytes),
        GLOAS_COLUMN_FIXED_LEN => gloas_column_header(bytes),
        _ => Err(HeaderError::Ssz),
    }
}

/// A Fulu sidecar's header. The other two offsets are read for their bounds only, which is what
/// tells a sidecar cut short from a whole one; the bytes they point at are the cells and the
/// commitments, and nothing here looks at those.
fn fulu_column_header(bytes: &[u8]) -> Result<(u64, u8, [u8; 32]), HeaderError> {
    let fixed = bytes
        .get(..COLUMN_FIXED_LEN)
        .ok_or(HeaderError::Truncated)?;
    let bounds = [
        COLUMN_FIXED_LEN,
        u32_at(fixed, 12) as usize,
        u32_at(fixed, 16) as usize,
        bytes.len(),
    ];
    if !bounds.is_sorted() {
        return Err(HeaderError::Ssz);
    }
    let header = BeaconBlockHeader {
        slot: Slot::new(u64_at(fixed, COLUMN_HEADER_AT)),
        proposer_index: u64_at(fixed, COLUMN_HEADER_AT + 8),
        parent_root: root_at(fixed, COLUMN_HEADER_AT + 16),
        state_root: root_at(fixed, COLUMN_HEADER_AT + 48),
        body_root: root_at(fixed, COLUMN_HEADER_AT + 80),
    };
    Ok((
        header.slot.as_u64(),
        column_index(fixed)?,
        bytes32(header.canonical_root()),
    ))
}

/// A Gloas sidecar's header, which is three fields of its fixed part: nothing is hashed. The
/// `kzg_proofs` offset is read for its bounds, as Fulu's are.
fn gloas_column_header(bytes: &[u8]) -> Result<(u64, u8, [u8; 32]), HeaderError> {
    let fixed = bytes
        .get(..GLOAS_COLUMN_FIXED_LEN)
        .ok_or(HeaderError::Truncated)?;
    let bounds = [
        GLOAS_COLUMN_FIXED_LEN,
        u32_at(fixed, 12) as usize,
        bytes.len(),
    ];
    if !bounds.is_sorted() {
        return Err(HeaderError::Ssz);
    }
    Ok((
        u64_at(fixed, 16),
        column_index(fixed)?,
        bytes32(root_at(fixed, 24)),
    ))
}

/// The index both layouts open with, which has to fit a subnet index.
fn column_index(fixed: &[u8]) -> Result<u8, HeaderError> {
    u8::try_from(u64_at(fixed, 0)).map_err(|_| HeaderError::Index)
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

    use overlay_core::header::block_parent_root;
    use overlay_core::msgid::MessageId;
    use overlay_core::recent::{RECENT_MAX_BYTES, RECENT_TTL, RecentLarge, SharedRecentLarge};
    use overlay_core::time::{Clock, FakeClock};
    use ssz::{Decode, Encode};
    use types::{
        BeaconBlock, BeaconBlockFulu, ChainSpec, DataColumnSidecar, DataColumnSidecarFulu,
        DataColumnSidecarGloas, EmptyBlock, ForkName, KzgCommitment,
    };

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
            let (slot, root, _) = block_header(&snappy(&wire)).unwrap();

            assert_eq!(slot, 4_242);
            assert_eq!(root, bytes32(block.canonical_root()));
        }
    }

    #[test]
    fn a_fulu_column_sidecar_decodes_to_its_root_and_index() {
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

    /// A Gloas sidecar carries the slot and the block root as fields of its own, so the root is
    /// read rather than hashed. The sidecar is the one `types` encodes, with the same 2 KB cell
    /// the Fulu fixture carries.
    #[test]
    fn a_gloas_column_sidecar_decodes_to_its_root_and_index() {
        let wire = crate::testutil::gloas_column_sidecar(9_001, 77, Hash256::repeat_byte(0x5a)).ssz;
        let sidecar = DataColumnSidecarGloas::<MainnetEthSpec>::from_ssz_bytes(&wire).unwrap();

        let (slot, index, block_root) = column_header(&snappy(&wire)).unwrap();

        assert_eq!(slot, sidecar.slot.as_u64());
        assert_eq!(u64::from(index), sidecar.index);
        assert_eq!(block_root, bytes32(sidecar.beacon_block_root));
    }

    /// A Gloas sidecar cut inside its fixed part is `Truncated` before a field is read, and one
    /// cut short of where its own `kzg_proofs` offset points is refused, so a slot or a root is
    /// never read out of bytes that stop early.
    #[test]
    fn gloas_column_cut_short_is_truncated() {
        let wire = crate::testutil::gloas_column_sidecar(1, 0, Hash256::repeat_byte(1)).ssz;
        let proofs_at = u32_at(&wire, 12) as usize;

        for cut in 0..GLOAS_COLUMN_FIXED_LEN {
            assert_eq!(
                column_header(&snappy(&wire[..cut])),
                Err(HeaderError::Truncated),
                "cut at {cut}"
            );
        }
        for cut in GLOAS_COLUMN_FIXED_LEN..proofs_at {
            assert_eq!(
                column_header(&snappy(&wire[..cut])),
                Err(HeaderError::Ssz),
                "cut at {cut}"
            );
        }
    }

    /// The refusal the exact first offset is for: a first offset that is neither layout's fixed
    /// part is a payload nobody built, and reading it as either would take a slot out of the
    /// middle of a root.
    #[test]
    fn a_made_up_first_offset_is_refused() {
        let (_, wire) = column_sidecar(1, 0);

        for offset in [0u32, 55, 57, 300, 355, 357, 400] {
            let mut other = wire.clone();
            other[8..12].copy_from_slice(&offset.to_le_bytes());
            assert_eq!(
                column_header(&snappy(&other)),
                Err(HeaderError::Ssz),
                "first offset {offset}"
            );
        }
    }

    /// A real Sepolia Gloas block: slot 11511776 (epoch 359743), finalized, as
    /// `GET /eth/v2/beacon/blocks/11511776` with `Accept: application/octet-stream` returned it
    /// from https://lodestar-sepolia.chainsafe.io on 2026-11-05, with `Eth-Consensus-Version:
    /// gloas`. It carries one attestation, one payload attestation and a bid with blob
    /// commitments, so its progressive lists are not empty.
    const SEPOLIA_GLOAS_BLOCK: &[u8] = include_bytes!("decode/fixtures/sepolia-gloas-11511776.ssz");

    /// Its root, from `GET /eth/v1/beacon/blocks/11511776/root` on the same node and on
    /// https://ethereum-sepolia-beacon-api.publicnode.com, which agreed.
    const SEPOLIA_GLOAS_ROOT: &str =
        "0xbb240e1fd2fba75129bfbae48ea2a59100f29821f16c7f9a1653c15c2a8d8883";

    /// Gloas operation lists are progressive (EIP-7688) and hash differently from the lists
    /// before them, so a Gloas block root is only right with the `types` that knows that. This
    /// holds the root the sidecar files a Gloas block under against the one a beacon node
    /// reports for it.
    #[test]
    fn gloas_block_root_matches_the_beacon_node() {
        let block =
            SignedBeaconBlock::<MainnetEthSpec>::any_from_ssz_bytes(SEPOLIA_GLOAS_BLOCK).unwrap();
        assert_eq!(block.fork_name_unchecked(), ForkName::Gloas);

        let (slot, root, _) = block_header(&snappy(SEPOLIA_GLOAS_BLOCK)).unwrap();

        assert_eq!(slot, 11_511_776);
        assert_eq!(root, bytes32(SEPOLIA_GLOAS_ROOT.parse().unwrap()));
    }

    /// A block's blob count is what tells custody that no column of it will ever exist. Before
    /// Gloas the commitments are in the body; from Gloas on the body has none and they are in
    /// the builder's bid, which the block carries, so the count is known at the block either way.
    #[test]
    fn block_header_reads_the_blob_commitment_count() {
        let spec = ChainSpec::mainnet();
        let mut fulu = BeaconBlockFulu::<MainnetEthSpec>::empty(&spec);
        for _ in 0..2 {
            fulu.body
                .blob_kzg_commitments
                .push(KzgCommitment::empty_for_testing())
                .unwrap();
        }
        let (_, wire) = signed_block(BeaconBlock::Fulu(fulu), 4_242);

        assert_eq!(block_header(&snappy(&wire)).unwrap().2, 2);

        let gloas =
            SignedBeaconBlock::<MainnetEthSpec>::any_from_ssz_bytes(SEPOLIA_GLOAS_BLOCK).unwrap();
        let in_bid = gloas
            .message()
            .body()
            .signed_execution_payload_bid_gloas()
            .unwrap()
            .message
            .blob_kzg_commitments
            .len();
        assert_ne!(in_bid, 0, "the fixture's bid carries commitments");
        assert_eq!(block_header(&snappy(SEPOLIA_GLOAS_BLOCK)).unwrap().2, in_bid);
    }

    /// What `cargo test -p overlay-bn drift` runs from this module: the byte offsets this
    /// module reads, held against every fork `types` knows (MD-10).
    mod drift {
        use super::*;

        /// T-101 test 4: `parent_root` sits at bytes 116..148 of a `SignedBeaconBlock` on every
        /// fork Lighthouse knows, which is what lets the receive path read it with no consensus
        /// type. A block of each fork gets a parent root of its own written at that offset, and the
        /// typed decode reads the same root back, so the offset is the field and not a coincidence
        /// of one layout. The forks come from `ForkName::list_all()`, so one Lighthouse adds is
        /// covered without anyone naming it here (MD-10). The wire is built here rather than by
        /// `signed_block`, which reads blocks back the way [`block_header`] does.
        #[test]
        fn parent_root_offset_holds_for_every_fork() {
            for (n, fork) in ForkName::list_all().into_iter().enumerate() {
                let spec = fork.make_genesis_spec(ChainSpec::mainnet());
                let block = BeaconBlock::<MainnetEthSpec>::empty(&spec);
                assert_eq!(block.to_ref().fork_name_unchecked(), fork);
                let parent = [n as u8 + 1; 32];
                let mut wire = 100u32.to_le_bytes().to_vec();
                wire.extend_from_slice(&infinity_signature());
                wire.extend_from_slice(&block.as_ssz_bytes());
                wire[116..148].copy_from_slice(&parent);

                // Decoded as its own fork: `any_from_ssz_bytes` stops at Gloas, and a Heze block,
                // whose bid differs from Gloas's, is not one it can read.
                let decoded = SignedBeaconBlock::<MainnetEthSpec>::from_ssz_bytes(&wire, &spec)
                    .unwrap_or_else(|err| panic!("{fork}: {err:?}"));

                assert_eq!(decoded.fork_name_unchecked(), fork);
                assert_eq!(bytes32(decoded.parent_root()), parent, "{fork}");
                assert_eq!(block_parent_root(&wire), Some(parent), "{fork}");
            }
            assert_eq!(block_parent_root(&[0; 148]), None, "not a signed block");
            assert_eq!(
                block_parent_root(&fulu_block(1).1[..147]),
                None,
                "cut short"
            );
        }

        /// The decoder's fork list: the fixed length [`column_header`] reads each fork's sidecar
        /// at. Every fork with column sidecars is here, Heze included, because Lighthouse maps
        /// every fork after Gloas to Gloas's sidecar until it says otherwise.
        const COLUMN_LAYOUTS: [(ForkName, usize); 3] = [
            (ForkName::Fulu, COLUMN_FIXED_LEN),
            (ForkName::Gloas, GLOAS_COLUMN_FIXED_LEN),
            (ForkName::Heze, GLOAS_COLUMN_FIXED_LEN),
        ];

        /// MD-10: for every fork with column sidecars, the first offset of the sidecar `types`
        /// encodes for it is the fixed length [`column_header`] reads, and the read gives the
        /// slot, index and block root `types` says the sidecar has. A fork whose sidecar changes
        /// shape, or a new fork with columns, fails here by name before a sidecar of it reaches
        /// the recent store.
        #[test]
        fn column_fixed_len_per_fork_matches_types() {
            // The same cell and proof in both, so each is past the Fulu fixed length the way a
            // real sidecar is.
            let (fulu, _) = column_sidecar(1, 0);
            let gloas = crate::testutil::gloas_column_sidecar(1, 0, Hash256::repeat_byte(1)).ssz;
            let fulu = fulu.as_ssz_bytes();

            let mut problems = Vec::new();
            for fork in ForkName::list_all()
                .into_iter()
                .filter(|f| f.fulu_enabled())
            {
                let Some(sidecar) = [&fulu, &gloas].into_iter().find_map(|bytes| {
                    DataColumnSidecar::<MainnetEthSpec>::from_ssz_bytes_for_fork(bytes, fork).ok()
                }) else {
                    problems.push(format!(
                        "{fork}: no sidecar this test builds decodes; add one"
                    ));
                    continue;
                };
                let bytes = sidecar.as_ssz_bytes();
                let first_offset = u32_at(&bytes, 8) as usize;
                let read = column_header_ssz(&bytes);
                let wanted = Ok((
                    sidecar.slot().as_u64(),
                    *sidecar.index() as u8,
                    bytes32(sidecar.block_root()),
                ));
                match COLUMN_LAYOUTS.iter().find(|(known, _)| *known == fork) {
                    None => problems.push(format!(
                        "{fork}: not in the decoder's fork list; its sidecar's first offset is {first_offset}"
                    )),
                    Some((_, len)) if first_offset != *len || read != wanted => {
                        problems.push(format!(
                            "{fork}: the decoder reads a fixed part of {len} bytes, types encodes \
                             {first_offset}, and the read gave {read:?}, not {wanted:?}"
                        ))
                    }
                    Some(_) => {}
                }
            }
            assert!(problems.is_empty(), "{}", problems.join("\n"));
        }
    }
}
