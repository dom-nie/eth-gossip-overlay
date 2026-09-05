//! The gossipsub message id, computed from the snappy-compressed bytes the sidecar carries.
//!
//! Lighthouse decompresses inbound data before its id function runs, so its id is
//! `SHA256(domain ++ uint64_le(len(topic)) ++ topic ++ decompressed)[..20]`, with the topic
//! being the full `/eth2/<digest>/<name>/ssz_snappy` string. The sidecar keeps payloads
//! compressed and decompresses only to hash. The bytes on the wire and the id are the same;
//! only the point of decompression moves, so the seen cache and the beacon node's duplicate
//! cache agree on every message.
//!
//! The consensus spec also defines an id for a payload that does not decompress: the invalid
//! domain over the raw bytes. Lighthouse never produces it, because its snappy transform
//! rejects such a payload before any id is computed. It is implemented here so the spec
//! function is complete and so two sidecars agree on the id of a corrupt payload while both
//! drop it. That is why [`compute`] reports the [`Branch`] it took. The overlay receive paths
//! (direct fanout in T-032, reassembly in T-074) drop anything but [`Branch::Valid`], count it
//! in `invalid_payload_total{peer}`, log a warning rate-limited per peer, and never insert it
//! into the seen cache or publish it. The inbound path from the beacon node (T-016) only sees
//! payloads the node already decompressed, so it has nothing to branch on.

use std::fmt;

use sha2::{Digest, Sha256};

const MESSAGE_DOMAIN_VALID_SNAPPY: [u8; 4] = [1, 0, 0, 0];
const MESSAGE_DOMAIN_INVALID_SNAPPY: [u8; 4] = [0, 0, 0, 0];

/// The first 20 bytes of the SHA-256 digest, the form gossipsub carries and deduplicates on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MessageId(pub [u8; 20]);

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

/// Which branch of the spec function produced an id. Only [`Branch::Valid`] is an id the
/// beacon node would ever compute; the other two exist so sidecars agree while dropping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Branch {
    /// The payload decompressed within the limit; the id covers the decompressed bytes under
    /// the valid domain.
    Valid,
    /// Decompression failed; the id covers the raw bytes under the invalid domain.
    Invalid,
    /// The declared decompressed length is above the limit. Nothing was decompressed and the
    /// id covers the raw bytes under the invalid domain. Kept apart from `Invalid` because the
    /// payload may be well-formed snappy that the beacon node would still refuse.
    TooLarge,
}

/// The id of a message and the branch that produced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Computed {
    /// The message id.
    pub id: MessageId,
    /// How it was computed. Anything but [`Branch::Valid`] is dropped by the receive paths.
    pub branch: Branch,
}

/// Computes the id of `compressed` on `topic`. `max_decompressed` is inclusive: it is the beacon
/// node's gossip maximum transmit size, passed in by the caller so this crate holds no copy of
/// a Lighthouse constant. The declared length is read from the snappy header and compared with
/// the limit before any buffer is allocated, so a hostile header cannot reserve gigabytes.
pub fn compute(topic: &str, compressed: &[u8], max_decompressed: usize) -> Computed {
    let decompressed = decompress(compressed, max_decompressed);
    let (branch, domain, data): (Branch, [u8; 4], &[u8]) = match &decompressed {
        Ok(data) => (Branch::Valid, MESSAGE_DOMAIN_VALID_SNAPPY, data),
        Err(branch) => (*branch, MESSAGE_DOMAIN_INVALID_SNAPPY, compressed),
    };
    let digest = Sha256::new_with_prefix(domain)
        .chain_update((topic.len() as u64).to_le_bytes())
        .chain_update(topic)
        .chain_update(data)
        .finalize();
    let mut id = [0; 20];
    id.copy_from_slice(&digest[..20]);
    Computed {
        id: MessageId(id),
        branch,
    }
}

fn decompress(compressed: &[u8], max_decompressed: usize) -> Result<Vec<u8>, Branch> {
    match snap::raw::decompress_len(compressed) {
        Ok(len) if len > max_decompressed => Err(Branch::TooLarge),
        Ok(_) => snap::raw::Decoder::new()
            .decompress_vec(compressed)
            .map_err(|_| Branch::Invalid),
        Err(_) => Err(Branch::Invalid),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    fn by_hand(domain: [u8; 4], length: [u8; 8], topic: &str, data: &[u8]) -> MessageId {
        let digest = Sha256::new_with_prefix(domain)
            .chain_update(length)
            .chain_update(topic)
            .chain_update(data)
            .finalize();
        let mut id = [0; 20];
        id.copy_from_slice(&digest[..20]);
        MessageId(id)
    }

    const TOPIC: &str = "/eth2/6a95a1a9/beacon_block/ssz_snappy";
    const HELLO_SNAPPY: &[u8] = &[0x05, 0x10, 0x68, 0x65, 0x6c, 0x6c, 0x6f];
    const HELLO_ID: &str = "d1346976629ef3d2c04a2a53ccacb9499c3db63a";

    #[test]
    fn valid_snappy_payload_matches_spec_vector() {
        let computed = compute(TOPIC, HELLO_SNAPPY, 1024);

        assert_eq!(computed.branch, Branch::Valid);
        assert_eq!(computed.id.to_string(), HELLO_ID);
    }

    const TRUNCATED_SNAPPY: &[u8] = &[0x05, 0x10, 0x68];
    const TRUNCATED_ID: &str = "0c900438f873351253246db4766f6035ababcbb0";

    #[test]
    fn undecompressable_payload_uses_invalid_domain_vector() {
        let computed = compute(TOPIC, TRUNCATED_SNAPPY, 1024);

        assert_eq!(computed.branch, Branch::Invalid);
        assert_eq!(computed.id.to_string(), TRUNCATED_ID);
    }

    #[test]
    fn topic_length_is_little_endian() {
        let topic = "x".repeat(256);
        let by_hand =
            |length: [u8; 8]| by_hand(MESSAGE_DOMAIN_VALID_SNAPPY, length, &topic, b"hello");

        let computed = compute(&topic, HELLO_SNAPPY, 1024);

        assert_eq!(computed.id, by_hand(256u64.to_le_bytes()));
        assert_ne!(computed.id, by_hand(256u64.to_be_bytes()));
    }

    #[test]
    fn payload_claiming_huge_length_does_not_allocate() {
        let four_gib_header = [0x80, 0x80, 0x80, 0x80, 0x10, 0x00];
        let started = Instant::now();

        let computed = compute(TOPIC, &four_gib_header, 1024);

        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(computed.branch, Branch::TooLarge);
        assert_eq!(
            computed.id,
            by_hand(
                MESSAGE_DOMAIN_INVALID_SNAPPY,
                (TOPIC.len() as u64).to_le_bytes(),
                TOPIC,
                &four_gib_header
            )
        );
    }
}
