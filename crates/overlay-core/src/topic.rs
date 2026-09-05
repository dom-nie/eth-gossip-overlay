//! Gossipsub topic strings, read but never written. The sidecar mirrors whatever topics the
//! beacon node subscribes to, so it parses `/eth2/<fork_digest>/<name>/ssz_snappy` into a typed
//! value and renders it back unchanged, without ever computing a topic of its own.

/// A parsed `/eth2/<fork_digest>/<name>/ssz_snappy` topic.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Topic {
    fork_digest: [u8; 4],
    kind: TopicKind,
}

/// What a topic carries, with the subnet, column or blob index for the kinds that have one.
///
/// Indices are not bounds-checked here: the beacon node already validated the topic, and a spec
/// constant moving must not make the sidecar refuse it.
///
/// `Other` holds the name as a `String`, which is why this is `Clone` and not `Copy`. Every
/// known kind is a couple of bytes, so cloning only allocates for unknown names.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TopicKind {
    /// `beacon_block`.
    BeaconBlock,
    /// `beacon_aggregate_and_proof`.
    BeaconAggregateAndProof,
    /// `beacon_attestation_{i}`.
    Attestation(u8),
    /// `sync_committee_{i}`.
    SyncCommittee(u8),
    /// `sync_committee_contribution_and_proof`.
    SyncContributionAndProof,
    /// `voluntary_exit`.
    VoluntaryExit,
    /// `proposer_slashing`.
    ProposerSlashing,
    /// `attester_slashing`.
    AttesterSlashing,
    /// `bls_to_execution_change`.
    BlsToExecutionChange,
    /// `data_column_sidecar_{i}`. The column index equals the subnet index.
    DataColumnSidecar(u8),
    /// `blob_sidecar_{i}`.
    BlobSidecar(u8),
    /// A name the sidecar does not know, kept verbatim. Such a topic is still relayed; only the
    /// transport class has to be guessed from the payload size.
    Other(String),
}

/// Why a string is not a topic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TopicError {
    /// Not `/eth2/<fork_digest>/<name>/<encoding>`: wrong prefix or wrong number of parts.
    #[error("expected /eth2/<fork_digest>/<name>/ssz_snappy")]
    Shape,
    /// The fork digest is not eight lowercase hex characters.
    #[error("fork digest is not 8 lowercase hex characters")]
    Digest,
    /// The encoding suffix is something other than `ssz_snappy`.
    #[error("encoding is not ssz_snappy")]
    Encoding,
    /// A subnet, column or blob index is missing or does not fit in `u8`.
    #[error("index is not a number in 0..=255")]
    Index,
}

impl Topic {
    /// Parses a topic string. The fork digest must be lowercase hex: accepting uppercase would
    /// mean a parsed topic could no longer render back to the exact string it came from.
    pub fn parse(s: &str) -> Result<Self, TopicError> {
        let mut parts = s.split('/');
        let (Some(""), Some("eth2"), Some(digest), Some(name), Some(encoding), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return Err(TopicError::Shape);
        };
        if encoding != "ssz_snappy" {
            return Err(TopicError::Encoding);
        }
        Ok(Self {
            fork_digest: fork_digest(digest)?,
            kind: TopicKind::parse(name)?,
        })
    }

    /// The fork digest the topic is scoped to.
    pub fn fork_digest(&self) -> [u8; 4] {
        self.fork_digest
    }

    /// What the topic carries.
    pub fn kind(&self) -> &TopicKind {
        &self.kind
    }
}

fn fork_digest(hex: &str) -> Result<[u8; 4], TopicError> {
    let hex: &[u8; 8] = hex.as_bytes().try_into().map_err(|_| TopicError::Digest)?;
    let mut digest = [0; 4];
    for (byte, [hi, lo]) in digest.iter_mut().zip(hex.as_chunks::<2>().0) {
        *byte = (nibble(*hi)? << 4) | nibble(*lo)?;
    }
    Ok(digest)
}

fn nibble(c: u8) -> Result<u8, TopicError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        _ => Err(TopicError::Digest),
    }
}

impl TopicKind {
    fn parse(name: &str) -> Result<Self, TopicError> {
        Ok(match name {
            "beacon_block" => Self::BeaconBlock,
            "beacon_aggregate_and_proof" => Self::BeaconAggregateAndProof,
            "sync_committee_contribution_and_proof" => Self::SyncContributionAndProof,
            "voluntary_exit" => Self::VoluntaryExit,
            "proposer_slashing" => Self::ProposerSlashing,
            "attester_slashing" => Self::AttesterSlashing,
            "bls_to_execution_change" => Self::BlsToExecutionChange,
            _ => {
                if let Some(i) = name.strip_prefix("beacon_attestation_") {
                    Self::Attestation(index(i)?)
                } else if let Some(i) = name.strip_prefix("sync_committee_") {
                    Self::SyncCommittee(index(i)?)
                } else {
                    Self::Other(name.to_owned())
                }
            }
        })
    }
}

fn index(digits: &str) -> Result<u8, TopicError> {
    digits.parse().map_err(|_| TopicError::Index)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "6a95a1a9";

    fn topic(name: &str) -> String {
        format!("/eth2/{DIGEST}/{name}/ssz_snappy")
    }

    fn kind(name: &str) -> TopicKind {
        Topic::parse(&topic(name))
            .unwrap_or_else(|err| panic!("{name}: {err}"))
            .kind()
            .clone()
    }

    #[test]
    fn parses_every_appendix_b_small_topic() {
        for (name, expected) in [
            ("beacon_attestation_0", TopicKind::Attestation(0)),
            (
                "beacon_aggregate_and_proof",
                TopicKind::BeaconAggregateAndProof,
            ),
            ("sync_committee_0", TopicKind::SyncCommittee(0)),
            (
                "sync_committee_contribution_and_proof",
                TopicKind::SyncContributionAndProof,
            ),
            ("voluntary_exit", TopicKind::VoluntaryExit),
            ("proposer_slashing", TopicKind::ProposerSlashing),
            ("attester_slashing", TopicKind::AttesterSlashing),
            ("bls_to_execution_change", TopicKind::BlsToExecutionChange),
        ] {
            assert_eq!(kind(name), expected, "{name}");
        }
    }

    #[test]
    fn parses_all_64_attestation_subnets() {
        for i in 0..64 {
            assert_eq!(
                kind(&format!("beacon_attestation_{i}")),
                TopicKind::Attestation(i)
            );
        }
    }

    #[test]
    fn parses_all_4_sync_subnets() {
        for i in 0..4 {
            assert_eq!(
                kind(&format!("sync_committee_{i}")),
                TopicKind::SyncCommittee(i)
            );
        }
    }

    #[test]
    fn parses_all_128_column_subnets() {
        for i in 0..128 {
            assert_eq!(
                kind(&format!("data_column_sidecar_{i}")),
                TopicKind::DataColumnSidecar(i)
            );
        }
    }

    #[test]
    fn parses_blob_sidecar_indices() {
        for i in 0..=u8::MAX {
            assert_eq!(
                kind(&format!("blob_sidecar_{i}")),
                TopicKind::BlobSidecar(i)
            );
        }
    }
}
