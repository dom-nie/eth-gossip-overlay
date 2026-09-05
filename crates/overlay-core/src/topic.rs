//! Gossipsub topic strings, read but never written. The sidecar mirrors whatever topics the
//! beacon node subscribes to, so it parses `/eth2/<fork_digest>/<name>/ssz_snappy` into a typed
//! value and renders it back unchanged, without ever computing a topic of its own.

use std::collections::BTreeSet;
use std::fmt;

/// Payloads on a topic name the sidecar does not know travel as [`Class::Large`] from this size
/// up. A constant rather than a config key: the class only picks the transport path, and a
/// release is the place to correct a wrong guess for a new topic.
pub const UNKNOWN_LARGE_THRESHOLD_BYTES: usize = 16 * 1024;

/// A parsed `/eth2/<fork_digest>/<name>/ssz_snappy` topic. [`fmt::Display`] renders the exact
/// string it was parsed from.
///
/// Ordered by fork digest, then kind: a stable order for sets, with no other meaning.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
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
///
/// Ordered by variant, then index, so a set of topics lists in a stable order.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
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

/// What the sidecar subscribes to, as two sets with one source (D12). `advertised` is exactly
/// what the beacon node subscribes to; `local` is what the sidecar's own gossipsub instance
/// subscribes to. T-027's SUBS bitmap and T-019's MetaData read `advertised`; T-026 interns
/// and announces `local`. The mirror keeps them equal, and T-015's extra column topics are the
/// only thing that makes them differ (D06). T-041's `bn_subscriptions` gauge is
/// `advertised.len()` read from the `watch` receiver the mirror's shell feeds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubscriptionSets {
    /// The beacon node's own subscriptions.
    pub advertised: BTreeSet<Topic>,
    /// The sidecar's own gossipsub subscriptions.
    pub local: BTreeSet<Topic>,
}

impl SubscriptionSets {
    /// Both sets equal to `topics`: the plain mirror, with no extras.
    pub fn mirrored(topics: BTreeSet<Topic>) -> Self {
        Self {
            advertised: topics.clone(),
            local: topics,
        }
    }
}

/// Which transport path a message takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Class {
    /// Batched with other small messages and sent as unreliable datagrams.
    Small,
    /// Chunked, parity-coded and striped over the region.
    Large,
}

impl Class {
    /// The class of a message on `kind`, following Appendix B: "Small class topics:
    /// `beacon_attestation_{0..63}`, `beacon_aggregate_and_proof`, `sync_committee_{0..3}`,
    /// `sync_committee_contribution_and_proof`, `voluntary_exit`, `proposer_slashing`,
    /// `attester_slashing`, `bls_to_execution_change`. Large class topics: `beacon_block`,
    /// `data_column_sidecar_{0..127}`, `blob_sidecar_*`." Known kinds ignore `payload_len`.
    ///
    /// A name the sidecar does not know is Large when `payload_len` is at least
    /// [`UNKNOWN_LARGE_THRESHOLD_BYTES`] and Small below it. A small payload on the large path
    /// wastes chunking and parity; a large payload on the small path exceeds the datagram limit
    /// and defeats batching.
    pub fn of(kind: &TopicKind, payload_len: usize) -> Self {
        match kind {
            TopicKind::BeaconBlock
            | TopicKind::DataColumnSidecar(_)
            | TopicKind::BlobSidecar(_) => Self::Large,
            TopicKind::BeaconAggregateAndProof
            | TopicKind::Attestation(_)
            | TopicKind::SyncCommittee(_)
            | TopicKind::SyncContributionAndProof
            | TopicKind::VoluntaryExit
            | TopicKind::ProposerSlashing
            | TopicKind::AttesterSlashing
            | TopicKind::BlsToExecutionChange => Self::Small,
            TopicKind::Other(_) if payload_len >= UNKNOWN_LARGE_THRESHOLD_BYTES => Self::Large,
            TopicKind::Other(_) => Self::Small,
        }
    }
}

/// How many attestation, sync committee and data column subnets the network has. Each count is
/// the first index that is out of range. A topic past a bound is never refused, only warned
/// about, because the beacon node validated it and a spec constant may simply have moved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubnetBounds {
    /// `ATTESTATION_SUBNET_COUNT`, a spec constant.
    pub attestation_subnet_count: u16,
    /// `SYNC_COMMITTEE_SUBNET_COUNT`, a spec constant.
    pub sync_committee_subnet_count: u16,
    /// `DATA_COLUMN_SIDECAR_SUBNET_COUNT`, read from the beacon node's spec snapshot.
    pub data_column_sidecar_subnet_count: u16,
}

impl SubnetBounds {
    /// The compiled-in mainnet counts.
    pub const MAINNET: Self = Self {
        attestation_subnet_count: 64,
        sync_committee_subnet_count: 4,
        data_column_sidecar_subnet_count: 128,
    };
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
    /// The name between the digest and the encoding is empty.
    #[error("empty topic name")]
    EmptyName,
    /// A subnet, column or blob index is missing, has leading zeros or does not fit in `u8`.
    #[error("index is not a number in 0..=255 without leading zeros")]
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

impl fmt::Display for Topic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d] = self.fork_digest;
        write!(
            f,
            "/eth2/{a:02x}{b:02x}{c:02x}{d:02x}/{}/ssz_snappy",
            self.kind
        )
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
    /// Whether this kind carries a subnet or column index at or past `bounds`. Blob sidecars
    /// have no bound, and kinds without an index never exceed.
    pub fn index_exceeds(&self, bounds: &SubnetBounds) -> bool {
        match *self {
            Self::Attestation(i) => u16::from(i) >= bounds.attestation_subnet_count,
            Self::SyncCommittee(i) => u16::from(i) >= bounds.sync_committee_subnet_count,
            Self::DataColumnSidecar(i) => u16::from(i) >= bounds.data_column_sidecar_subnet_count,
            _ => false,
        }
    }

    fn parse(name: &str) -> Result<Self, TopicError> {
        if name.is_empty() {
            return Err(TopicError::EmptyName);
        }
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
                } else if let Some(i) = name.strip_prefix("data_column_sidecar_") {
                    Self::DataColumnSidecar(index(i)?)
                } else if let Some(i) = name.strip_prefix("blob_sidecar_") {
                    Self::BlobSidecar(index(i)?)
                } else {
                    Self::Other(name.to_owned())
                }
            }
        })
    }
}

impl fmt::Display for TopicKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BeaconBlock => f.write_str("beacon_block"),
            Self::BeaconAggregateAndProof => f.write_str("beacon_aggregate_and_proof"),
            Self::Attestation(i) => write!(f, "beacon_attestation_{i}"),
            Self::SyncCommittee(i) => write!(f, "sync_committee_{i}"),
            Self::SyncContributionAndProof => f.write_str("sync_committee_contribution_and_proof"),
            Self::VoluntaryExit => f.write_str("voluntary_exit"),
            Self::ProposerSlashing => f.write_str("proposer_slashing"),
            Self::AttesterSlashing => f.write_str("attester_slashing"),
            Self::BlsToExecutionChange => f.write_str("bls_to_execution_change"),
            Self::DataColumnSidecar(i) => write!(f, "data_column_sidecar_{i}"),
            Self::BlobSidecar(i) => write!(f, "blob_sidecar_{i}"),
            Self::Other(name) => f.write_str(name),
        }
    }
}

/// `str::parse` takes a sign and leading zeros. Those are refused here because the parsed
/// index has to print back as the exact text it came from.
fn index(digits: &str) -> Result<u8, TopicError> {
    let leading_zero = digits.len() > 1 && digits.starts_with('0');
    let all_digits = digits.bytes().all(|b| b.is_ascii_digit());
    if leading_zero || !all_digits {
        return Err(TopicError::Index);
    }
    digits.parse().map_err(|_| TopicError::Index)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

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

    #[test]
    fn class_table_matches_appendix_b() {
        for (kind, expected) in [
            (TopicKind::BeaconBlock, Class::Large),
            (TopicKind::BeaconAggregateAndProof, Class::Small),
            (TopicKind::Attestation(0), Class::Small),
            (TopicKind::SyncCommittee(0), Class::Small),
            (TopicKind::SyncContributionAndProof, Class::Small),
            (TopicKind::VoluntaryExit, Class::Small),
            (TopicKind::ProposerSlashing, Class::Small),
            (TopicKind::AttesterSlashing, Class::Small),
            (TopicKind::BlsToExecutionChange, Class::Small),
            (TopicKind::DataColumnSidecar(0), Class::Large),
            (TopicKind::BlobSidecar(0), Class::Large),
        ] {
            for payload_len in [0, 1 << 20] {
                assert_eq!(
                    Class::of(&kind, payload_len),
                    expected,
                    "{kind:?} at {payload_len} bytes"
                );
            }
        }
    }

    #[test]
    fn unknown_name_parses_as_other() {
        assert_eq!(
            kind("light_client_finality_update"),
            TopicKind::Other("light_client_finality_update".to_owned())
        );
    }

    #[test]
    fn unknown_below_threshold_is_small() {
        let other = TopicKind::Other("light_client_finality_update".to_owned());

        assert_eq!(
            Class::of(&other, UNKNOWN_LARGE_THRESHOLD_BYTES - 1),
            Class::Small
        );
    }

    #[test]
    fn unknown_at_threshold_is_large() {
        let other = TopicKind::Other("light_client_finality_update".to_owned());

        assert_eq!(
            Class::of(&other, UNKNOWN_LARGE_THRESHOLD_BYTES),
            Class::Large
        );
    }

    #[test]
    fn out_of_range_index_parses_and_exceeds_mainnet_bounds() {
        for (name, expected, exceeds) in [
            ("beacon_attestation_64", TopicKind::Attestation(64), true),
            ("sync_committee_4", TopicKind::SyncCommittee(4), true),
            (
                "data_column_sidecar_128",
                TopicKind::DataColumnSidecar(128),
                true,
            ),
            ("beacon_attestation_63", TopicKind::Attestation(63), false),
            ("sync_committee_3", TopicKind::SyncCommittee(3), false),
            (
                "data_column_sidecar_127",
                TopicKind::DataColumnSidecar(127),
                false,
            ),
            ("blob_sidecar_255", TopicKind::BlobSidecar(255), false),
            ("beacon_block", TopicKind::BeaconBlock, false),
        ] {
            let parsed = kind(name);

            assert_eq!(parsed, expected, "{name}");
            assert_eq!(
                parsed.index_exceeds(&SubnetBounds::MAINNET),
                exceeds,
                "{name}"
            );
        }
    }

    #[test]
    fn malformed_topic_is_error() {
        let no_index = topic("beacon_attestation_");
        let leading_zeros = topic("beacon_attestation_007");
        let too_big = topic("beacon_attestation_256");
        for (input, expected) in [
            ("/eth2/beacon_block/ssz_snappy", TopicError::Shape),
            ("eth2/6a95a1a9/beacon_block/ssz_snappy", TopicError::Shape),
            ("/eth2/6a95a1a9/beacon_block/ssz_snappy/", TopicError::Shape),
            ("/eth2/6a95a1a/beacon_block/ssz_snappy", TopicError::Digest),
            ("/eth2/6A95A1A9/beacon_block/ssz_snappy", TopicError::Digest),
            ("/eth2/6a95a1a9/beacon_block/ssz", TopicError::Encoding),
            ("/eth2/6a95a1a9//ssz_snappy", TopicError::EmptyName),
            (no_index.as_str(), TopicError::Index),
            (leading_zeros.as_str(), TopicError::Index),
            (too_big.as_str(), TopicError::Index),
        ] {
            assert_eq!(Topic::parse(input), Err(expected), "{input}");
        }
    }

    fn any_kind() -> impl Strategy<Value = TopicKind> {
        prop_oneof![
            Just(TopicKind::BeaconBlock),
            Just(TopicKind::BeaconAggregateAndProof),
            any::<u8>().prop_map(TopicKind::Attestation),
            any::<u8>().prop_map(TopicKind::SyncCommittee),
            Just(TopicKind::SyncContributionAndProof),
            Just(TopicKind::VoluntaryExit),
            Just(TopicKind::ProposerSlashing),
            Just(TopicKind::AttesterSlashing),
            Just(TopicKind::BlsToExecutionChange),
            any::<u8>().prop_map(TopicKind::DataColumnSidecar),
            any::<u8>().prop_map(TopicKind::BlobSidecar),
            "light_client_[a-z_]{1,24}".prop_map(TopicKind::Other),
        ]
    }

    proptest! {
        #[test]
        fn display_round_trips_parse(digest: [u8; 4], kind in any_kind()) {
            let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
            let text = format!("/eth2/{hex}/{kind}/ssz_snappy");

            let parsed = Topic::parse(&text).unwrap();

            prop_assert_eq!(parsed.fork_digest(), digest);
            prop_assert_eq!(parsed.kind(), &kind);
            prop_assert_eq!(parsed.to_string(), text);
        }
    }

    #[test]
    fn fork_digest_bytes_are_decoded() {
        let parsed = Topic::parse(&topic("beacon_block")).unwrap();

        assert_eq!(parsed.fork_digest(), [0x6a, 0x95, 0xa1, 0xa9]);
    }
}
