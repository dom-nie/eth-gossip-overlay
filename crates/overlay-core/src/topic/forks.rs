//! Every gossip topic Lighthouse subscribes to at every fork it knows, scheduled or not, with
//! the kind and class the sidecar gives it (MD-10). `overlay-bn` holds this table against
//! `lighthouse_network::types::all_topics_at_fork` at the pinned tag in both directions, so a
//! Lighthouse bump that adds, drops or renames a topic fails by fork and name instead of
//! falling silently into `TopicKind::Other`.

use crate::topic::{Class, TopicKind};

/// Lighthouse's `ForkName`s in order, as they display. A row is live from its
/// [`since`](ForkTopic::since) fork onwards.
pub const FORKS: [&str; 9] = [
    "phase0",
    "altair",
    "bellatrix",
    "capella",
    "deneb",
    "electra",
    "fulu",
    "gloas",
    "heze",
];

/// One topic name, or one family of names with an index, and what the sidecar makes of it.
#[derive(Clone, Copy, Debug)]
pub struct ForkTopic {
    /// The first fork in [`FORKS`] at which Lighthouse subscribes to it.
    pub since: &'static str,
    /// The name between the fork digest and the encoding. `{i}` stands for every subnet or
    /// column index.
    pub name: &'static str,
    /// The kind and class the sidecar gives it.
    pub sidecar: Sidecar,
}

/// The sidecar's reading of a topic name.
#[derive(Clone, Copy, Debug)]
pub enum Sidecar {
    /// A kind the sidecar names, built from the name's index (0 for a name without one), and
    /// the class that kind always takes.
    Named(fn(u8) -> TopicKind, Class),
    /// `TopicKind::Other`: classed by payload size under D02, and counted by
    /// `overlay_unknown_topic_kind_total` on every message.
    Other,
}

/// The table, checked against Lighthouse v8.3.2. Lighthouse's own list is its worst case:
/// every subnet and column, the light-client server and execution proofs all switched on.
pub const FORK_TOPICS: &[ForkTopic] = &[
    named(
        "phase0",
        "beacon_block",
        |_| TopicKind::BeaconBlock,
        Class::Large,
    ),
    named(
        "phase0",
        "beacon_aggregate_and_proof",
        |_| TopicKind::BeaconAggregateAndProof,
        Class::Small,
    ),
    named(
        "phase0",
        "beacon_attestation_{i}",
        TopicKind::Attestation,
        Class::Small,
    ),
    named(
        "phase0",
        "voluntary_exit",
        |_| TopicKind::VoluntaryExit,
        Class::Small,
    ),
    named(
        "phase0",
        "proposer_slashing",
        |_| TopicKind::ProposerSlashing,
        Class::Small,
    ),
    named(
        "phase0",
        "attester_slashing",
        |_| TopicKind::AttesterSlashing,
        Class::Small,
    ),
    named(
        "altair",
        "sync_committee_{i}",
        TopicKind::SyncCommittee,
        Class::Small,
    ),
    named(
        "altair",
        "sync_committee_contribution_and_proof",
        |_| TopicKind::SyncContributionAndProof,
        Class::Small,
    ),
    // Lighthouse serves light clients by default (`--disable-light-client-server` turns it
    // off), so a default beacon node subscribes to both and the sidecar mirrors them.
    other("altair", "light_client_finality_update"),
    other("altair", "light_client_optimistic_update"),
    named(
        "capella",
        "bls_to_execution_change",
        |_| TopicKind::BlsToExecutionChange,
        Class::Small,
    ),
    named(
        "fulu",
        "data_column_sidecar_{i}",
        TopicKind::DataColumnSidecar,
        Class::Large,
    ),
    // MD-08 names these four; until T-119 does, they are Other.
    other("gloas", "execution_payload"),
    other("gloas", "execution_payload_bid"),
    other("gloas", "payload_attestation_message"),
    other("gloas", "proposer_preferences"),
    // Other by decision (MD-08): subscribed only with the node's `--enable-execution-proof`.
    other("gloas", "execution_proof"),
    // Other by decision (MD-08): Heze is scheduled on no network.
    other("heze", "inclusion_list"),
];

/// Kinds the sidecar names that no Lighthouse fork subscribes to, each with the reason it is
/// kept. Holding these here is what lets a test insist that every other kind has a row.
pub const KINDS_WITHOUT_A_TOPIC: [(&str, &str); 1] = [(
    "blob_sidecar_{i}",
    "D02 made blob sidecars a known Large kind; Lighthouse v8.2.3 and v8.3.2 subscribe to \
     blob_sidecar at no fork, Deneb and Electra included",
)];

const fn named(
    since: &'static str,
    name: &'static str,
    kind: fn(u8) -> TopicKind,
    class: Class,
) -> ForkTopic {
    ForkTopic {
        since,
        name,
        sidecar: Sidecar::Named(kind, class),
    }
}

const fn other(since: &'static str, name: &'static str) -> ForkTopic {
    ForkTopic {
        since,
        name,
        sidecar: Sidecar::Other,
    }
}

impl ForkTopic {
    /// Whether the row is live at `fork`. A fork missing from [`FORKS`] has no rows.
    pub fn live_at(&self, fork: &str) -> bool {
        match (position(self.since), position(fork)) {
            (Some(since), Some(at)) => since <= at,
            _ => false,
        }
    }

    /// The index `name` carries if it is one of this row's names: `Some(0)` for an exact match
    /// on a row without `{i}`, the parsed index for a row with one, `None` otherwise.
    pub fn index_of(&self, name: &str) -> Option<u8> {
        match self.name.strip_suffix("{i}") {
            Some(prefix) => name.strip_prefix(prefix)?.parse().ok(),
            None => (self.name == name).then_some(0),
        }
    }
}

/// Whether the table lists `name` at any fork: a named kind's name, or one it lists as
/// `Other` by decision. A name it does not list is one nobody has reviewed, and only that is
/// what `overlay_unknown_topic_kind_total` counts (MD-10 amended).
pub fn lists(name: &str) -> bool {
    FORK_TOPICS.iter().any(|row| row.index_of(name).is_some())
}

fn position(fork: &str) -> Option<usize> {
    FORKS.iter().position(|known| *known == fork)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One of every kind the sidecar names.
    const NAMED_KINDS: [TopicKind; 11] = [
        TopicKind::BeaconBlock,
        TopicKind::BeaconAggregateAndProof,
        TopicKind::Attestation(0),
        TopicKind::SyncCommittee(0),
        TopicKind::SyncContributionAndProof,
        TopicKind::VoluntaryExit,
        TopicKind::ProposerSlashing,
        TopicKind::AttesterSlashing,
        TopicKind::BlsToExecutionChange,
        TopicKind::DataColumnSidecar(0),
        TopicKind::BlobSidecar(0),
    ];

    #[test]
    fn lists_every_name_the_table_has_and_nothing_else() {
        for name in [
            "beacon_block",
            "beacon_attestation_17",
            "data_column_sidecar_127",
            "light_client_finality_update",
            "execution_payload_bid",
            "inclusion_list",
        ] {
            assert!(lists(name), "{name}");
        }
        for name in [
            "made_up_topic",
            "blob_sidecar_0",
            "beacon_attestation_",
            "beacon_attestation_x",
            "execution_payload_bids",
        ] {
            assert!(!lists(name), "{name}");
        }
    }

    /// A named kind with no row would be a kind the sidecar can parse that the beacon node never
    /// sends, which is either dead code or a topic the table forgot.
    #[test]
    fn every_named_kind_has_a_fork_topic_row_or_a_listed_reason() {
        for kind in NAMED_KINDS {
            let has_row = FORK_TOPICS.iter().any(|row| match row.sidecar {
                Sidecar::Named(make, _) => {
                    std::mem::discriminant(&make(0)) == std::mem::discriminant(&kind)
                }
                Sidecar::Other => false,
            });
            let pattern = match &kind {
                TopicKind::Attestation(_)
                | TopicKind::SyncCommittee(_)
                | TopicKind::DataColumnSidecar(_)
                | TopicKind::BlobSidecar(_) => {
                    format!("{}{{i}}", kind.to_string().trim_end_matches('0'))
                }
                _ => kind.to_string(),
            };
            let excepted = KINDS_WITHOUT_A_TOPIC
                .iter()
                .any(|(name, _)| *name == pattern);
            assert!(
                has_row != excepted,
                "{pattern}: a row {has_row}, listed without a topic {excepted}"
            );
        }
    }
}
