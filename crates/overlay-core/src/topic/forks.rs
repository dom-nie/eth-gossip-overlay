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

/// The table. Empty until the drift test says what belongs in it.
pub const FORK_TOPICS: &[ForkTopic] = &[];

/// Kinds the sidecar names that no Lighthouse fork subscribes to, each with the reason it is
/// kept. Holding these here is what lets a test insist that every other kind has a row.
pub const KINDS_WITHOUT_A_TOPIC: [(&str, &str); 0] = [];

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
