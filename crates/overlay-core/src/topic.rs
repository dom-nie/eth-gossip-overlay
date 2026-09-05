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
}
