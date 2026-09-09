//! The req/resp protocol ids, in one table: every id Lighthouse v8.2.2 can negotiate
//! (`SupportedProtocol` in `beacon_node/lighthouse_network/src/rpc/protocol.rs`), rendered the
//! way `ProtocolId::new` does, `/eth2/beacon_chain/req/<name>/<version>/ssz_snappy`, each with
//! what the sidecar does when it is negotiated. Lighthouse offers a fork-dependent subset of
//! these to a peer; registering all of them means any request it can make gets a well-formed
//! answer instead of a negotiation failure it would log. The drift test compares the table with
//! Lighthouse's enum in both directions.

use libp2p::StreamProtocol;

/// What the sidecar does with a negotiated protocol id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    /// `status/1`: echoed.
    StatusV1,
    /// `status/2`: echoed, with `earliest_available_slot`.
    StatusV2,
    /// `ping/1`: answered with the metadata sequence number.
    PingV1,
    /// `metadata/1`: answered with `seq_number` and `attnets`.
    MetaDataV1,
    /// `metadata/2`: answered with `syncnets` as well.
    MetaDataV2,
    /// `metadata/3`: answered with the custody group count as well.
    MetaDataV3,
    /// `goodbye/1`: the connection is closed.
    GoodbyeV1,
    /// `beacon_blocks_by_root/2`: answered out of the recent store while the by-root cache is
    /// on, and `ResourceUnavailable` otherwise (§5.8).
    BlocksByRootV2,
    /// `data_column_sidecars_by_root/1`: the same.
    ColumnsByRootV1,
    /// Every other id Lighthouse can negotiate: answered `ResourceUnavailable`.
    Unsupported,
}

impl Protocol {
    /// The `protocol` label of `by_root_requests_total`, empty for an id the cache never serves.
    pub fn as_label(self) -> &'static str {
        match self {
            Self::BlocksByRootV2 => "beacon_blocks_by_root",
            Self::ColumnsByRootV1 => "data_column_sidecars_by_root",
            _ => "",
        }
    }
}

macro_rules! id {
    ($name:literal, $version:literal) => {
        StreamProtocol::new(concat!(
            "/eth2/beacon_chain/req/",
            $name,
            "/",
            $version,
            "/ssz_snappy"
        ))
    };
}

/// The table, in `SupportedProtocol`'s order.
static TABLE: [(StreamProtocol, Protocol); 22] = [
    (id!("status", "1"), Protocol::StatusV1),
    (id!("status", "2"), Protocol::StatusV2),
    (id!("goodbye", "1"), Protocol::GoodbyeV1),
    (id!("beacon_blocks_by_range", "1"), Protocol::Unsupported),
    (id!("beacon_blocks_by_range", "2"), Protocol::Unsupported),
    // Version 1 stays unserved. Its response chunks carry no context bytes, so Lighthouse reads
    // one as a phase-0 block, and every block this sidecar holds is of a later fork; an answer
    // would be a decode error at the requester rather than the block it asked for. Lighthouse
    // offers v2 first and its own lookups build v2 requests.
    (id!("beacon_blocks_by_root", "1"), Protocol::Unsupported),
    (id!("beacon_blocks_by_root", "2"), Protocol::BlocksByRootV2),
    (id!("beacon_blocks_by_head", "1"), Protocol::Unsupported),
    (
        id!("execution_payload_envelopes_by_range", "1"),
        Protocol::Unsupported,
    ),
    (
        id!("execution_payload_envelopes_by_root", "1"),
        Protocol::Unsupported,
    ),
    (id!("blob_sidecars_by_range", "1"), Protocol::Unsupported),
    (id!("blob_sidecars_by_root", "1"), Protocol::Unsupported),
    (
        id!("data_column_sidecars_by_root", "1"),
        Protocol::ColumnsByRootV1,
    ),
    (
        id!("data_column_sidecars_by_range", "1"),
        Protocol::Unsupported,
    ),
    (id!("ping", "1"), Protocol::PingV1),
    (id!("metadata", "1"), Protocol::MetaDataV1),
    (id!("metadata", "2"), Protocol::MetaDataV2),
    (id!("metadata", "3"), Protocol::MetaDataV3),
    (id!("light_client_bootstrap", "1"), Protocol::Unsupported),
    (
        id!("light_client_optimistic_update", "1"),
        Protocol::Unsupported,
    ),
    (
        id!("light_client_finality_update", "1"),
        Protocol::Unsupported,
    ),
    (
        id!("light_client_updates_by_range", "1"),
        Protocol::Unsupported,
    ),
];

/// Every id the sidecar registers with the request-response behaviour.
pub fn all() -> impl Iterator<Item = StreamProtocol> {
    TABLE.iter().map(|(id, _)| id.clone())
}

/// What to do with a negotiated id. Only ids from [`all`] are ever negotiated, so an unknown
/// one can only be a table edit gone wrong; it is treated like any other unsupported protocol.
pub fn classify(id: &StreamProtocol) -> Protocol {
    TABLE
        .iter()
        .find(|(known, _)| known == id)
        .map_or(Protocol::Unsupported, |(_, protocol)| *protocol)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use lighthouse_network::rpc::RequestType;
    use lighthouse_network::rpc::methods::Ping;
    use strum::IntoEnumIterator;
    use types::MainnetEthSpec;

    use super::*;

    /// `SupportedProtocol` and `ProtocolId` live in a module Lighthouse keeps private, so the
    /// enum is reached through a value (`RequestType::versioned_protocol` returns one) and
    /// strum's `EnumIter` on it yields every variant.
    fn every_variant<T: IntoEnumIterator>(_: &T) -> T::Iterator {
        T::iter()
    }

    /// Both directions: every variant Lighthouse has is in the table, and nothing else is.
    /// The prefix and encoding segment are checked against a `ProtocolId` Lighthouse renders
    /// itself, the names and versions come from the enum.
    #[test]
    fn registered_protocol_list_matches_lighthouse_supported_protocols() {
        let ping = RequestType::<MainnetEthSpec>::Ping(Ping { data: 0 });
        let ping_ids = ping.supported_protocols();
        let rendered: Vec<&str> = ping_ids.iter().map(AsRef::as_ref).collect();
        assert_eq!(rendered, ["/eth2/beacon_chain/req/ping/1/ssz_snappy"]);

        let lighthouse: BTreeSet<String> = every_variant(&ping.versioned_protocol())
            .map(|variant| {
                format!(
                    "/eth2/beacon_chain/req/{}/{}/ssz_snappy",
                    variant.protocol(),
                    variant.version_string()
                )
            })
            .collect();
        let ours: BTreeSet<String> = all().map(|id| id.as_ref().to_owned()).collect();

        assert_eq!(ours, lighthouse);
        assert_eq!(
            all().count(),
            lighthouse.len(),
            "a duplicate id in the table"
        );
    }
}
