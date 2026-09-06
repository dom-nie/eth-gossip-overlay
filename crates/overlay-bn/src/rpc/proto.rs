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
    /// Every other id Lighthouse can negotiate: answered `ResourceUnavailable`.
    Unsupported,
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
    (id!("beacon_blocks_by_root", "1"), Protocol::Unsupported),
    (id!("beacon_blocks_by_root", "2"), Protocol::Unsupported),
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
        Protocol::Unsupported,
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
