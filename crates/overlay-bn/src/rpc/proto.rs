//! The req/resp protocol ids, in one table.

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
