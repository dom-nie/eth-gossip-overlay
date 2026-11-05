//! The spec constants the sidecar sizes itself by, as the beacon node reports them (CL-N3).
//!
//! The values live here because two consumers are outside the crate that fetches them: T-083's
//! custody tracker takes its threshold and its bitset size from `NUMBER_OF_COLUMNS`, and the
//! repair task that drives it is in `overlay-transport`. What a beacon node's answer looks like
//! on the wire, and what mainnet's values are when it has not answered yet, both stay in
//! `overlay_bn::spec`, which is the crate that talks to it.

/// The `/eth/v1/config/spec` values the sidecar reads.
///
/// [`Default`] is zeros and means nothing: a consumer takes its values from the `watch`
/// `overlay_bn::spec::spec_watch` opens, which starts at `overlay_bn::spec::MAINNET`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SpecSnapshot {
    /// `DATA_COLUMN_SIDECAR_SUBNET_COUNT`: how many column subnets there are. Equal to
    /// `NUMBER_OF_COLUMNS` on every known network, which T-083 asserts.
    pub data_column_sidecar_subnet_count: u64,
    /// `NUMBER_OF_COLUMNS`: how many columns a block's blobs are extended into. It sizes the
    /// mirror's extra column subscriptions (T-015) and, halved, is the repair threshold
    /// (T-083).
    pub number_of_columns: u64,
    /// `NUMBER_OF_CUSTODY_GROUPS`: how many groups the columns are assigned to for custody.
    pub number_of_custody_groups: u64,
    /// `MAX_PAYLOAD_SIZE`: the largest gossip message the beacon node accepts. The gossipsub
    /// link's limit must agree with it.
    pub max_payload_size: u64,
    /// `SECONDS_PER_SLOT`: the slot length, which times import telemetry.
    pub seconds_per_slot: u64,
    /// `SLOTS_PER_EPOCH`: for turning epoch-denominated spec values into time.
    pub slots_per_epoch: u64,
    /// `GLOAS_FORK_EPOCH`: where column repair starts anchoring on the payload envelope instead
    /// of the block (MD-09). [`FAR_FUTURE_EPOCH`] when the network has not scheduled it.
    pub gloas_fork_epoch: u64,
}

/// What Lighthouse sends for a fork epoch it has not scheduled (`chain_spec.rs`,
/// `serialize_fork_epoch`).
pub const FAR_FUTURE_EPOCH: u64 = u64::MAX;

impl SpecSnapshot {
    /// The first slot of the Gloas fork, or `None` while it is not scheduled. An epoch whose
    /// first slot does not fit a `u64`, [`FAR_FUTURE_EPOCH`] among them, is one no chain reaches.
    pub fn first_gloas_slot(&self) -> Option<u64> {
        self.gloas_fork_epoch.checked_mul(self.slots_per_epoch)
    }
}
