//! What a beacon node answers `/eth/v1/config/spec` with, what the sidecar assumes until it
//! has, and the channel the answer arrives on (CL-N3).
//!
//! The values themselves are [`overlay_core::spec::SpecSnapshot`], because `overlay-core` and
//! `overlay-transport` size themselves by them; the wire form and the compiled defaults are
//! here, in the crate that owns the beacon node's HTTP contract.

use serde::Deserialize;
use tokio::sync::watch;

pub use overlay_core::spec::SpecSnapshot;

/// Mainnet as the pinned Lighthouse v8.2.2 ships it. `DATA_COLUMN_SIDECAR_SUBNET_COUNT`,
/// `NUMBER_OF_CUSTODY_GROUPS`, `CUSTODY_REQUIREMENT`, `MAX_PAYLOAD_SIZE` and
/// `SECONDS_PER_SLOT` come from
/// `common/eth2_network_config/built_in_network_configs/mainnet/config.yaml`,
/// `NUMBER_OF_COLUMNS` from `consensus/types/presets/mainnet/fulu.yaml` and
/// `SLOTS_PER_EPOCH` from `consensus/types/presets/mainnet/phase0.yaml`.
pub const MAINNET: SpecSnapshot = SpecSnapshot {
    data_column_sidecar_subnet_count: 128,
    number_of_columns: 128,
    number_of_custody_groups: 128,
    custody_requirement: 4,
    max_payload_size: 10_485_760,
    seconds_per_slot: 12,
    slots_per_epoch: 32,
};

/// The snapshot as the beacon node sends it. Lighthouse serialises every number as a quoted
/// decimal string, so each field parses one; a key it does not send, an older fork, keeps
/// [`MAINNET`]'s value for that field.
#[derive(Deserialize)]
#[serde(default, rename_all = "UPPERCASE")]
pub struct SpecWire {
    #[serde(deserialize_with = "quoted")]
    data_column_sidecar_subnet_count: u64,
    #[serde(deserialize_with = "quoted")]
    number_of_columns: u64,
    #[serde(deserialize_with = "quoted")]
    number_of_custody_groups: u64,
    #[serde(deserialize_with = "quoted")]
    custody_requirement: u64,
    #[serde(deserialize_with = "quoted")]
    max_payload_size: u64,
    #[serde(deserialize_with = "quoted")]
    seconds_per_slot: u64,
    #[serde(deserialize_with = "quoted")]
    slots_per_epoch: u64,
}

impl Default for SpecWire {
    fn default() -> Self {
        Self::from(MAINNET)
    }
}

impl From<SpecSnapshot> for SpecWire {
    fn from(spec: SpecSnapshot) -> Self {
        Self {
            data_column_sidecar_subnet_count: spec.data_column_sidecar_subnet_count,
            number_of_columns: spec.number_of_columns,
            number_of_custody_groups: spec.number_of_custody_groups,
            custody_requirement: spec.custody_requirement,
            max_payload_size: spec.max_payload_size,
            seconds_per_slot: spec.seconds_per_slot,
            slots_per_epoch: spec.slots_per_epoch,
        }
    }
}

impl From<SpecWire> for SpecSnapshot {
    fn from(wire: SpecWire) -> Self {
        Self {
            data_column_sidecar_subnet_count: wire.data_column_sidecar_subnet_count,
            number_of_columns: wire.number_of_columns,
            number_of_custody_groups: wire.number_of_custody_groups,
            custody_requirement: wire.custody_requirement,
            max_payload_size: wire.max_payload_size,
            seconds_per_slot: wire.seconds_per_slot,
            slots_per_epoch: wire.slots_per_epoch,
        }
    }
}

/// The channel consumers read the snapshot from, seeded with mainnet so a value is there
/// before the beacon node has answered. The BN link keeps the sender.
pub fn spec_watch() -> (watch::Sender<SpecSnapshot>, watch::Receiver<SpecSnapshot>) {
    watch::channel(MAINNET)
}

/// A number the BN sends as `"12"`, never as `12`.
fn quoted<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    let text = String::deserialize(deserializer)?;
    text.parse().map_err(|err| {
        serde::de::Error::custom(format!("{text:?} is not a decimal integer: {err}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_watch_starts_at_mainnet_defaults() {
        let (_tx, rx) = spec_watch();

        assert_eq!(*rx.borrow(), MAINNET);
    }

    #[test]
    fn mainnet_is_the_pinned_lighthouse_column_count() {
        assert_eq!(MAINNET.number_of_columns, 128);
        assert_eq!(SpecSnapshot::from(SpecWire::default()), MAINNET);
    }
}
