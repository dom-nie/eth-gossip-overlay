//! The spec constants the sidecar sizes itself by, as the beacon node reports them. Consumers
//! read a `watch` that starts at mainnet, so nothing waits on the beacon node; the BN link
//! replaces the value on every connect.

use serde::Deserialize;

/// The six `/eth/v1/config/spec` values the sidecar reads. Lighthouse serialises every number
/// as a quoted decimal string, so each field parses one; a key the BN does not send, an older
/// fork, keeps that field's [`MAINNET`](Self::MAINNET) value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(default, rename_all = "UPPERCASE")]
pub struct SpecSnapshot {
    /// `DATA_COLUMN_SIDECAR_SUBNET_COUNT`: how many `data_column_sidecar_*` topics a fork
    /// digest has. The sidecar subscribes to all of them.
    #[serde(deserialize_with = "quoted")]
    pub data_column_sidecar_subnet_count: u64,
    /// `NUMBER_OF_COLUMNS`: how many columns a block's blobs are extended into; half of it is
    /// the repair threshold.
    #[serde(deserialize_with = "quoted")]
    pub number_of_columns: u64,
    /// `NUMBER_OF_CUSTODY_GROUPS`: how many groups the columns are assigned to for custody.
    #[serde(deserialize_with = "quoted")]
    pub number_of_custody_groups: u64,
    /// `MAX_PAYLOAD_SIZE`: the largest gossip message the beacon node accepts. The gossipsub
    /// link's limit must agree with it.
    #[serde(deserialize_with = "quoted")]
    pub max_payload_size: u64,
    /// `SECONDS_PER_SLOT`: the slot length, which times import telemetry.
    #[serde(deserialize_with = "quoted")]
    pub seconds_per_slot: u64,
    /// `SLOTS_PER_EPOCH`: for turning epoch-denominated spec values into time.
    #[serde(deserialize_with = "quoted")]
    pub slots_per_epoch: u64,
}

impl SpecSnapshot {
    /// Mainnet as the pinned Lighthouse v8.2.2 ships it. `DATA_COLUMN_SIDECAR_SUBNET_COUNT`,
    /// `NUMBER_OF_CUSTODY_GROUPS`, `MAX_PAYLOAD_SIZE` and `SECONDS_PER_SLOT` come from
    /// `common/eth2_network_config/built_in_network_configs/mainnet/config.yaml`,
    /// `NUMBER_OF_COLUMNS` from `consensus/types/presets/mainnet/fulu.yaml` and
    /// `SLOTS_PER_EPOCH` from `consensus/types/presets/mainnet/phase0.yaml`.
    pub const MAINNET: Self = Self {
        data_column_sidecar_subnet_count: 128,
        number_of_columns: 128,
        number_of_custody_groups: 128,
        max_payload_size: 10_485_760,
        seconds_per_slot: 12,
        slots_per_epoch: 32,
    };
}

impl Default for SpecSnapshot {
    fn default() -> Self {
        Self::MAINNET
    }
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

        assert_eq!(*rx.borrow(), SpecSnapshot::MAINNET);
    }
}
