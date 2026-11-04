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
/// `NUMBER_OF_CUSTODY_GROUPS`, `MAX_PAYLOAD_SIZE` and `SECONDS_PER_SLOT` come from
/// `common/eth2_network_config/built_in_network_configs/mainnet/config.yaml`,
/// `NUMBER_OF_COLUMNS` from `consensus/types/presets/mainnet/fulu.yaml` and
/// `SLOTS_PER_EPOCH` from `consensus/types/presets/mainnet/phase0.yaml`.
pub const MAINNET: SpecSnapshot = SpecSnapshot {
    data_column_sidecar_subnet_count: 128,
    number_of_columns: 128,
    number_of_custody_groups: 128,
    max_payload_size: 10_485_760,
    seconds_per_slot: 12,
    slots_per_epoch: 32,
};

/// The keys [`SpecWire`] reads, in its field order, by the name the beacon node sends.
pub const SPEC_KEYS: [&str; 6] = [
    "DATA_COLUMN_SIDECAR_SUBNET_COUNT",
    "NUMBER_OF_COLUMNS",
    "NUMBER_OF_CUSTODY_GROUPS",
    "MAX_PAYLOAD_SIZE",
    "SECONDS_PER_SLOT",
    "SLOTS_PER_EPOCH",
];

/// The snapshot as the beacon node sends it. Lighthouse serialises every number as a quoted
/// decimal string, so each field parses one. A key it does not send stays `None`, so the
/// client can say which before [`MAINNET`]'s value stands in for it.
#[derive(Default, Deserialize)]
#[serde(default, rename_all = "UPPERCASE")]
pub struct SpecWire {
    #[serde(deserialize_with = "quoted")]
    data_column_sidecar_subnet_count: Option<u64>,
    #[serde(deserialize_with = "quoted")]
    number_of_columns: Option<u64>,
    #[serde(deserialize_with = "quoted")]
    number_of_custody_groups: Option<u64>,
    #[serde(deserialize_with = "quoted")]
    max_payload_size: Option<u64>,
    #[serde(deserialize_with = "quoted")]
    seconds_per_slot: Option<u64>,
    #[serde(deserialize_with = "quoted")]
    slots_per_epoch: Option<u64>,
}

impl SpecWire {
    /// The keys this answer did not carry, each of which takes [`MAINNET`]'s value.
    pub fn missing(&self) -> impl Iterator<Item = &'static str> {
        let values = [
            self.data_column_sidecar_subnet_count,
            self.number_of_columns,
            self.number_of_custody_groups,
            self.max_payload_size,
            self.seconds_per_slot,
            self.slots_per_epoch,
        ];
        SPEC_KEYS
            .into_iter()
            .zip(values)
            .filter_map(|(key, value)| value.is_none().then_some(key))
    }
}

impl From<SpecWire> for SpecSnapshot {
    fn from(wire: SpecWire) -> Self {
        Self {
            data_column_sidecar_subnet_count: wire
                .data_column_sidecar_subnet_count
                .unwrap_or(MAINNET.data_column_sidecar_subnet_count),
            number_of_columns: wire.number_of_columns.unwrap_or(MAINNET.number_of_columns),
            number_of_custody_groups: wire
                .number_of_custody_groups
                .unwrap_or(MAINNET.number_of_custody_groups),
            max_payload_size: wire.max_payload_size.unwrap_or(MAINNET.max_payload_size),
            seconds_per_slot: wire.seconds_per_slot.unwrap_or(MAINNET.seconds_per_slot),
            slots_per_epoch: wire.slots_per_epoch.unwrap_or(MAINNET.slots_per_epoch),
        }
    }
}

/// The channel consumers read the snapshot from, seeded with mainnet so a value is there
/// before the beacon node has answered. The BN link keeps the sender.
pub fn spec_watch() -> (watch::Sender<SpecSnapshot>, watch::Receiver<SpecSnapshot>) {
    watch::channel(MAINNET)
}

/// A number the BN sends as `"12"`, never as `12`.
fn quoted<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<u64>, D::Error> {
    let text = String::deserialize(deserializer)?;
    text.parse().map(Some).map_err(|err| {
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

#[cfg(test)]
mod drift {
    use serde_json::json;
    use types::{ChainSpec, ConfigAndPreset, MainnetEthSpec};

    use super::*;

    /// MD-10: a key Lighthouse stops sending would leave the sidecar on the mainnet value
    /// without a word, so every key the sidecar reads is held against what the handler of
    /// `/eth/v1/config/spec` serialises for mainnet at the pinned tag, read back through
    /// `SpecWire` so that a value format the sidecar cannot parse, or a compiled-in default that
    /// is not mainnet's, fails too. The first assertion is what makes the list the struct's:
    /// six keys each set to 1 leave no field at its default.
    #[test]
    fn spec_keys_the_sidecar_reads_are_in_lighthouse_config() {
        let ones: serde_json::Map<_, _> = SPEC_KEYS
            .iter()
            .map(|k| (k.to_string(), json!("1")))
            .collect();
        let wire: SpecWire = serde_json::from_value(ones.into()).unwrap();
        assert_eq!(
            SpecSnapshot::from(wire),
            SpecSnapshot {
                data_column_sidecar_subnet_count: 1,
                number_of_columns: 1,
                number_of_custody_groups: 1,
                max_payload_size: 1,
                seconds_per_slot: 1,
                slots_per_epoch: 1,
            }
        );

        let lighthouse = serde_json::to_value(ConfigAndPreset::from_chain_spec::<MainnetEthSpec>(
            &ChainSpec::mainnet(),
        ))
        .unwrap();
        let missing: Vec<&str> = SPEC_KEYS
            .into_iter()
            .filter(|key| lighthouse.get(key).is_none())
            .collect();
        assert!(missing.is_empty(), "Lighthouse no longer sends {missing:?}");

        // Present is not enough: each value has to parse the way `SpecWire` reads it, and the
        // compiled-in defaults have to be what Lighthouse's own mainnet says.
        let wire: SpecWire = serde_json::from_value(lighthouse)
            .unwrap_or_else(|err| panic!("Lighthouse's spec no longer parses: {err}"));
        assert_eq!(wire.missing().collect::<Vec<_>>(), Vec::<&str>::new());
        assert_eq!(SpecSnapshot::from(wire), MAINNET);
    }

    /// The warning names what `missing()` returns, so each name has to be the key whose value
    /// is absent and not its neighbour's: every key is dropped from an otherwise complete
    /// answer in turn, and that key alone must come back.
    #[test]
    fn missing_names_exactly_the_key_the_answer_lacks() {
        for absent in SPEC_KEYS {
            let rest: serde_json::Map<_, _> = SPEC_KEYS
                .iter()
                .filter(|key| **key != absent)
                .map(|key| (key.to_string(), json!("1")))
                .collect();
            let wire: SpecWire = serde_json::from_value(rest.into()).unwrap();

            assert_eq!(wire.missing().collect::<Vec<_>>(), [absent]);
        }
    }
}
