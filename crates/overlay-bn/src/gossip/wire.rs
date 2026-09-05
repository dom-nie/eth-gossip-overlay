//! The gossipsub values that must equal the beacon node's, copied from Lighthouse v8.2.2
//! (`e423a66763bb1bd780492d635123f208d80c3538`) because the module that builds them,
//! `beacon_node/lighthouse_network/src/config.rs`, is private. Each constant names its source
//! line; the drift tests fail when a Lighthouse bump moves the value.

use crate::spec::SpecSnapshot;

/// The largest gossipsub RPC either side sends or accepts, from
/// `beacon_node/lighthouse_network/src/service/mod.rs:243` (`ctx.chain_spec.max_message_size()`
/// into `gossipsub_max_transmit_size`) with mainnet's `MAX_PAYLOAD_SIZE`.
pub const MAX_TRANSMIT_SIZE: u64 = max_transmit_size_for(SpecSnapshot::MAINNET.max_payload_size);

/// `ChainSpec::max_message_size` from `consensus/types/src/core/chain_spec.rs:859-882`: snappy's
/// worst-case compressed length of the payload, 1024 bytes for framing, floored at 1 MiB.
pub const fn max_transmit_size_for(max_payload_size: u64) -> u64 {
    let compressed = 32 + max_payload_size + max_payload_size / 6;
    let with_framing = compressed + 1024;
    if with_framing > 1024 * 1024 {
        with_framing
    } else {
        1024 * 1024
    }
}
