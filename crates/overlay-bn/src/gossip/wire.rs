//! The gossipsub values that must equal the beacon node's, copied from Lighthouse v8.2.2
//! (`e423a66763bb1bd780492d635123f208d80c3538`) because the module that builds them,
//! `beacon_node/lighthouse_network/src/config.rs`, is private. Each constant names its source
//! line; the drift tests fail when a Lighthouse bump moves the value.

use crate::spec::SpecSnapshot;

/// The protocol ids both sides negotiate, newest first. Lighthouse sets no prefix
/// (`gossipsub_config` in `beacon_node/lighthouse_network/src/config.rs:450-523` never calls
/// `protocol_id_prefix`), so these are the fork's defaults from
/// `protocols/gossipsub/src/protocol.rs:49-66` and `Default for ProtocolConfig` at rev
/// `c774d4e71357d7cd2f792c4767d616d2dd369ee3`. `1.3.0` is the partial-messages extension.
pub const PROTOCOL_IDS: [&str; 4] = [
    "/meshsub/1.3.0",
    "/meshsub/1.2.0",
    "/meshsub/1.1.0",
    "/meshsub/1.0.0",
];

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

/// The beacon node's `MAX_PAYLOAD_SIZE` gives a transmit size other than the compiled one: a
/// Lighthouse or a network this binary was not built for. The behaviour is not rebuilt; T-018
/// logs it and shows `overlay_bn_compat{state="size_mismatch"}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error(
    "max transmit size mismatch: compiled for {compiled} bytes, the beacon node's spec gives {bn}"
)]
pub struct SizeMismatch {
    /// [`MAX_TRANSMIT_SIZE`].
    pub compiled: u64,
    /// What the BN's spec value derives to.
    pub bn: u64,
}

/// Derives the transmit size the beacon node runs with from the `MAX_PAYLOAD_SIZE` it reports
/// and compares it with the compiled constant. The BN link calls this on every connect.
pub fn check_max_payload_size(spec_max_payload_size: u64) -> Result<(), SizeMismatch> {
    let bn = max_transmit_size_for(spec_max_payload_size);
    if bn == MAX_TRANSMIT_SIZE {
        Ok(())
    } else {
        Err(SizeMismatch {
            compiled: MAX_TRANSMIT_SIZE,
            bn,
        })
    }
}

#[cfg(test)]
mod drift {
    use libp2p::core::UpgradeInfo;
    use libp2p::swarm::{ConnectionHandler, ConnectionId, NetworkBehaviour};
    use libp2p::{Multiaddr, PeerId};
    use prometheus_client::registry::Registry;

    use super::*;
    use crate::gossip::{BnLinkConfig, build_behaviour};

    /// `Config` has no getter for the ids, so this reads what a fresh connection's handler
    /// offers to negotiate, which is the list the beacon node sees.
    #[test]
    fn protocol_ids_equal_lighthouse() {
        let cfg = BnLinkConfig {
            idontwant_on_publish: true,
        };
        let mut behaviour = build_behaviour(&cfg, &mut Registry::default());
        let addr: Multiaddr = "/memory/1".parse().unwrap();

        let handler = behaviour
            .handle_established_inbound_connection(
                ConnectionId::new_unchecked(0),
                PeerId::random(),
                &addr,
                &addr,
            )
            .unwrap();
        let advertised: Vec<String> = handler
            .listen_protocol()
            .upgrade()
            .protocol_info()
            .into_iter()
            .map(|id| AsRef::<str>::as_ref(&id).to_owned())
            .collect();

        assert_eq!(advertised, PROTOCOL_IDS);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_payload_size_mismatch_is_reported() {
        assert_eq!(
            check_max_payload_size(SpecSnapshot::MAINNET.max_payload_size),
            Ok(())
        );

        let bn = SpecSnapshot::MAINNET.max_payload_size + 1;

        assert_eq!(
            check_max_payload_size(bn),
            Err(SizeMismatch {
                compiled: MAX_TRANSMIT_SIZE,
                bn: max_transmit_size_for(bn),
            })
        );
    }
}
