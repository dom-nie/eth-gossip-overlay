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
