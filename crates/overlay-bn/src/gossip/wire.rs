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

/// Publish messages the sidecar accepts in one RPC, `gossipsub_config` at
/// `beacon_node/lighthouse_network/src/config.rs:511`. The beacon node packs IWANT responses
/// by its own limit, so the sidecar must take at least as many. No drift test: the module is
/// private.
pub const MAX_PUBLISH_MESSAGES: usize = 500;
/// Control messages sent in one RPC, `config.rs:512`. No drift test: the module is private.
pub const MAX_CONTROL_MESSAGES_SENT: usize = 500;
/// The largest control message or subscription accepted in one RPC, `config.rs:513`. The
/// beacon node subscribes to hundreds of topics at a fork and the fork's 16 KiB default would
/// reject that RPC. No drift test: the module is private.
pub const MAX_CONTROL_MESSAGE_SIZE: usize = 128 << 10;

/// The most a payload may decompress to. The beacon node's `SnappyTransform::inbound_transform`
/// (`beacon_node/lighthouse_network/src/types/pubsub.rs:106`) refuses anything past
/// `max_uncompressed_len`, which `service/mod.rs:343` sets to `spec.max_payload_size`, so the
/// message id must use the same bound or it would give a valid-domain id to a payload the BN
/// never accepts.
pub const MAX_PAYLOAD_SIZE: u64 = SpecSnapshot::MAINNET.max_payload_size;

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
/// and compares it with the compiled constant. T-018's consumer of the spec watch calls this
/// whenever the snapshot changes.
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
    use crate::gossip::{self, BnLinkConfig, build_behaviour, config};

    fn cfg() -> BnLinkConfig {
        BnLinkConfig {
            idontwant_on_publish: true,
        }
    }

    #[test]
    fn max_payload_size_equals_lighthouse() {
        assert_eq!(
            MAX_PAYLOAD_SIZE,
            types::ChainSpec::mainnet().max_payload_size
        );
    }

    /// `overlay-core` carries the same number for its frame limits and cannot reach Lighthouse
    /// itself, because the dependency runs this way round. This is the only place the two can be
    /// compared (T-024).
    #[test]
    fn max_payload_size_equals_the_frame_codec_limit() {
        assert_eq!(
            MAX_PAYLOAD_SIZE,
            overlay_core::wire::MAX_PAYLOAD_BYTES as u64
        );
    }

    /// `lighthouse_network::config` is private, so the comparison is with the value it reads
    /// from `ChainSpec`, which is what reaches `max_transmit_size(..)`.
    #[test]
    fn max_transmit_size_equals_lighthouse() {
        let lighthouse = types::ChainSpec::mainnet().max_message_size() as u64;

        assert_eq!(MAX_TRANSMIT_SIZE, lighthouse);
        assert_eq!(config(&cfg()).max_transmit_size() as u64, lighthouse);
    }

    /// Local policy rather than wire-compat, but the table claims it equals the beacon node's
    /// default and `NetworkConfig` is public, so the claim is pinned.
    #[test]
    fn idontwant_threshold_equals_lighthouse_default() {
        assert_eq!(
            gossip::IDONTWANT_MESSAGE_SIZE_THRESHOLD,
            lighthouse_network::NetworkConfig::default().idontwant_message_size_threshold
        );
    }

    /// `Config` has no getter for the ids, so this reads what a fresh connection's handler
    /// offers to negotiate, which is the list the beacon node sees.
    #[test]
    fn protocol_ids_equal_lighthouse() {
        let mut behaviour = build_behaviour(&cfg(), &mut Registry::default());
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
    use crate::gossip::{BnLinkConfig, config};

    /// The beacon node sizes its RPCs by its own limits, so the sidecar must accept at least
    /// what Lighthouse is willing to send in one RPC.
    #[test]
    fn rpc_limits_equal_the_copied_lighthouse_values() {
        let config = config(&BnLinkConfig {
            idontwant_on_publish: true,
        });

        assert_eq!(config.max_publish_messages(), MAX_PUBLISH_MESSAGES);
        assert_eq!(
            config.max_control_messages_sent(),
            MAX_CONTROL_MESSAGES_SENT
        );
        assert_eq!(config.max_control_message_size(), MAX_CONTROL_MESSAGE_SIZE);
        assert_eq!(
            (
                MAX_PUBLISH_MESSAGES,
                MAX_CONTROL_MESSAGES_SENT,
                MAX_CONTROL_MESSAGE_SIZE
            ),
            (500, 500, 128 << 10)
        );
    }

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
