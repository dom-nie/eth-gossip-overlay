//! The one QUIC endpoint a sidecar owns: what it binds and what every connection through it
//! agrees to.

use std::time::Duration;

use overlay_core::config::Overlay;
use quinn::{IdleTimeout, VarInt};

/// The parameters every overlay connection runs under, dialled or accepted. One function
/// because there is one place to change: T-076 adds the inbound stream limits, the receive
/// windows and the initial congestion window here once there is a benchmark to move them
/// against, and everything it does not set is quinn's default on purpose.
pub fn transport_config(cfg: &Overlay) -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport
        .keep_alive_interval(Some(cfg.keepalive))
        .max_idle_timeout(Some(idle_timeout(cfg.idle_timeout)));
    transport
}

/// `idle_timeout_ms` as the variable-length integer QUIC carries it in. A value too large to
/// encode saturates rather than failing the bind: an operator who asks for a timeout of 146
/// million years and one who asks for 49 days want the same thing, and neither is a reason to
/// refuse to start.
fn idle_timeout(idle: Duration) -> IdleTimeout {
    IdleTimeout::try_from(idle).unwrap_or_else(|_| IdleTimeout::from(VarInt::MAX))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use overlay_core::config::Overlay;

    use super::*;

    /// quinn's `TransportConfig` has setters and no getters, so its `Debug` output is the only
    /// way to read a value back out. A name that is not in it is a broken test rather than
    /// anything a sidecar could do.
    fn field(transport: &quinn::TransportConfig, name: &str) -> String {
        let debug = format!("{transport:?}");
        let (_, rest) = debug
            .split_once(&format!("{name}: "))
            .expect("TransportConfig's Debug names every field it has");
        rest.split(',')
            .next()
            .expect("split always yields at least one piece")
            .to_owned()
    }

    #[test]
    fn transport_config_uses_keepalive_and_idle_from_config() {
        let cfg = Overlay {
            keepalive: Duration::from_millis(250),
            idle_timeout: Duration::from_millis(3000),
            ..Overlay::default()
        };

        let transport = transport_config(&cfg);

        assert_eq!(field(&transport, "keep_alive_interval"), "Some(250ms)");
        assert_eq!(field(&transport, "max_idle_timeout"), "Some(3000)");
    }

    /// §5.3 asks for probing that starts at 1200 and climbs, which is what quinn does when
    /// nothing sets otherwise. Nothing here does, so this pins the default: a release that
    /// moved it would take the overlay's floor with it and no other test would notice.
    #[test]
    fn mtu_discovery_starts_at_1200() {
        let transport = transport_config(&Overlay::default());

        assert_eq!(field(&transport, "initial_mtu"), "1200");
        assert!(
            field(&transport, "mtu_discovery_config").starts_with("Some("),
            "MTU discovery is off"
        );
        let upper: u16 = field(&transport, "upper_bound")
            .parse()
            .expect("the upper bound is a UDP payload size");
        assert!(upper > 1200, "discovery probes down from {upper}, not up");
    }
}
