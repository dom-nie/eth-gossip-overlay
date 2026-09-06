//! The one QUIC endpoint a sidecar owns: what it binds and what every connection through it
//! agrees to.

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
}
