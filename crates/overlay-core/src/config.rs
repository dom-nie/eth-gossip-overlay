//! The `config.yaml` model. Every tunable the sidecar has lives here as a typed field with an
//! Appendix A default, so the rest of the code reads a struct and never a key name. The file is
//! pushed to every host by configuration management, so an unknown or removed key fails loudly
//! at startup instead of silently taking a default.

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::time::Duration;

    use super::*;

    /// Architecture.md Appendix A, verbatim. The defaults are pinned to this text.
    const APPENDIX_A: &str = r#"
overlay:
  listen: "[::]:7788"           # dual-stack, default public interface, no interface selection
  roster_file: /etc/fleet-overlay/roster.yaml   # re-read on SIGHUP and within 10 s of a change
  fleet_seed_file: /etc/fleet-overlay/seed      # $CREDENTIALS_DIRECTORY/seed wins when the unit uses LoadCredential=
  # fleet_seed_previous_file: /etc/fleet-overlay/seed.previous   # optional, set only while a seed rotation is in progress
  keepalive_ms: 1000
  idle_timeout_ms: 5000
  initial_window_bytes: 4000000
  fanout:
    large:
      in_region: stripe         # chunk i to host i, second hop in-region
      cross_region: stripe      # second independent stripe over the other region, no relay
      stripe_min_recipients: 16 # below this, send whole messages directly
    small:
      in_region: direct
      cross_region: relays      # or direct
      relays_per_remote_region: 3
      relay_min_remote_hosts: 12  # fewer live subscribed hosts in a remote region: send to them directly
  io_thread:
    pin_cpu: null               # a reserved core pins the overlay I/O thread; off by default
    prefer_busy_poll: false
    busy_poll_usecs: 100
    steering: off               # auto: ntuple flow rule if the NIC supports it, else RFS
bn:
  identity_url: http://127.0.0.1:5052/eth/v1/node/identity
  events_url: http://127.0.0.1:5052/eth/v1/events?topics=block
  libp2p_addr: /ip4/127.0.0.1/tcp/9000
  node_key_file: /var/lib/fleet-overlay/node.key   # per-host libp2p identity, created on first start
  publish_rate_limit:
    small_per_s: 8000
    large_per_s: 300
    bytes_per_s: 33554432
  idontwant_on_publish: true
classes:
  small:
    batch_window_ms: 10
    stale_after_ms: 1000
  large:
    chunk_bytes: 2048
    parity_ratio: 0.10
    repair_deadline_ms: 250     # measured from the first chunk
inject: true
admin_socket: /run/fleet-overlay/admin.sock
metrics_listen: 127.0.0.1:7789
log:
  level: info
  format: auto                  # json when stdout is not a TTY, else text; RUST_LOG overrides
"#;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn appendix_a_example_parses_to_expected_values() {
        let cfg = Config::from_yaml(APPENDIX_A).unwrap();

        assert_eq!(cfg.overlay.listen, addr("[::]:7788"));
        assert_eq!(cfg.overlay.fanout.small.relays_per_remote_region, 3);
        assert_eq!(cfg.overlay.fanout.small.relay_min_remote_hosts, 12);
        assert_eq!(cfg.classes.large.chunk_bytes, 2048);
        assert_eq!(
            cfg.classes.large.repair_deadline,
            Duration::from_millis(250)
        );
        assert!(cfg.inject);
        assert_eq!(cfg.overlay.io_thread.pin_cpu, None);
        assert_eq!(cfg.metrics_listen, addr("127.0.0.1:7789"));
        assert_eq!(
            cfg.bn.node_key_file,
            PathBuf::from("/var/lib/fleet-overlay/node.key")
        );
        assert_eq!(cfg.bn.publish_rate_limit.small_per_s, 8000);
        assert_eq!(cfg.log.format, LogFormat::Auto);
    }
}
