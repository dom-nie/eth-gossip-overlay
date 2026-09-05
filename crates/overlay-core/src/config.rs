//! The `config.yaml` model. Every tunable the sidecar has lives here as a typed field with an
//! Appendix A default, so the rest of the code reads a struct and never a key name. The file is
//! pushed to every host by configuration management, so an unknown or removed key fails loudly
//! at startup instead of silently taking a default.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Deserializer};
use serde_yaml_bw as yaml;
use url::Url;

/// The whole `config.yaml`, one field per key.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// `overlay`: the QUIC mesh between sidecars.
    pub overlay: Overlay,
    /// `bn`: the link to the local beacon node.
    pub bn: Bn,
    /// `classes`: tunables for the small and large traffic classes.
    pub classes: Classes,
    /// `inject`: whether the sidecar publishes what it receives into the beacon node. `false`
    /// is the kill switch: the sidecar keeps observing and reporting but changes nothing.
    pub inject: bool,
    /// `admin_socket`: the Unix socket `fleet-overlayctl` connects to.
    pub admin_socket: PathBuf,
    /// `metrics_listen`: where the Prometheus scrape endpoint binds.
    pub metrics_listen: SocketAddr,
    /// `log`: level and format of the single log stream.
    pub log: Log,
}

/// `overlay`: the QUIC mesh between sidecars.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Overlay {
    /// `listen`: the address the QUIC endpoint binds. `[::]` listens dual-stack.
    pub listen: SocketAddr,
    /// `roster_file`: the fleet roster, re-read on SIGHUP and whenever the file changes.
    pub roster_file: PathBuf,
    /// `fleet_seed_file`: the shared secret every overlay TLS key derives from.
    pub fleet_seed_file: PathBuf,
    /// `fleet_seed_previous_file`: the outgoing seed while a rotation is in progress, so peers
    /// still on it keep pairing. Absent or `null` otherwise.
    pub fleet_seed_previous_file: Option<PathBuf>,
    /// `keepalive_ms`: the QUIC keepalive interval. Shorter than `idle_timeout_ms`, or every
    /// quiet connection would drop.
    #[serde(rename = "keepalive_ms", deserialize_with = "millis")]
    pub keepalive: Duration,
    /// `idle_timeout_ms`: how long a silent connection lives before QUIC closes it.
    #[serde(rename = "idle_timeout_ms", deserialize_with = "millis")]
    pub idle_timeout: Duration,
    /// `initial_window_bytes`: the initial congestion window. A connection that carries one
    /// block every 12 s never leaves slow start with the RFC default.
    pub initial_window_bytes: u64,
    /// `fanout`: how each traffic class reaches its own region and the others.
    pub fanout: Fanout,
    /// `io_thread`: latency tuning for the overlay I/O thread. Linux only, off by default.
    pub io_thread: IoThread,
}

/// `overlay.fanout`: routing per traffic class.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Fanout {
    /// `large`: blocks and data columns.
    pub large: LargeFanout,
    /// `small`: attestations and the rest of the per-slot chatter.
    pub small: SmallFanout,
}

/// `overlay.fanout.large`.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LargeFanout {
    /// `in_region`: how a large message reaches the origin's own region.
    pub in_region: InRegion,
    /// `cross_region`: how it reaches each other region.
    pub cross_region: CrossRegion,
    /// `stripe_min_recipients`: with fewer subscribed recipients than this the message goes out
    /// whole; a stripe over a handful of hosts saves nothing.
    pub stripe_min_recipients: usize,
}

/// `overlay.fanout.small`.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SmallFanout {
    /// `in_region`: how a batch reaches the origin's own region.
    pub in_region: InRegion,
    /// `cross_region`: how it reaches each other region.
    pub cross_region: CrossRegion,
    /// `relays_per_remote_region`: how many hosts in a remote region receive a batch and re-fan
    /// it locally.
    pub relays_per_remote_region: usize,
    /// `relay_min_remote_hosts`: a remote region with fewer live subscribed hosts than this is
    /// sent to directly; relaying would not save enough WAN traffic to pay for the extra hop.
    pub relay_min_remote_hosts: usize,
}

/// How a message reaches hosts in the origin's own region.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InRegion {
    /// Chunk `i` to host `i`, each host forwarding its chunk to the rest.
    Stripe,
    /// Whole messages to every subscribed host.
    Direct,
}

/// How a message reaches hosts in another region.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CrossRegion {
    /// An independent stripe over the remote region's subscribed hosts.
    Stripe,
    /// Whole messages to every subscribed host over the WAN.
    Direct,
    /// A few hosts in the remote region receive the batch and re-fan it in-region.
    Relays,
}

/// `overlay.io_thread`.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IoThread {
    /// `pin_cpu`: a reserved core to pin the overlay I/O thread to. `null` leaves it unpinned.
    pub pin_cpu: Option<u32>,
    /// `prefer_busy_poll`: spin on the socket instead of waiting for interrupts.
    pub prefer_busy_poll: bool,
    /// `busy_poll_usecs`: how long each busy-poll spin lasts.
    pub busy_poll_usecs: u32,
    /// `steering`: how the overlay's packets are steered to the pinned core's NIC queue.
    pub steering: Steering,
}

/// `overlay.io_thread.steering`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Steering {
    /// An ntuple flow rule if the NIC supports it, else RFS.
    Auto,
    /// An ntuple flow rule only.
    Ntuple,
    /// Receive flow steering in the kernel.
    Rfs,
    /// No steering.
    Off,
}

/// `bn`: the link to the local beacon node.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Bn {
    /// `identity_url`: the beacon API endpoint that reports the node's peer id.
    pub identity_url: Url,
    /// `events_url`: the beacon API event stream.
    pub events_url: Url,
    /// `libp2p_addr`: the multiaddr the sidecar dials to join the beacon node's gossipsub.
    pub libp2p_addr: String,
    /// `node_key_file`: the sidecar's own libp2p identity, per host, created on first start.
    pub node_key_file: PathBuf,
    /// `publish_rate_limit`: ceilings on what the sidecar injects into the beacon node.
    pub publish_rate_limit: PublishRateLimit,
    /// `idontwant_on_publish`: tell the beacon node IDONTWANT for a message as it is published.
    pub idontwant_on_publish: bool,
}

/// `bn.publish_rate_limit`: class-aware ceilings on the publish path. A bug guard, not a normal
/// control; the defaults sit well above any legitimate rate.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PublishRateLimit {
    /// `small_per_s`: small-class messages per second.
    pub small_per_s: u32,
    /// `large_per_s`: large-class messages per second.
    pub large_per_s: u32,
    /// `bytes_per_s`: payload bytes per second across both classes.
    pub bytes_per_s: u64,
}

/// `classes`: tunables per traffic class.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Classes {
    /// `small`: batched small messages over datagrams.
    pub small: SmallClass,
    /// `large`: striped large messages over streams.
    pub large: LargeClass,
}

/// `classes.small`.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SmallClass {
    /// `batch_window_ms`: how long a batch collects entries before it is flushed.
    #[serde(rename = "batch_window_ms", deserialize_with = "millis")]
    pub batch_window: Duration,
    /// `stale_after_ms`: a batch older than this is dropped rather than delivered late.
    #[serde(rename = "stale_after_ms", deserialize_with = "millis")]
    pub stale_after: Duration,
}

/// `classes.large`.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LargeClass {
    /// `chunk_bytes`: the fixed chunk size. A multiple of 64, which the Reed-Solomon shards
    /// require.
    pub chunk_bytes: usize,
    /// `parity_ratio`: parity chunks as a fraction of data chunks.
    pub parity_ratio: f64,
    /// `repair_deadline_ms`: how long after the first chunk a receiver waits before asking peers
    /// for the missing ones.
    #[serde(rename = "repair_deadline_ms", deserialize_with = "millis")]
    pub repair_deadline: Duration,
}

/// `log`.
#[derive(Clone, Debug, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Log {
    /// `level`: the least severe level that is emitted. `RUST_LOG` overrides it.
    pub level: LogLevel,
    /// `format`: how the log stream is rendered.
    pub format: LogFormat,
}

/// `log.level`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Everything.
    Trace,
    /// Diagnostics for someone reading the code.
    Debug,
    /// Normal operation.
    Info,
    /// Something an operator should look at.
    Warn,
    /// Something is broken.
    Error,
}

/// `log.format`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// JSON when stdout is not a TTY, text otherwise.
    Auto,
    /// One JSON object per line.
    Json,
    /// Human-readable lines.
    Text,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            overlay: Overlay::default(),
            bn: Bn::default(),
            classes: Classes::default(),
            inject: true,
            admin_socket: PathBuf::from("/run/fleet-overlay/admin.sock"),
            metrics_listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 7789)),
            log: Log::default(),
        }
    }
}

impl Default for Overlay {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from((Ipv6Addr::UNSPECIFIED, 7788)),
            roster_file: PathBuf::from("/etc/fleet-overlay/roster.yaml"),
            fleet_seed_file: PathBuf::from("/etc/fleet-overlay/seed"),
            fleet_seed_previous_file: None,
            keepalive: Duration::from_millis(1000),
            idle_timeout: Duration::from_millis(5000),
            initial_window_bytes: 4_000_000,
            fanout: Fanout::default(),
            io_thread: IoThread::default(),
        }
    }
}

impl Default for LargeFanout {
    fn default() -> Self {
        Self {
            in_region: InRegion::Stripe,
            cross_region: CrossRegion::Stripe,
            stripe_min_recipients: 16,
        }
    }
}

impl Default for SmallFanout {
    fn default() -> Self {
        Self {
            in_region: InRegion::Direct,
            cross_region: CrossRegion::Relays,
            relays_per_remote_region: 3,
            relay_min_remote_hosts: 12,
        }
    }
}

impl Default for IoThread {
    fn default() -> Self {
        Self {
            pin_cpu: None,
            prefer_busy_poll: false,
            busy_poll_usecs: 100,
            steering: Steering::Off,
        }
    }
}

impl Default for Bn {
    fn default() -> Self {
        Self {
            identity_url: url("http://127.0.0.1:5052/eth/v1/node/identity"),
            events_url: url("http://127.0.0.1:5052/eth/v1/events?topics=block"),
            libp2p_addr: "/ip4/127.0.0.1/tcp/9000".to_owned(),
            node_key_file: PathBuf::from("/var/lib/fleet-overlay/node.key"),
            publish_rate_limit: PublishRateLimit::default(),
            idontwant_on_publish: true,
        }
    }
}

impl Default for PublishRateLimit {
    fn default() -> Self {
        Self {
            small_per_s: 8000,
            large_per_s: 300,
            bytes_per_s: 32 * 1024 * 1024,
        }
    }
}

impl Default for SmallClass {
    fn default() -> Self {
        Self {
            batch_window: Duration::from_millis(10),
            stale_after: Duration::from_millis(1000),
        }
    }
}

impl Default for LargeClass {
    fn default() -> Self {
        Self {
            chunk_bytes: 2048,
            parity_ratio: 0.10,
            repair_deadline: Duration::from_millis(250),
        }
    }
}

impl Default for Log {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Auto,
        }
    }
}

/// Parses one of the URL literals in the defaults above.
#[expect(
    clippy::expect_used,
    reason = "only called on the Appendix A literals, which are valid URLs"
)]
fn url(literal: &str) -> Url {
    Url::parse(literal).expect("Appendix A URL literal")
}

/// Why a configuration could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The file could not be read.
    #[error("{}: {source}", .path.display())]
    Io {
        /// The file that was asked for.
        path: PathBuf,
        /// What the filesystem said.
        source: std::io::Error,
    },
    /// The text is not valid YAML or does not fit the schema.
    #[error("{source}")]
    Parse {
        /// The parser's own error, which names the offending key and its position.
        source: yaml::Error,
    },
    /// A value parsed but is outside what the sidecar can run with.
    #[error("{field}: {reason}")]
    Invalid {
        /// The dotted YAML path of the offending key, such as `classes.large.chunk_bytes`.
        field: &'static str,
        /// What is wrong with the value.
        reason: String,
    },
}

impl Config {
    /// Reads and parses the file at `path`.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_owned(),
            source,
        })?;
        Self::from_yaml(&text)
    }

    /// Parses a complete `config.yaml` document.
    pub fn from_yaml(text: &str) -> Result<Self, ConfigError> {
        // Not yaml::from_str: on any error it retries through a Value tree to resolve merge
        // keys and returns that second error, which has lost the key path and the line.
        let config = Self::deserialize(yaml::Deserializer::from_str(text))
            .map_err(|source| ConfigError::Parse { source })?;
        config.validate()?;
        Ok(config)
    }

    /// Range and cross-field checks the types alone cannot express.
    fn validate(&self) -> Result<(), ConfigError> {
        let chunk = self.classes.large.chunk_bytes;
        if chunk == 0 || !chunk.is_multiple_of(64) {
            return Err(invalid(
                "classes.large.chunk_bytes",
                format!("{chunk} is not a positive multiple of 64"),
            ));
        }
        let ratio = self.classes.large.parity_ratio;
        if !(0.0..=1.0).contains(&ratio) {
            return Err(invalid(
                "classes.large.parity_ratio",
                format!("{ratio} is outside 0.0..=1.0"),
            ));
        }
        let (keepalive, idle) = (self.overlay.keepalive, self.overlay.idle_timeout);
        if keepalive >= idle {
            return Err(invalid(
                "overlay.keepalive_ms",
                format!(
                    "{} ms is not shorter than idle_timeout_ms ({} ms)",
                    keepalive.as_millis(),
                    idle.as_millis()
                ),
            ));
        }
        let (window, stale) = (
            self.classes.small.batch_window,
            self.classes.small.stale_after,
        );
        if stale < window {
            return Err(invalid(
                "classes.small.stale_after_ms",
                format!(
                    "{} ms is shorter than batch_window_ms ({} ms)",
                    stale.as_millis(),
                    window.as_millis()
                ),
            ));
        }
        let (fanout, limits) = (&self.overlay.fanout, &self.bn.publish_rate_limit);
        for (field, zero) in [
            (
                "overlay.fanout.large.stripe_min_recipients",
                fanout.large.stripe_min_recipients == 0,
            ),
            (
                "overlay.fanout.small.relays_per_remote_region",
                fanout.small.relays_per_remote_region == 0,
            ),
            ("bn.publish_rate_limit.small_per_s", limits.small_per_s == 0),
            ("bn.publish_rate_limit.large_per_s", limits.large_per_s == 0),
            ("bn.publish_rate_limit.bytes_per_s", limits.bytes_per_s == 0),
        ] {
            if zero {
                return Err(invalid(field, "must be at least 1".to_owned()));
            }
        }
        Ok(())
    }
}

fn invalid(field: &'static str, reason: String) -> ConfigError {
    ConfigError::Invalid { field, reason }
}

/// Reads an integer `_ms` key as a [`Duration`], so nothing downstream multiplies by 1000.
fn millis<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Duration, D::Error> {
    u64::deserialize(deserializer).map(Duration::from_millis)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
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

    #[test]
    fn empty_document_equals_default() {
        assert_eq!(Config::from_yaml("{}").unwrap(), Config::default());
    }

    #[test]
    fn default_equals_appendix_a() {
        assert_eq!(Config::from_yaml(APPENDIX_A).unwrap(), Config::default());
    }

    #[test]
    fn unknown_field_is_rejected_with_its_name() {
        let err = Config::from_yaml("overlay: { keepalive_sm: 5 }").unwrap_err();

        assert!(err.to_string().contains("keepalive_sm"), "{err}");
    }

    #[test]
    fn removed_keys_are_rejected_with_their_names() {
        for (doc, key) in [
            ("overlay: { auth: pinned }", "auth"),
            (
                "overlay: { fanout: { relay_selection: rtt } }",
                "relay_selection",
            ),
            (
                "bn: { publish_rate_limit_per_s: 20000 }",
                "publish_rate_limit_per_s",
            ),
        ] {
            let err = Config::from_yaml(doc).unwrap_err();

            assert!(err.to_string().contains(key), "{doc}: {err}");
        }
    }

    #[test]
    fn pin_cpu_accepts_null_and_an_integer() {
        let null = Config::from_yaml("overlay: { io_thread: { pin_cpu: null } }").unwrap();
        let absent =
            Config::from_yaml("overlay: { io_thread: { prefer_busy_poll: true } }").unwrap();
        let pinned = Config::from_yaml("overlay: { io_thread: { pin_cpu: 30 } }").unwrap();

        assert_eq!(null.overlay.io_thread.pin_cpu, None);
        assert_eq!(absent.overlay.io_thread.pin_cpu, None);
        assert_eq!(pinned.overlay.io_thread.pin_cpu, Some(30));
    }

    #[test]
    fn previous_seed_file_is_none_unless_set() {
        let absent = Config::from_yaml("{}").unwrap();
        let set = Config::from_yaml(
            "overlay: { fleet_seed_previous_file: /etc/fleet-overlay/seed.previous }",
        )
        .unwrap();

        assert_eq!(absent.overlay.fleet_seed_previous_file, None);
        assert_eq!(
            set.overlay.fleet_seed_previous_file,
            Some(PathBuf::from("/etc/fleet-overlay/seed.previous"))
        );
    }

    #[test]
    fn log_enums_are_closed_sets() {
        let ok = Config::from_yaml("log: { format: json, level: debug }").unwrap();
        assert_eq!(ok.log.format, LogFormat::Json);
        assert_eq!(ok.log.level, LogLevel::Debug);

        for (doc, field) in [
            ("log: { format: logfmt }", "log.format"),
            ("log: { level: verbose }", "log.level"),
        ] {
            let err = Config::from_yaml(doc).unwrap_err();

            assert!(err.to_string().contains(field), "{doc}: {err}");
        }
    }

    #[test]
    fn chunk_bytes_must_be_multiple_of_64() {
        for doc in [
            "classes: { large: { chunk_bytes: 2000 } }",
            "classes: { large: { chunk_bytes: 0 } }",
        ] {
            let err = Config::from_yaml(doc).unwrap_err();

            assert!(
                err.to_string().contains("classes.large.chunk_bytes"),
                "{doc}: {err}"
            );
        }
        assert!(Config::from_yaml("classes: { large: { chunk_bytes: 2048 } }").is_ok());
    }

    #[test]
    fn parity_ratio_outside_unit_interval_rejected() {
        for doc in [
            "classes: { large: { parity_ratio: 1.5 } }",
            "classes: { large: { parity_ratio: -0.1 } }",
        ] {
            let err = Config::from_yaml(doc).unwrap_err();

            assert!(
                err.to_string().contains("classes.large.parity_ratio"),
                "{doc}: {err}"
            );
        }
    }

    #[test]
    fn keepalive_must_be_shorter_than_idle_timeout() {
        let err = Config::from_yaml("overlay: { keepalive_ms: 5000, idle_timeout_ms: 5000 }")
            .unwrap_err();

        assert!(err.to_string().contains("overlay.keepalive_ms"), "{err}");
        assert!(
            Config::from_yaml("overlay: { keepalive_ms: 4999, idle_timeout_ms: 5000 }").is_ok()
        );
    }

    #[test]
    fn stale_after_must_not_be_shorter_than_batch_window() {
        let err =
            Config::from_yaml("classes: { small: { batch_window_ms: 20, stale_after_ms: 10 } }")
                .unwrap_err();

        assert!(
            err.to_string().contains("classes.small.stale_after_ms"),
            "{err}"
        );
        assert!(
            Config::from_yaml("classes: { small: { batch_window_ms: 20, stale_after_ms: 20 } }")
                .is_ok()
        );
    }

    #[test]
    fn publish_rate_limit_fields_must_be_positive() {
        for (doc, field) in [
            (
                "bn: { publish_rate_limit: { small_per_s: 0 } }",
                "bn.publish_rate_limit.small_per_s",
            ),
            (
                "bn: { publish_rate_limit: { large_per_s: 0 } }",
                "bn.publish_rate_limit.large_per_s",
            ),
            (
                "bn: { publish_rate_limit: { bytes_per_s: 0 } }",
                "bn.publish_rate_limit.bytes_per_s",
            ),
        ] {
            let err = Config::from_yaml(doc).unwrap_err();

            assert!(err.to_string().contains(field), "{doc}: {err}");
        }
    }

    #[test]
    fn relays_per_remote_region_must_be_at_least_one() {
        let err =
            Config::from_yaml("overlay: { fanout: { small: { relays_per_remote_region: 0 } } }")
                .unwrap_err();

        assert!(
            err.to_string()
                .contains("overlay.fanout.small.relays_per_remote_region"),
            "{err}"
        );
    }

    #[test]
    fn stripe_min_recipients_must_be_at_least_one() {
        let err = Config::from_yaml("overlay: { fanout: { large: { stripe_min_recipients: 0 } } }")
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("overlay.fanout.large.stripe_min_recipients"),
            "{err}"
        );
    }

    #[test]
    fn listen_must_be_a_socket_address() {
        for (doc, field) in [
            ("overlay: { listen: \"7788\" }", "overlay.listen"),
            ("metrics_listen: \"7789\"", "metrics_listen"),
        ] {
            let err = Config::from_yaml(doc).unwrap_err();

            assert!(err.to_string().contains(field), "{doc}: {err}");
        }
        for doc in [
            "overlay: { listen: \"[::]:7788\" }",
            "overlay: { listen: \"0.0.0.0:7788\" }",
        ] {
            assert!(Config::from_yaml(doc).is_ok(), "{doc}");
        }
    }

    #[test]
    fn load_reports_path_when_file_missing() {
        let path = Path::new("/nonexistent/fleet-overlay/config.yaml");

        let err = Config::load(path).unwrap_err();

        assert!(
            err.to_string()
                .contains("/nonexistent/fleet-overlay/config.yaml"),
            "{err}"
        );
    }

    #[test]
    fn load_names_file_and_field_on_invalid_value() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yaml");
        for (doc, field) in [
            (
                "classes: { large: { chunk_bytes: 2000 } }",
                "classes.large.chunk_bytes",
            ),
            ("log: { format: logfmt }", "log.format"),
        ] {
            std::fs::write(&path, doc).unwrap();

            let message = Config::load(&path).unwrap_err().to_string();

            assert!(
                message.contains(&path.display().to_string()) && message.contains(field),
                "{doc}: {message}"
            );
        }
    }
}
