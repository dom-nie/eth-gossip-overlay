//! Which Lighthouse versions the sidecar is known to work with, and the task that checks the
//! running beacon node against that on every connect (D09, CL-N5).

use std::collections::BTreeSet;
use std::fmt;
use std::ops::RangeInclusive;
use std::sync::Arc;

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::gossip::wire::check_max_payload_size;
use crate::link::BnEvent;
use crate::spec::SpecSnapshot;

/// The Lighthouse release the workspace is built against: the tag the root `Cargo.toml` pins
/// for `lighthouse_network` and `types`, whose own `Cargo.toml` names the `sigp/rust-libp2p`
/// rev in the `[patch]` table. The three move together; the drift test below holds this one
/// to the tag.
pub const PINNED: Version = Version {
    major: 8,
    minor: 2,
    patch: 2,
};

/// Exactly the versions the compatibility matrix has passed, so the range grows only with a
/// matrix run, never by reasoning that a release "should" still work. [`LAST_VERIFIED`] is
/// the date of that run and is updated with the range.
pub const SUPPORTED: RangeInclusive<Version> = PINNED..=PINNED;

/// When the matrix last passed on every version in [`SUPPORTED`].
pub const LAST_VERIFIED: &str = "2026-09-06";

/// The `state` label values of `overlay_bn_compat`. T-012 named `size_mismatch` without a
/// constant; these are the shared definitions the gauge, the watch and T-041 use.
pub const STATE_SUPPORTED: &str = "supported";
/// The beacon node is newer than any version in [`SUPPORTED`].
pub const STATE_UNTESTED: &str = "untested";
/// The beacon node is older than the oldest version in [`SUPPORTED`].
pub const STATE_UNSUPPORTED: &str = "unsupported";
/// The beacon node's `MAX_PAYLOAD_SIZE` gives a transmit size other than the compiled one.
pub const STATE_SIZE_MISMATCH: &str = "size_mismatch";

/// Where a beacon node's version stands against [`SUPPORTED`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compat {
    /// In the range.
    Supported,
    /// Above the range: nothing is known to be wrong, nothing has been checked.
    Untested,
    /// Below the range.
    Unsupported,
}

impl Compat {
    /// The `overlay_bn_compat{state}` label for this outcome.
    pub const fn state(self) -> &'static str {
        match self {
            Self::Supported => STATE_SUPPORTED,
            Self::Untested => STATE_UNTESTED,
            Self::Unsupported => STATE_UNSUPPORTED,
        }
    }
}

/// Classifies `version` against [`SUPPORTED`].
pub fn check(version: Version) -> Compat {
    if SUPPORTED.contains(&version) {
        Compat::Supported
    } else if version > *SUPPORTED.end() {
        Compat::Untested
    } else {
        Compat::Unsupported
    }
}

/// Where the compatibility gauges live. T-041 binds [`set_compat`](Self::set_compat) to
/// `overlay_bn_compat{state}`, which it sets to 1 for `state` and to 0 for every other
/// state, so exactly one series is ever 1; [`set_info`](Self::set_info) to
/// `overlay_bn_info{version}`, whose single series it relabels, so the old version's series
/// is gone; and [`set_trusted`](Self::set_trusted) to `overlay_bn_trusted`, 1 or 0, which
/// `None` removes from the output. `()` keeps nothing.
pub trait CompatStats: Send + Sync {
    /// The one compat state that is now 1.
    fn set_compat(&self, state: &'static str);
    /// The beacon node's raw version string, as the one info series.
    fn set_info(&self, version: &str);
    /// Whether the beacon node lists the sidecar as trusted; `None` when it could not say.
    fn set_trusted(&self, trusted: Option<bool>);
}

impl CompatStats for () {
    fn set_compat(&self, _: &'static str) {}
    fn set_info(&self, _: &str) {}
    fn set_trusted(&self, _: Option<bool>) {}
}

/// The compatibility state of the beacon node the link is talking to, fed from
/// [`BnEvent::BnInfo`] and the spec watch. Pure apart from the gauges and the log, so the
/// decisions are testable without a runtime; [`spawn`](Self::spawn) is the task around it.
///
/// A version outside the range is logged once per distinct string, not per connect: the
/// sidecar reconnects with backoff and an operator on an untested Lighthouse would otherwise
/// get the same warning on every attempt. A size mismatch from the spec wins over the version
/// state until a spec without one arrives, because a wrong transmit size loses messages on a
/// version the range says is fine.
pub struct Watch {
    stats: Arc<dyn CompatStats>,
    /// Version strings already warned or errored about.
    warned: BTreeSet<String>,
    /// The state the last version string gave, kept under a size mismatch so it can come
    /// back when the mismatch clears.
    version_state: Option<&'static str>,
    /// Transmit sizes already reported, so a reconnect to the same spec does not repeat the
    /// error.
    mismatched: BTreeSet<u64>,
    /// Whether the spec currently disagrees with the compiled transmit size.
    size_mismatch: bool,
    /// The absent peers endpoint is said once for the sidecar's lifetime: a beacon node that
    /// lacks it lacks it on every connect.
    trusted_unknown_logged: bool,
}

impl Watch {
    /// A watch that has heard nothing from the beacon node yet.
    pub fn new(stats: Arc<dyn CompatStats>) -> Self {
        Self {
            stats,
            warned: BTreeSet::new(),
            version_state: None,
            mismatched: BTreeSet::new(),
            size_mismatch: false,
            trusted_unknown_logged: false,
        }
    }

    /// Takes what the connect probe found. A `None` version was a failed request the link
    /// already warned about, so the last known state stands.
    pub fn on_bn_info(&mut self, version: Option<String>, trusted: Option<bool>) {
        if let Some(raw) = version {
            self.version_state = Some(self.classify(&raw));
            self.stats.set_info(&raw);
            self.publish_state();
        }
        if trusted.is_none() && !self.trusted_unknown_logged {
            self.trusted_unknown_logged = true;
            tracing::warn!(
                "cannot tell whether the beacon node trusts the sidecar: peers endpoint absent \
                 or sidecar not listed"
            );
        }
        self.stats.set_trusted(trusted);
    }

    /// Takes the spec the beacon node reported and holds its transmit size against the
    /// compiled one.
    pub fn on_spec(&mut self, spec: &SpecSnapshot) {
        match check_max_payload_size(spec.max_payload_size) {
            Ok(()) => self.size_mismatch = false,
            Err(err) => {
                self.size_mismatch = true;
                if self.mismatched.insert(err.bn) {
                    tracing::error!(%err, "the beacon node's gossip messages can exceed what this build accepts");
                }
            }
        }
        self.publish_state();
    }

    /// Runs `check` over `raw` and logs the outcome. A string that does not parse is treated
    /// as untested: it is not a Lighthouse this build knows, which is no reason to stop.
    fn classify(&mut self, raw: &str) -> &'static str {
        let first_time = self.warned.insert(raw.to_owned());
        let version = match parse(raw) {
            Ok(parsed) => parsed.version,
            Err(err) => {
                if first_time {
                    tracing::warn!(version = raw, %err, "unrecognised beacon node version");
                }
                return STATE_UNTESTED;
            }
        };
        let compat = check(version);
        match compat {
            Compat::Supported => tracing::info!(version = raw, "beacon node version is supported"),
            Compat::Untested if first_time => tracing::warn!(
                version = raw,
                supported = %Supported,
                "beacon node is newer than any version the sidecar was tested with"
            ),
            Compat::Unsupported if first_time => tracing::error!(
                version = raw,
                supported = %Supported,
                "beacon node is older than the oldest supported version; gossip may be silently dropped"
            ),
            Compat::Untested | Compat::Unsupported => {}
        }
        compat.state()
    }

    fn publish_state(&self) {
        let state = if self.size_mismatch {
            Some(STATE_SIZE_MISMATCH)
        } else {
            self.version_state
        };
        if let Some(state) = state {
            self.stats.set_compat(state);
        }
    }

    /// Drives a watch from the link's `events` and its `spec` watch until either closes.
    /// The link's event channel has one consumer; T-045 fans it out to the mirror and this.
    pub fn spawn(
        mut events: mpsc::Receiver<BnEvent>,
        mut spec: watch::Receiver<SpecSnapshot>,
        stats: Arc<dyn CompatStats>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut watch = Self::new(stats);
            watch.on_spec(&spec.borrow_and_update());
            loop {
                tokio::select! {
                    event = events.recv() => match event {
                        Some(BnEvent::BnInfo { version, trusted }) => {
                            watch.on_bn_info(version, trusted);
                        }
                        Some(_) => {}
                        None => return,
                    },
                    changed = spec.changed() => match changed {
                        Ok(()) => watch.on_spec(&spec.borrow_and_update()),
                        Err(_) => return,
                    },
                }
            }
        })
    }
}

/// [`SUPPORTED`] as `8.2.2..=8.2.2`, for the logs and the compatibility document.
struct Supported;

impl fmt::Display for Supported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}..={}", SUPPORTED.start(), SUPPORTED.end())
    }
}

/// A Lighthouse release number. Only this part of the version string decides compatibility;
/// a pre-release compares as its numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    /// The first number of the triple.
    pub major: u64,
    /// The second number.
    pub minor: u64,
    /// The third number.
    pub patch: u64,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// What `GET /eth/v1/node/version` says, taken apart. Lighthouse's `version_with_platform()`
/// in `common/lighthouse_version/src/lib.rs` builds it as
/// `Lighthouse/v<major>.<minor>.<patch>[-(rc|beta).N][-<7 hex>]/<arch>-<os>`; the commit is
/// missing from a build without git information.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LighthouseVersion {
    /// The release number.
    pub version: Version,
    /// `rc.N` or `beta.N` when the build is a pre-release.
    pub pre_release: Option<String>,
    /// The first seven hex digits of the commit the binary was built from.
    pub commit: Option<String>,
    /// `<arch>-<os>` as Rust's `std::env::consts` spells them.
    pub platform: Option<String>,
}

/// Why a version string could not be taken apart.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum VersionParseError {
    /// No `Lighthouse/v` prefix: another client, or not a version string at all.
    #[error("no `Lighthouse/v` prefix")]
    NotLighthouse,
    /// What follows the prefix is not three dot-separated integers.
    #[error("{0:?} is not a major.minor.patch triple")]
    Triple(String),
    /// A dash-separated part that is neither a pre-release tag nor a seven-digit commit.
    #[error("{0:?} is neither a pre-release tag nor a commit")]
    Suffix(String),
}

/// Takes a Lighthouse version string apart.
pub fn parse(s: &str) -> Result<LighthouseVersion, VersionParseError> {
    let rest = s
        .strip_prefix("Lighthouse/v")
        .ok_or(VersionParseError::NotLighthouse)?;
    let (build, platform) = match rest.split_once('/') {
        Some((build, platform)) => (build, Some(platform.to_owned())),
        None => (rest, None),
    };
    let mut parts = build.split('-');
    let triple = parts.next().unwrap_or_default();
    let version =
        parse_triple(triple).ok_or_else(|| VersionParseError::Triple(triple.to_owned()))?;
    let mut pre_release = None;
    let mut commit = None;
    for part in parts {
        let is_pre_release = part
            .strip_prefix("rc.")
            .or_else(|| part.strip_prefix("beta."))
            .is_some_and(|n| n.parse::<u64>().is_ok());
        let is_commit = part.len() == 7 && part.bytes().all(|b| b.is_ascii_hexdigit());
        if is_pre_release && pre_release.is_none() && commit.is_none() {
            pre_release = Some(part.to_owned());
        } else if is_commit && commit.is_none() {
            commit = Some(part.to_owned());
        } else {
            return Err(VersionParseError::Suffix(part.to_owned()));
        }
    }
    Ok(LighthouseVersion {
        version,
        pre_release,
        commit,
        platform,
    })
}

fn parse_triple(s: &str) -> Option<Version> {
    let mut numbers = s.split('.').map(|n| n.parse::<u64>().ok());
    let version = Version {
        major: numbers.next()??,
        minor: numbers.next()??,
        patch: numbers.next()??,
    };
    numbers.next().is_none().then_some(version)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    /// The gauges as T-041 will keep them, modelled so the trait's promises are what the
    /// tests assert: one compat series at 1, one info series, trusted absent when `None`.
    #[derive(Clone, Debug, Default, PartialEq, Eq)]
    struct Gauges {
        compat: Option<&'static str>,
        info: Option<String>,
        trusted: Option<bool>,
    }

    #[derive(Default)]
    struct Recording(Mutex<Gauges>);

    impl Recording {
        fn gauges(&self) -> Gauges {
            self.0.lock().unwrap().clone()
        }
    }

    impl CompatStats for Recording {
        fn set_compat(&self, state: &'static str) {
            self.0.lock().unwrap().compat = Some(state);
        }

        fn set_info(&self, version: &str) {
            self.0.lock().unwrap().info = Some(version.to_owned());
        }

        fn set_trusted(&self, trusted: Option<bool>) {
            self.0.lock().unwrap().trusted = trusted;
        }
    }

    fn watch() -> (Watch, Arc<Recording>) {
        let stats = Arc::new(Recording::default());
        (Watch::new(stats.clone()), stats)
    }

    fn v(major: u64, minor: u64, patch: u64) -> Version {
        Version {
            major,
            minor,
            patch,
        }
    }

    /// The shapes `version_with_platform()` in Lighthouse's `common/lighthouse_version`
    /// produces: a release with its commit, a pre-release, a build without git information,
    /// and the bare form T-011's tests use. Anything else is garbage.
    #[test]
    fn parses_version_string_into_semver() {
        assert_eq!(
            parse("Lighthouse/v8.2.2-e423a66/x86_64-linux").unwrap(),
            LighthouseVersion {
                version: v(8, 2, 2),
                pre_release: None,
                commit: Some("e423a66".to_owned()),
                platform: Some("x86_64-linux".to_owned()),
            }
        );
        assert_eq!(
            parse("Lighthouse/v9.0.0-rc.1-abcdef0/aarch64-macos").unwrap(),
            LighthouseVersion {
                version: v(9, 0, 0),
                pre_release: Some("rc.1".to_owned()),
                commit: Some("abcdef0".to_owned()),
                platform: Some("aarch64-macos".to_owned()),
            }
        );
        assert_eq!(
            parse("Lighthouse/v9.0.0-beta.0/x86_64-linux").unwrap(),
            LighthouseVersion {
                version: v(9, 0, 0),
                pre_release: Some("beta.0".to_owned()),
                commit: None,
                platform: Some("x86_64-linux".to_owned()),
            }
        );
        assert_eq!(
            parse("Lighthouse/v8.2.2").unwrap(),
            LighthouseVersion {
                version: v(8, 2, 2),
                pre_release: None,
                commit: None,
                platform: None,
            }
        );
        assert_eq!(v(8, 2, 2).to_string(), "8.2.2");
        for garbage in [
            "",
            "Lighthouse",
            "Lighthouse/8.2.2",
            "Lighthouse/v8.2",
            "Lighthouse/v8.2.2.1",
            "Lighthouse/vx.y.z",
            "Lighthouse/v8.2.2-dirty",
            "Lighthouse/v8.2.2-e423a66-e423a66",
            "Prysm/v5.0.0",
        ] {
            assert!(parse(garbage).is_err(), "{garbage:?} parsed");
        }
    }

    /// Newer than the range is untested, older is unsupported; the ends of the range are in.
    #[test]
    fn check_classifies_supported_untested_and_unsupported() {
        let (start, end) = (*SUPPORTED.start(), *SUPPORTED.end());

        assert_eq!(check(start), Compat::Supported);
        assert_eq!(check(end), Compat::Supported);
        assert_eq!(check(PINNED), Compat::Supported);
        assert_eq!(
            check(v(end.major, end.minor, end.patch + 1)),
            Compat::Untested
        );
        assert_eq!(check(v(end.major + 1, 0, 0)), Compat::Untested);
        assert_eq!(check(v(start.major, start.minor, 0)), Compat::Unsupported);
        assert_eq!(check(v(0, 0, 0)), Compat::Unsupported);
        assert_eq!(Compat::Supported.state(), STATE_SUPPORTED);
        assert_eq!(Compat::Untested.state(), STATE_UNTESTED);
        assert_eq!(Compat::Unsupported.state(), STATE_UNSUPPORTED);
    }

    /// A beacon node upgraded under a running sidecar: the second connect's version replaces
    /// the first in `overlay_bn_info` and moves the one compat series.
    #[test]
    fn bn_info_sets_exactly_one_compat_state_and_relabels_info_version() {
        let (mut watch, stats) = watch();
        let pinned = format!("Lighthouse/v{PINNED}-e423a66/x86_64-linux");
        let newer = "Lighthouse/v99.0.0-abcdef0/x86_64-linux";

        watch.on_bn_info(Some(pinned.clone()), Some(true));
        let first = stats.gauges();
        watch.on_bn_info(Some(newer.to_owned()), Some(true));
        let second = stats.gauges();

        assert_eq!(
            (first.compat, first.info),
            (Some(STATE_SUPPORTED), Some(pinned))
        );
        assert_eq!(
            (second.compat, second.info),
            (Some(STATE_UNTESTED), Some(newer.to_owned()))
        );
    }
}

#[cfg(test)]
mod drift {
    use super::*;

    /// `PINNED` and the tag the root `Cargo.toml` pins for Lighthouse's crates move together;
    /// a bump that forgets one of them would report the wrong version as supported.
    #[test]
    fn pinned_version_equals_the_lighthouse_tag_in_the_root_cargo_toml() {
        let manifest =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.toml"))
                .unwrap();
        let tag_of = |krate: &str| {
            let line = manifest
                .lines()
                .find(|line| line.starts_with(&format!("{krate} = ")))
                .unwrap_or_else(|| panic!("no {krate} in the root Cargo.toml"));
            line.split("tag = \"")
                .nth(1)
                .and_then(|rest| rest.split('"').next())
                .unwrap_or_else(|| panic!("{krate} is not pinned by tag: {line}"))
                .to_owned()
        };

        assert_eq!(tag_of("lighthouse_network"), format!("v{PINNED}"));
        assert_eq!(tag_of("types"), format!("v{PINNED}"));
    }
}
