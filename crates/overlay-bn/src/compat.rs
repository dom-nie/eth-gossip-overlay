//! Which Lighthouse versions the sidecar is known to work with, and the task that checks the
//! running beacon node against that on every connect (D09, CL-N5).

use std::fmt;
use std::ops::RangeInclusive;

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
    use super::*;

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
