//! Which Lighthouse versions the sidecar is known to work with, and the task that checks the
//! running beacon node against that on every connect (D09, CL-N5).

use std::fmt;

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
}
