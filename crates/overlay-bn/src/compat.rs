//! Which Lighthouse versions the sidecar is known to work with, and the task that checks the
//! running beacon node against that on every connect (D09, CL-N5).

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
