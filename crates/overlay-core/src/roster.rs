//! The fleet roster: every host the sidecar may pair with, keyed by hostname. Configuration
//! management renders it from the inventory, so an unknown key or an address that does not
//! parse is an inventory bug, and the load fails naming the host.

use std::collections::{BTreeSet, HashSet};
use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_yaml_bw as yaml;

use crate::config::in_file;

/// A host's name as the operator wrote it in the roster. It is the only identity in the
/// system: roster key, key-derivation input, connection tie-break, stripe order and relay
/// spreading. Any non-empty string will do; hostnames never reach a certificate or a DNS
/// query, so there is no alphabet to enforce.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(transparent)]
pub struct Hostname(pub String);

impl fmt::Display for Hostname {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The fanout domain a host belongs to: hosts in one region are a metro RTT apart and fan out
/// to each other directly. An arbitrary label; a fleet may have one region or five.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(transparent)]
pub struct Region(pub String);

impl fmt::Display for Region {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One roster entry: a host, where it is and how to reach it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostEntry {
    /// The host's identity.
    pub hostname: Hostname,
    /// The region the host fans out in.
    pub region: Region,
    /// A label for metrics and failure-domain reporting. Routing never reads it.
    pub site: Option<String>,
    /// The public address other sidecars dial.
    pub addr: SocketAddr,
}

/// The whole `roster.yaml`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Roster {
    /// Every host, in file order.
    pub hosts: Vec<HostEntry>,
}

/// The file as written. `addr` stays text until validation so a bad one is reported under
/// its hostname; serde's own error only knows the key path.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRoster {
    hosts: Vec<RawHost>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHost {
    hostname: Hostname,
    region: Region,
    site: Option<String>,
    addr: String,
}

/// Why a roster could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum RosterError {
    /// The file could not be read.
    #[error("{}: {source}", .path.display())]
    Io {
        /// The file that was asked for.
        path: PathBuf,
        /// What the filesystem said.
        source: std::io::Error,
    },
    /// The text is not valid YAML or does not fit the schema.
    #[error("{}{source}", in_file(.path.as_deref()))]
    Parse {
        /// The file the text came from, if it came from one.
        path: Option<PathBuf>,
        /// The parser's own error, which names the offending key and its position.
        source: yaml::Error,
    },
    /// A host parsed but cannot be used as written.
    #[error("{}hosts[{index}] {:?}: {reason}", in_file(.path.as_deref()), .hostname.0)]
    Invalid {
        /// The file the host came from, if it came from one.
        path: Option<PathBuf>,
        /// The host's position in `hosts`, so an empty hostname can still be found.
        index: usize,
        /// The hostname as written.
        hostname: Hostname,
        /// What is wrong with the entry.
        reason: String,
    },
    /// The hostname this process resolved to has no roster entry and nothing in the
    /// environment says which region it should fan out in.
    #[error("{hostname} is not in the roster and {REGION_ENV} is not set")]
    UnknownHost {
        /// The hostname that was looked up.
        hostname: Hostname,
    },
}

impl Roster {
    /// Reads and parses the file at `path`.
    pub fn load(path: &Path) -> Result<Self, RosterError> {
        let text = std::fs::read_to_string(path).map_err(|source| RosterError::Io {
            path: path.to_owned(),
            source,
        })?;
        Self::parse(&text, Some(path))
    }

    /// Parses a complete `roster.yaml` document.
    pub fn from_yaml(text: &str) -> Result<Self, RosterError> {
        Self::parse(text, None)
    }

    fn parse(text: &str, path: Option<&Path>) -> Result<Self, RosterError> {
        // The direct deserializer, not yaml::from_str, for the reason config.rs gives: the
        // retry through a Value tree loses the key path and the line.
        let raw = RawRoster::deserialize(yaml::Deserializer::from_str(text)).map_err(|source| {
            RosterError::Parse {
                path: path.map(Path::to_owned),
                source,
            }
        })?;
        Self::validate(raw, path)
    }

    fn validate(raw: RawRoster, path: Option<&Path>) -> Result<Self, RosterError> {
        let mut hosts = Vec::with_capacity(raw.hosts.len());
        let mut seen = HashSet::with_capacity(raw.hosts.len());
        for (index, host) in raw.hosts.into_iter().enumerate() {
            let invalid = |reason: String| RosterError::Invalid {
                path: path.map(Path::to_owned),
                index,
                hostname: host.hostname.clone(),
                reason,
            };
            if host.hostname.0.is_empty() {
                return Err(invalid("empty hostname".to_owned()));
            }
            if host.region.0.is_empty() {
                return Err(invalid("empty region".to_owned()));
            }
            let addr = host
                .addr
                .parse()
                .map_err(|err| invalid(format!("addr {:?}: {err}", host.addr)))?;
            if !seen.insert(host.hostname.clone()) {
                return Err(invalid("duplicate hostname".to_owned()));
            }
            hosts.push(HostEntry {
                hostname: host.hostname,
                region: host.region,
                site: host.site,
                addr,
            });
        }
        Ok(Self { hosts })
    }

    /// The entry for `hostname`, if the roster has one.
    pub fn get(&self, hostname: &Hostname) -> Option<&HostEntry> {
        self.hosts.iter().find(|host| &host.hostname == hostname)
    }

    /// Every host in `region`, sorted by hostname with the plain byte-wise `Ord` on the
    /// string, whatever order the file had. Striping (T-072) hands chunk `i` to the `i`th host
    /// of this list rotated by the message id, and two origins only make the same assignment
    /// because they sort the same way, so this is the one place the order is defined.
    pub fn in_region(&self, region: &Region) -> Vec<&HostEntry> {
        let mut hosts: Vec<_> = self
            .hosts
            .iter()
            .filter(|host| &host.region == region)
            .collect();
        hosts.sort_by(|a, b| a.hostname.cmp(&b.hostname));
        hosts
    }

    /// Every region that has at least one host, sorted.
    pub fn regions(&self) -> BTreeSet<Region> {
        self.hosts.iter().map(|host| host.region.clone()).collect()
    }

    /// Every host but `hostname`, in file order: the peers this host dials or accepts.
    pub fn others<'s>(&'s self, hostname: &Hostname) -> impl Iterator<Item = &'s HostEntry> {
        self.hosts
            .iter()
            .filter(move |host| &host.hostname != hostname)
    }
}

/// Which roster host this process is and where it fans out from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelfIdentity {
    /// The name this process runs under, and its key in every peer's roster.
    pub hostname: Hostname,
    /// The region this process fans out in.
    pub region: Region,
    /// The site label, if there is one.
    pub site: Option<String>,
}

const HOSTNAME_ENV: &str = "FLEET_OVERLAY_HOSTNAME";
const REGION_ENV: &str = "FLEET_OVERLAY_REGION";
const SITE_ENV: &str = "FLEET_OVERLAY_SITE";

/// Works out who this process is: `FLEET_OVERLAY_HOSTNAME` if set, else `gethostname`, looked
/// up in `roster`. `FLEET_OVERLAY_REGION` and `FLEET_OVERLAY_SITE` override the entry's
/// values, and with the region set a host missing from the roster still resolves, with no site
/// unless the environment gives one. Both sources are passed in so this crate never reads the
/// real environment and a test can stage any combination.
pub fn resolve_self(
    roster: &Roster,
    env: &dyn Fn(&str) -> Option<String>,
    gethostname: &dyn Fn() -> String,
) -> Result<SelfIdentity, RosterError> {
    let hostname = Hostname(env(HOSTNAME_ENV).unwrap_or_else(gethostname));
    let entry = roster.get(&hostname);
    let region = match env(REGION_ENV) {
        Some(region) => Region(region),
        None => entry
            .ok_or_else(|| RosterError::UnknownHost {
                hostname: hostname.clone(),
            })?
            .region
            .clone(),
    };
    Ok(SelfIdentity {
        hostname,
        region,
        site: env(SITE_ENV).or_else(|| entry.and_then(|entry| entry.site.clone())),
    })
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    /// Architecture.md Appendix A, verbatim.
    const APPENDIX_A: &str = r#"
hosts:
  - hostname: bn-ams1-07
    region: eu
    site: ams1
    addr: "203.0.113.37:7788"
  - hostname: bn-fra1-02
    region: eu
    site: fra1
    addr: "198.51.100.12:7788"
  - hostname: bn-nyc1-01
    region: us
    site: nyc1
    addr: "[2001:db8:1::120]:7788"
"#;

    fn host(name: &str) -> Hostname {
        Hostname(name.to_owned())
    }

    fn region(name: &str) -> Region {
        Region(name.to_owned())
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn appendix_a_roster_parses_three_hosts() {
        let roster = Roster::from_yaml(APPENDIX_A).unwrap();

        let regions: Vec<_> = roster.hosts.iter().map(|h| h.region.clone()).collect();
        assert_eq!(regions, [region("eu"), region("eu"), region("us")]);
        let sites: Vec<_> = roster.hosts.iter().map(|h| h.site.as_deref()).collect();
        assert_eq!(sites, [Some("ams1"), Some("fra1"), Some("nyc1")]);
        let nyc = roster.get(&host("bn-nyc1-01")).unwrap();
        assert_eq!(nyc.addr, addr("[2001:db8:1::120]:7788"));
    }

    #[test]
    fn duplicate_hostname_is_rejected() {
        let doc = r#"hosts:
  - { hostname: bn-1, region: eu, addr: "192.0.2.1:7788" }
  - { hostname: bn-2, region: eu, addr: "192.0.2.2:7788" }
  - { hostname: bn-1, region: us, addr: "192.0.2.3:7788" }
"#;

        let err = Roster::from_yaml(doc).unwrap_err();

        let message = err.to_string();
        assert!(
            message.contains("bn-1") && message.contains("duplicate"),
            "{message}"
        );
    }

    #[test]
    fn empty_region_is_rejected() {
        let doc = r#"hosts:
  - { hostname: bn-1, region: "", addr: "192.0.2.1:7788" }
"#;

        let err = Roster::from_yaml(doc).unwrap_err();

        let message = err.to_string();
        assert!(
            message.contains("bn-1") && message.contains("region"),
            "{message}"
        );
    }

    #[test]
    fn empty_hostname_is_rejected_with_its_index() {
        let doc = r#"hosts:
  - { hostname: bn-1, region: eu, addr: "192.0.2.1:7788" }
  - { hostname: "", region: eu, addr: "192.0.2.2:7788" }
"#;

        let err = Roster::from_yaml(doc).unwrap_err();

        let message = err.to_string();
        assert!(
            message.contains("hosts[1]") && message.contains("hostname"),
            "{message}"
        );
    }

    #[test]
    fn unparseable_addr_is_rejected_with_hostname_in_message() {
        for bad in ["192.0.2.1", "2001:db8:1::120:7788", "bn-1.example.org:7788"] {
            let doc = format!("hosts:\n  - {{ hostname: bn-1, region: eu, addr: \"{bad}\" }}\n");

            let err = Roster::from_yaml(&doc).unwrap_err();

            let message = err.to_string();
            assert!(
                message.contains("bn-1") && message.contains(bad),
                "{message}"
            );
        }
    }

    #[test]
    fn load_names_file_and_host_on_bad_addr() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("roster.yaml");
        std::fs::write(
            &path,
            "hosts:\n  - { hostname: bn-1, region: eu, addr: \"192.0.2.1\" }\n",
        )
        .unwrap();

        let message = Roster::load(&path).unwrap_err().to_string();

        assert!(
            message.contains(&path.display().to_string()) && message.contains("bn-1"),
            "{message}"
        );
    }

    fn names(hosts: &[&HostEntry]) -> Vec<String> {
        hosts.iter().map(|h| h.hostname.to_string()).collect()
    }

    #[test]
    fn in_region_returns_hosts_sorted_by_hostname() {
        let doc = r#"hosts:
  - { hostname: bn-a, region: eu, addr: "192.0.2.1:7788" }
  - { hostname: bn-9, region: eu, addr: "192.0.2.2:7788" }
  - { hostname: bn-0, region: us, addr: "192.0.2.3:7788" }
  - { hostname: bn-B, region: eu, addr: "192.0.2.4:7788" }
  - { hostname: bn-10, region: eu, addr: "192.0.2.5:7788" }
"#;
        let roster = Roster::from_yaml(doc).unwrap();

        let eu = roster.in_region(&region("eu"));

        assert_eq!(names(&eu), ["bn-10", "bn-9", "bn-B", "bn-a"]);
    }

    #[test]
    fn regions_lists_each_region_once() {
        let roster = Roster::from_yaml(APPENDIX_A).unwrap();

        let regions: Vec<_> = roster.regions().into_iter().collect();

        assert_eq!(regions, [region("eu"), region("us")]);
    }

    #[test]
    fn others_excludes_self() {
        let roster = Roster::from_yaml(APPENDIX_A).unwrap();

        let others: Vec<_> = roster.others(&host("bn-fra1-02")).collect();

        assert_eq!(names(&others), ["bn-ams1-07", "bn-nyc1-01"]);
    }

    fn env(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let vars: Vec<(String, String)> = vars
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        move |key| {
            vars.iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.clone())
        }
    }

    fn gethostname() -> String {
        "bn-ams1-07".to_owned()
    }

    #[test]
    fn resolve_self_prefers_env_hostname_over_gethostname() {
        let roster = Roster::from_yaml(APPENDIX_A).unwrap();

        let me = resolve_self(
            &roster,
            &env(&[("FLEET_OVERLAY_HOSTNAME", "bn-nyc1-01")]),
            &gethostname,
        )
        .unwrap();

        assert_eq!(me.hostname, host("bn-nyc1-01"));
        assert_eq!(me.region, region("us"));
        assert_eq!(me.site.as_deref(), Some("nyc1"));
    }

    #[test]
    fn resolve_self_falls_back_to_gethostname() {
        let roster = Roster::from_yaml(APPENDIX_A).unwrap();

        let me = resolve_self(&roster, &env(&[]), &gethostname).unwrap();

        assert_eq!(me.hostname, host("bn-ams1-07"));
        assert_eq!(me.region, region("eu"));
        assert_eq!(me.site.as_deref(), Some("ams1"));
    }

    #[test]
    fn resolve_self_region_env_override_wins_over_roster() {
        let roster = Roster::from_yaml(APPENDIX_A).unwrap();

        let me = resolve_self(
            &roster,
            &env(&[
                ("FLEET_OVERLAY_HOSTNAME", "bn-nyc1-01"),
                ("FLEET_OVERLAY_REGION", "eu"),
            ]),
            &gethostname,
        )
        .unwrap();

        assert_eq!(me.region, region("eu"));
        assert_eq!(me.site.as_deref(), Some("nyc1"));
    }

    #[test]
    fn resolve_self_unknown_hostname_without_region_override_is_error() {
        let roster = Roster::from_yaml(APPENDIX_A).unwrap();

        let err = resolve_self(
            &roster,
            &env(&[("FLEET_OVERLAY_HOSTNAME", "bn-lon1-03")]),
            &gethostname,
        )
        .unwrap_err();

        assert!(
            matches!(&err, RosterError::UnknownHost { hostname } if hostname == &host("bn-lon1-03"))
        );
        let message = err.to_string();
        assert!(
            message.contains("bn-lon1-03") && message.contains("FLEET_OVERLAY_REGION"),
            "{message}"
        );
    }

    #[test]
    fn resolve_self_unknown_hostname_with_region_override_succeeds_with_no_site() {
        let roster = Roster::from_yaml(APPENDIX_A).unwrap();

        let me = resolve_self(
            &roster,
            &env(&[
                ("FLEET_OVERLAY_HOSTNAME", "bn-lon1-03"),
                ("FLEET_OVERLAY_REGION", "eu"),
            ]),
            &gethostname,
        )
        .unwrap();

        assert_eq!(me.hostname, host("bn-lon1-03"));
        assert_eq!(me.region, region("eu"));
        assert_eq!(me.site, None);
    }

    #[test]
    fn resolve_self_site_env_override_wins_over_roster() {
        let roster = Roster::from_yaml(APPENDIX_A).unwrap();

        let me = resolve_self(
            &roster,
            &env(&[("FLEET_OVERLAY_SITE", "ams2")]),
            &gethostname,
        )
        .unwrap();

        assert_eq!(me.hostname, host("bn-ams1-07"));
        assert_eq!(me.site.as_deref(), Some("ams2"));
    }

    #[test]
    fn single_region_roster_is_valid_and_others_returns_all_but_self() {
        let doc = r#"hosts:
  - { hostname: bn-1, region: home, addr: "192.0.2.1:7788" }
  - { hostname: bn-2, region: home, addr: "192.0.2.2:7788" }
  - { hostname: bn-3, region: home, addr: "192.0.2.3:7788" }
"#;
        let roster = Roster::from_yaml(doc).unwrap();

        let others: Vec<_> = roster.others(&host("bn-2")).collect();

        assert_eq!(names(&others), ["bn-1", "bn-3"]);
        assert_eq!(roster.regions().len(), 1);
        assert_eq!(
            names(&roster.in_region(&region("home"))),
            ["bn-1", "bn-2", "bn-3"]
        );
    }

    #[test]
    fn five_regions_are_listed_in_sorted_order() {
        let doc = r#"hosts:
  - { hostname: bn-1, region: us-west, addr: "192.0.2.1:7788" }
  - { hostname: bn-2, region: ap, addr: "192.0.2.2:7788" }
  - { hostname: bn-3, region: eu, addr: "192.0.2.3:7788" }
  - { hostname: bn-4, region: us-east, addr: "192.0.2.4:7788" }
  - { hostname: bn-5, region: ap, addr: "192.0.2.5:7788" }
  - { hostname: bn-6, region: sa, addr: "192.0.2.6:7788" }
"#;
        let roster = Roster::from_yaml(doc).unwrap();

        let regions: Vec<_> = roster
            .regions()
            .into_iter()
            .map(|r| r.to_string())
            .collect();

        assert_eq!(regions, ["ap", "eu", "sa", "us-east", "us-west"]);
    }
}
