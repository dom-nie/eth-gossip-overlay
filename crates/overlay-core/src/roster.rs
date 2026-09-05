//! The fleet roster: every host the sidecar may pair with, keyed by hostname. Configuration
//! management renders it from the inventory, so a key nobody expects or a host that cannot be
//! dialled is an inventory bug and fails the load with the host named.

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

/// One line of the roster.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Roster {
    /// Every host, in file order.
    pub hosts: Vec<HostEntry>,
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
}

impl Roster {
    /// Parses a complete `roster.yaml` document.
    pub fn from_yaml(text: &str) -> Result<Self, RosterError> {
        Self::parse(text, None)
    }

    fn parse(text: &str, path: Option<&Path>) -> Result<Self, RosterError> {
        // The direct deserializer, not yaml::from_str, for the reason config.rs gives: the
        // retry through a Value tree loses the key path and the line.
        Self::deserialize(yaml::Deserializer::from_str(text)).map_err(|source| {
            RosterError::Parse {
                path: path.map(Path::to_owned),
                source,
            }
        })
    }

    /// The entry for `hostname`, if the roster has one.
    pub fn get(&self, hostname: &Hostname) -> Option<&HostEntry> {
        self.hosts.iter().find(|host| &host.hostname == hostname)
    }
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
}
