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
