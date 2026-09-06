//! Pinned-key TLS for the overlay: which sidecars may pair with this one.

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arc_swap::ArcSwap;
    use overlay_core::identity::{FleetSeed, Seeds, derive_tls_keypair};
    use overlay_core::roster::{HostEntry, Hostname, Region, Roster};
    use rustls::pki_types::CertificateDer;

    use super::*;

    fn host(name: &str) -> Hostname {
        Hostname(name.to_owned())
    }

    fn roster(names: &[&str]) -> Roster {
        Roster {
            hosts: names
                .iter()
                .enumerate()
                .map(|(index, name)| HostEntry {
                    hostname: host(name),
                    region: Region("eu".to_owned()),
                    site: None,
                    addr: format!("127.0.0.1:{}", 7788 + index).parse().unwrap(),
                })
                .collect(),
        }
    }

    fn seeds(current: u8, previous: Option<u8>) -> Seeds {
        Seeds {
            current: FleetSeed::from([current; 32]),
            previous: previous.map(|byte| FleetSeed::from([byte; 32])),
        }
    }

    fn pins(roster: &Roster, seeds: &Seeds) -> Arc<ArcSwap<PinTable>> {
        Arc::new(ArcSwap::from_pointee(PinTable::build(roster, seeds)))
    }

    /// What a host puts on the wire, built the way the endpoint builds it, so a wrong
    /// assumption about the encoding fails the test rather than hiding in both halves.
    fn presented(seed: &FleetSeed, name: &str) -> CertificateDer<'static> {
        identity(&derive_tls_keypair(seed, &host(name)))
            .unwrap()
            .cert[0]
            .clone()
    }

    #[test]
    fn acceptor_verifier_accepts_pinned_key_and_yields_its_hostname() {
        let seeds = seeds(0x11, None);
        let verifier = AcceptorVerifier::new(pins(&roster(&["bn-a", "bn-b"]), &seeds));

        let entry = verifier
            .identify(&presented(&seeds.current, "bn-a"))
            .unwrap();

        assert_eq!(entry.hostname, host("bn-a"));
        assert_eq!(entry.seed, SeedGeneration::Current);
    }
}
