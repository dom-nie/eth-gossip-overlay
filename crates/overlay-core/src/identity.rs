//! Who a sidecar is on the overlay and where that comes from. One seed is shared by the whole
//! fleet, and HKDF over the seed and a hostname gives every host's overlay TLS key, so a host
//! can compute a sibling's expected key from the roster alone. Nothing else derives from the
//! seed: the libp2p identity is a per-host key in `overlay_bn::node_key`, so rotating the seed
//! never touches a beacon node.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roster::Hostname;

    fn host(name: &str) -> Hostname {
        Hostname(name.to_owned())
    }

    fn seed(byte: u8) -> FleetSeed {
        FleetSeed::from([byte; 32])
    }

    #[test]
    fn same_seed_and_hostname_give_same_tls_key() {
        let seed = seed(0x11);

        let first = derive_tls_keypair(&seed, &host("bn-1"));
        let second = derive_tls_keypair(&seed, &host("bn-1"));

        assert_eq!(first.to_bytes(), second.to_bytes());
    }
}
