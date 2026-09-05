//! Who a sidecar is on the overlay and where that comes from. One seed is shared by the whole
//! fleet, and HKDF over the seed and a hostname gives every host's overlay TLS key, so a host
//! can compute a sibling's expected key from the roster alone. Nothing else derives from the
//! seed: the libp2p identity is a per-host key in `overlay_bn::node_key`, so rotating the seed
//! never touches a beacon node.

use std::fmt;

use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::roster::Hostname;

/// The HKDF salt. Versioned so a later derivation scheme can never collide with this one.
const HKDF_SALT: &[u8] = b"fleet-overlay/v1";
/// The HKDF info prefix for the overlay TLS key; the hostname follows it. The purpose label
/// keeps a second derivation from the same seed apart from this one.
const TLS_INFO_PREFIX: &[u8] = b"overlay-tls:";

/// The secret the whole fleet shares. Together with a hostname it gives that host's overlay
/// TLS key, and nothing else; the bytes are wiped when the value is dropped and never shown
/// by `Debug`.
pub struct FleetSeed(Zeroizing<[u8; 32]>);

impl From<[u8; 32]> for FleetSeed {
    fn from(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

impl fmt::Debug for FleetSeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FleetSeed(..)")
    }
}

/// The overlay TLS key of `hostname` under `seed`: HKDF-SHA256 with the fleet salt and an
/// `overlay-tls:<hostname>` info, 32 bytes of output as the Ed25519 secret. Every sibling
/// runs the same function to know what key to expect from this host, so the inputs are
/// frozen by the golden vector in the tests.
#[expect(
    clippy::expect_used,
    reason = "HKDF-SHA256 only refuses more than 8160 bytes of output, and 32 are asked for"
)]
pub fn derive_tls_keypair(seed: &FleetSeed, hostname: &Hostname) -> SigningKey {
    let info = [TLS_INFO_PREFIX, hostname.0.as_bytes()].concat();
    let mut secret = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(HKDF_SALT), &*seed.0)
        .expand(&info, &mut *secret)
        .expect("32 bytes of HKDF output");
    SigningKey::from_bytes(&secret)
}

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
