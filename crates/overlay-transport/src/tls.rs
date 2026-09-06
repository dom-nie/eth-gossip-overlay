//! Pinned-key TLS for the overlay: which sidecars may pair with this one.
//!
//! There is no certificate authority. Every host derives its overlay key from the fleet seed
//! and its own hostname ([`overlay_core::identity`]), so every host can compute every other
//! host's expected key from the roster alone. The acceptor looks the presented key up in a
//! [`PinTable`] and thereby learns who connected; the dialler compares it with the key it
//! expected of the host it dialled. Neither side reads a name off the wire, which is why
//! roster hostnames stay arbitrary strings (D27): `rack3/bn 01` pairs as happily as
//! `bn-01.example.com`.
//!
//! # Raw public keys, not certificates
//!
//! The ticket asked for a spike: do RFC 7250 raw public keys pass through quinn? They do, in
//! both roles. rustls 0.23 negotiates `CertificateType::RawPublicKey` through
//! `AlwaysResolvesServerRawPublicKeys` and `AlwaysResolvesClientRawPublicKeys`, and quinn 0.11
//! looks only at a configuration's cipher suites when it wraps one, so it never sees the
//! difference; a mutually authenticated loopback handshake came up on the first attempt.
//!
//! So the overlay carries no certificates at all. What a peer presents is the 44-byte
//! `SubjectPublicKeyInfo` of its Ed25519 key, which is the thing being pinned anyway. That
//! leaves no `rcgen`, no self-signed certificate, no SAN, no validity period to ignore and no
//! X.509 parser in the dependency graph. One trap is worth recording: the handshake signature
//! must be checked with `verify_tls13_signature_with_raw_key`. The certificate-shaped helper
//! next to it parses its argument as X.509 and rejects a raw key as `BadEncoding`.
//!
//! # What pinning proves
//!
//! Fleet membership, and nothing else. A peer that completes the handshake holds a key
//! derived from the fleet seed, so it is a host the operator put in the roster, which is what
//! earns it a trusted path into a beacon node (Architecture §8). It says nothing about the
//! payloads that follow: their authenticity is the receiving beacon node's BLS validation, and
//! a member that floods its siblings is the fan-out budget's problem (T-032), not this
//! module's.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use arc_swap::ArcSwap;
use ed25519_dalek::SigningKey;
use overlay_core::identity::{Seeds, expected_tls_public_key};
use overlay_core::roster::{Hostname, Roster};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use zeroize::Zeroizing;

/// The PKCS#8 v1 wrapper around a bare Ed25519 secret: the sequence, version 0, the Ed25519
/// algorithm identifier and the octet string that holds the 32 secret bytes. Fixed for the
/// algorithm, so those 32 bytes are the only part that varies.
const PKCS8_ED25519_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// The 12 bytes every Ed25519 `SubjectPublicKeyInfo` starts with. The 32 that follow are the
/// public key, and the 44 together are what a peer presents in place of a certificate.
const SPKI_ED25519_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Why the overlay's TLS configuration could not be built. All of it means the crypto provider
/// is not the one this module installs, so none of it happens under `ring`.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// rustls refused the seed-derived key or the protocol version the overlay asks for.
    #[error("overlay TLS: {0}")]
    Rustls(#[from] rustls::Error),
    /// The provider loaded the key but will not say what its public half is, leaving nothing
    /// to present as a raw public key.
    #[error("overlay TLS: the crypto provider does not expose a public key")]
    NoPublicKey,
}

/// This host's overlay identity: the seed-derived key, ready for rustls to sign the handshake
/// with and to present as its raw public key. `own_key` always comes from the current seed;
/// a host accepts the outgoing seed from its peers but never presents it (DX-N2).
pub fn identity(own_key: &SigningKey) -> Result<Arc<CertifiedKey>, TlsError> {
    let mut pkcs8 = Zeroizing::new(Vec::with_capacity(PKCS8_ED25519_PREFIX.len() + 32));
    pkcs8.extend_from_slice(&PKCS8_ED25519_PREFIX);
    pkcs8.extend_from_slice(own_key.as_bytes());
    let key =
        rustls::crypto::ring::sign::any_eddsa_type(&PrivatePkcs8KeyDer::from(pkcs8.as_slice()))?;
    let spki = key.public_key().ok_or(TlsError::NoPublicKey)?;
    Ok(Arc::new(CertifiedKey::new(
        vec![CertificateDer::from(spki.as_ref().to_vec())],
        key,
    )))
}

/// The Ed25519 key a peer presented, or `None` when what it presented is not a raw Ed25519
/// public key. Nothing is hashed or truncated: this is the key itself.
fn presented_key(presented: &CertificateDer<'_>) -> Option<[u8; 32]> {
    presented
        .as_ref()
        .strip_prefix(&SPKI_ED25519_PREFIX)?
        .try_into()
        .ok()
}

/// Which seed a pinned key was derived from. `Previous` is only ever reached while a rotation
/// is in progress and is what `peer_auth_via_previous_seed_total` counts, so an operator can
/// watch a fleet converge on the new seed before removing the old one (DX-N2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeedGeneration {
    /// The seed in force.
    Current,
    /// The seed being rotated out.
    Previous,
}

/// Who a pinned key belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinEntry {
    /// The roster host that derives this key. T-025 checks HELLO against it.
    pub hostname: Hostname,
    /// Which seed derived it.
    pub seed: SeedGeneration,
}

/// Every key the fleet may present, and whose it is. Built from the roster and the seeds in
/// force, which is the whole of the overlay's admission control: a key that is not here
/// belongs to no host an operator listed.
#[derive(Debug, Default)]
pub struct PinTable {
    by_key: HashMap<[u8; 32], PinEntry>,
}

impl PinTable {
    /// Derives the expected key of every roster host under every seed that is in force. The
    /// previous seed goes in first so that a key both seeds happen to derive is remembered as
    /// current, which keeps the rotation metric honest.
    pub fn build(roster: &Roster, seeds: &Seeds) -> Self {
        let mut by_key = HashMap::with_capacity(roster.hosts.len() * 2);
        let generations = seeds
            .previous
            .iter()
            .map(|seed| (seed, SeedGeneration::Previous))
            .chain([(&seeds.current, SeedGeneration::Current)]);
        for (seed, generation) in generations {
            for host in &roster.hosts {
                by_key.insert(
                    expected_tls_public_key(seed, &host.hostname),
                    PinEntry {
                        hostname: host.hostname.clone(),
                        seed: generation,
                    },
                );
            }
        }
        Self { by_key }
    }

    /// Whose key this is, if it is anybody's.
    pub fn lookup(&self, key: &[u8; 32]) -> Option<&PinEntry> {
        self.by_key.get(key)
    }

    /// Every key `hostname` may present: one, or two mid-rotation.
    pub fn expected(&self, hostname: &Hostname) -> impl Iterator<Item = [u8; 32]> {
        self.by_key
            .iter()
            .filter(move |(_, entry)| &entry.hostname == hostname)
            .map(|(key, _)| *key)
    }
}

/// Which end of a handshake gave up, as the `role` label of `handshake_failures_total`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// This host dialled.
    Dial,
    /// This host accepted.
    Accept,
}

impl Role {
    /// The metric label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dial => "dial",
            Self::Accept => "accept",
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a handshake did not finish, as the `reason` label of `handshake_failures_total`. This
/// module produces the first three; T-025 maps HELLO's failures onto the rest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureReason {
    /// The presented key belongs to no host in the roster under any seed in force.
    UnknownKey,
    /// The key is a fleet key but not the one the dialled host should have presented.
    KeyMismatch,
    /// HELLO named a host other than the one the pin table yielded.
    Hostname,
    /// The pair could not agree at the TLS layer, which for a differing protocol major is
    /// the ALPN failing to match.
    Version,
    /// The peer stopped answering before the handshake finished.
    Timeout,
    /// HELLO arrived but could not be read.
    Decode,
}

impl FailureReason {
    /// The metric label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnknownKey => "unknown_key",
            Self::KeyMismatch => "key_mismatch",
            Self::Hostname => "hostname",
            Self::Version => "version",
            Self::Timeout => "timeout",
            Self::Decode => "decode",
        }
    }
}

impl fmt::Display for FailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A handshake that did not produce a peer. T-023 counts one of these per failed dial or
/// accept and owns the rate-limited warning that goes with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{role} handshake failed: {reason}")]
pub struct HandshakeFailure {
    /// Which end this host was.
    pub role: Role,
    /// What went wrong.
    pub reason: FailureReason,
}

/// The acceptor's side of the pin check: an inbound connection is from whoever holds the key,
/// and from nobody at all if the table does not know it.
#[derive(Debug)]
pub struct AcceptorVerifier {
    pins: Arc<ArcSwap<PinTable>>,
}

impl AcceptorVerifier {
    /// Reads the table through the `ArcSwap` on every handshake, so a roster reload (T-043)
    /// replaces the pins under a running endpoint without rebuilding a configuration.
    pub fn new(pins: Arc<ArcSwap<PinTable>>) -> Self {
        Self { pins }
    }

    /// Who presented this key, or the failure to count for it.
    pub fn identify(&self, presented: &CertificateDer<'_>) -> Result<PinEntry, HandshakeFailure> {
        presented_key(presented)
            .and_then(|key| self.pins.load().lookup(&key).cloned())
            .ok_or(HandshakeFailure {
                role: Role::Accept,
                reason: FailureReason::UnknownKey,
            })
    }
}

/// The dialler's side of the pin check: the host it rang has one expected key, two while a
/// seed rotation is in progress, and anything else fails the handshake.
#[derive(Debug)]
pub struct DialerVerifier {
    pins: Arc<ArcSwap<PinTable>>,
    peer: Hostname,
}

impl DialerVerifier {
    /// One per dialled host, sharing the table with every other configuration so that a
    /// roster reload reaches all of them at once.
    pub fn new(pins: Arc<ArcSwap<PinTable>>, peer: Hostname) -> Self {
        Self { pins, peer }
    }

    /// Whether the host that answered is the host that was dialled. A key from no seed at all
    /// is the same answer as a sibling's key, because from here both are the wrong host.
    pub fn check(&self, presented: &CertificateDer<'_>) -> Result<(), HandshakeFailure> {
        let key = presented_key(presented);
        let matches = key.is_some_and(|key| {
            self.pins
                .load()
                .expected(&self.peer)
                .any(|expected| expected == key)
        });
        matches.then_some(()).ok_or(HandshakeFailure {
            role: Role::Dial,
            reason: FailureReason::KeyMismatch,
        })
    }
}

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
    #[test]
    fn acceptor_verifier_rejects_key_from_neither_seed_as_unknown_key() {
        let seeds = seeds(0x11, Some(0x22));
        let verifier = AcceptorVerifier::new(pins(&roster(&["bn-a", "bn-b"]), &seeds));

        let failure = verifier
            .identify(&presented(&FleetSeed::from([0x33; 32]), "bn-a"))
            .unwrap_err();

        assert_eq!(failure.role.as_str(), "accept");
        assert_eq!(failure.reason.as_str(), "unknown_key");
    }
    /// Same seed as the fleet, but a host nobody listed. The table is built from the roster,
    /// so the seed alone earns nothing.
    #[test]
    fn acceptor_verifier_rejects_key_of_host_absent_from_roster() {
        let seeds = seeds(0x11, None);
        let verifier = AcceptorVerifier::new(pins(&roster(&["bn-a", "bn-b"]), &seeds));

        let failure = verifier
            .identify(&presented(&seeds.current, "bn-c"))
            .unwrap_err();

        assert_eq!(failure.reason.as_str(), "unknown_key");
    }
    #[test]
    fn dialer_verifier_rejects_another_roster_hosts_key_as_key_mismatch() {
        let seeds = seeds(0x11, None);
        let verifier = DialerVerifier::new(pins(&roster(&["bn-a", "bn-b"]), &seeds), host("bn-a"));

        verifier.check(&presented(&seeds.current, "bn-a")).unwrap();
        let failure = verifier
            .check(&presented(&seeds.current, "bn-b"))
            .unwrap_err();

        assert_eq!(failure.role.as_str(), "dial");
        assert_eq!(failure.reason.as_str(), "key_mismatch");
    }
}
