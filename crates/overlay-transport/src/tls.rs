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
use overlay_core::protocol::protocol_alpn;
use overlay_core::roster::{Hostname, Roster};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::client::AlwaysResolvesClientRawPublicKeys;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{
    CertificateDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime,
};
use rustls::server::AlwaysResolvesServerRawPublicKeys;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::sign::CertifiedKey;
use rustls::{DigitallySignedStruct, DistinguishedName, SignatureScheme};
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

/// The name the dialler puts in SNI and the acceptor never reads. TLS insists on a name;
/// the overlay's identities are keys, so one constant stands in for all of them and roster
/// hostnames never have to fit a name type (D14, D27).
pub const PLACEHOLDER_NAME: &str = "fleet-overlay";

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
    /// The provider has no TLS 1.3 initial cipher suite, without which QUIC cannot start a
    /// connection at all.
    #[error("overlay TLS: {0}")]
    Quic(#[from] quinn::crypto::rustls::NoInitialCipherSuite),
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

impl Role {
    /// What a rejected key is called from this side: the acceptor was shown a key belonging
    /// to nobody, the dialler a key belonging to somebody other than its peer.
    fn pin_failure(self) -> FailureReason {
        match self {
            Self::Dial => FailureReason::KeyMismatch,
            Self::Accept => FailureReason::UnknownKey,
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

impl HandshakeFailure {
    /// What T-023 counts when a connection never came up. A rejected key arrives as
    /// `certificate_unknown`, whether this host sent that alert or received it; a dialler
    /// cannot tell its own rejection from the peer's, and counting both as a mismatch is the
    /// honest answer, since either way the two do not agree on who the other is.
    ///
    /// An ALPN that does not match arrives as `no_application_protocol` and means a peer on
    /// another protocol major (D29). Everything else the TLS layer refuses is counted with
    /// it: a pair that cannot finish a handshake has nothing finer left to disagree about.
    pub fn from_connection_error(role: Role, error: &quinn::ConnectionError) -> Self {
        let rejected_the_key = |code| {
            code == quinn::TransportErrorCode::crypto(u8::from(
                rustls::AlertDescription::CertificateUnknown,
            ))
        };
        let reason = match error {
            quinn::ConnectionError::TimedOut => FailureReason::Timeout,
            quinn::ConnectionError::TransportError(error) if rejected_the_key(error.code) => {
                role.pin_failure()
            }
            quinn::ConnectionError::ConnectionClosed(close)
                if rejected_the_key(close.error_code) =>
            {
                role.pin_failure()
            }
            _ => FailureReason::Version,
        };
        Self { role, reason }
    }
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

impl From<HandshakeFailure> for rustls::Error {
    /// Carries the reason into the alert rustls sends and the message quinn reports, so a
    /// rejection reads as `unknown_key` rather than as an unspecified bad certificate.
    fn from(failure: HandshakeFailure) -> Self {
        Self::InvalidCertificate(rustls::CertificateError::Other(rustls::OtherError(
            Arc::new(failure),
        )))
    }
}

/// The peer signs the handshake with the key it presented, and this is the helper that reads
/// that key as a `SubjectPublicKeyInfo`. The certificate-shaped one next to it in rustls
/// parses its argument as X.509 and rejects a raw key outright.
fn verify_handshake_signature(
    message: &[u8],
    presented: &CertificateDer<'_>,
    signature: &DigitallySignedStruct,
) -> Result<HandshakeSignatureValid, rustls::Error> {
    rustls::crypto::verify_tls13_signature_with_raw_key(
        message,
        &SubjectPublicKeyInfoDer::from(presented.as_ref()),
        signature,
        &rustls::crypto::ring::default_provider().signature_verification_algorithms,
    )
}

/// QUIC mandates TLS 1.3 and the configurations below offer nothing else, so reaching this is
/// a bug in rustls rather than anything a peer can provoke.
fn no_tls12_signature() -> Result<HandshakeSignatureValid, rustls::Error> {
    Err(rustls::PeerIncompatible::Tls12NotOffered.into())
}

/// Ed25519 and nothing else. The key is derived by HKDF from the fleet seed, so no other
/// algorithm can ever appear, and offering one would only invite a downgrade.
fn ed25519_only() -> Vec<SignatureScheme> {
    vec![SignatureScheme::ED25519]
}

/// The acceptor authenticates its peer by key alone: no chain to walk, no roots to consult,
/// no name to match, and `now` unread.
impl ClientCertVerifier for AcceptorVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    /// Stated rather than left to rustls's default, because it is the whole security property
    /// of this crate: a connection with no key to pin is not a peer.
    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.identify(end_entity)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        no_tls12_signature()
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_handshake_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ed25519_only()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// The dialler likewise, and it ignores `server_name` as well: it dialled an address from the
/// roster and expects that host's key, which is a stronger statement than any name in the
/// handshake could make.
impl ServerCertVerifier for DialerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.check(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        no_tls12_signature()
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_handshake_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        ed25519_only()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// The crypto provider the overlay uses, named rather than taken from the process default:
/// another crate linked into the same binary may have registered a different one, and which
/// of them answered would then come down to link order.
fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// What this host dials `peer` with. TLS 1.3 only, because that is all QUIC has; the peer's
/// key is checked against the pin table and the name in SNI is a placeholder nobody reads.
pub fn client_config(
    pins: Arc<ArcSwap<PinTable>>,
    own_key: &SigningKey,
    peer: &Hostname,
) -> Result<quinn::ClientConfig, TlsError> {
    let mut tls = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(DialerVerifier::new(pins, peer.clone())))
        .with_client_cert_resolver(Arc::new(AlwaysResolvesClientRawPublicKeys::new(identity(
            own_key,
        )?)));
    // A ticket is a cached admission decision, and admission is per roster and per seed. A
    // resumed session skips the certificate state entirely, so the pin check would not run
    // and a ticket would outlive the roster entry that earned it.
    tls.resumption = rustls::client::Resumption::disabled();
    tls.alpn_protocols = vec![protocol_alpn()];
    Ok(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls)?,
    )))
}

/// What this host accepts on. Client authentication is mandatory: an anonymous connection has
/// no key to pin, and pinning is the only thing standing between an open UDP port and a
/// trusted path into a beacon node.
pub fn server_config(
    pins: Arc<ArcSwap<PinTable>>,
    own_key: &SigningKey,
) -> Result<quinn::ServerConfig, TlsError> {
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(AcceptorVerifier::new(pins)))
        .with_cert_resolver(Arc::new(AlwaysResolvesServerRawPublicKeys::new(identity(
            own_key,
        )?)));
    // No tickets to hand out and nothing to resume from. A resumed session restores the peer
    // straight from the ticket without entering the certificate state, so the pin check never
    // runs and a host expelled from the roster would keep its path in until the ticket aged
    // out. Admission is per roster and per seed; a cached decision cannot be either.
    tls.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    tls.send_tls13_tickets = 0;
    tls.alpn_protocols = vec![protocol_alpn()];
    Ok(quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(tls)?,
    )))
}

/// Who a live connection is with. The verifier already looked this key up to let the
/// handshake finish; reading it back off the connection is how T-023 learns the hostname
/// without the verifier having to smuggle it out.
pub fn peer_identity(pins: &PinTable, connection: &quinn::Connection) -> Option<PinEntry> {
    let presented = connection
        .peer_identity()?
        .downcast::<Vec<CertificateDer<'static>>>()
        .ok()?;
    let key = presented_key(presented.first()?)?;
    pins.lookup(&key).cloned()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use arc_swap::ArcSwap;
    use ed25519_dalek::SigningKey;
    use overlay_core::identity::{FleetSeed, Seeds, derive_tls_keypair};
    use overlay_core::roster::{HostEntry, Hostname, Region, Roster};
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::server::danger::ClientCertVerifier;

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
    /// A raw public key has no validity period, so the only date in sight is the `now` rustls
    /// hands the verifier, and both sides ignore it. A verifier that started refusing a key
    /// at some wall-clock time would take an operator's whole fleet down on a date nobody
    /// remembers setting.
    #[test]
    fn verifiers_accept_a_pinned_key_at_any_wall_clock_time() {
        let seeds = seeds(0x11, None);
        let pins = pins(&roster(&["bn-a"]), &seeds);
        let key = presented(&seeds.current, "bn-a");
        let name = ServerName::try_from(PLACEHOLDER_NAME).unwrap();

        for now in [
            UnixTime::since_unix_epoch(Duration::ZERO),
            UnixTime::since_unix_epoch(Duration::from_secs(1 << 40)),
        ] {
            AcceptorVerifier::new(pins.clone())
                .verify_client_cert(&key, &[], now)
                .unwrap();
            DialerVerifier::new(pins.clone(), host("bn-a"))
                .verify_server_cert(&key, &[], &name, &[], now)
                .unwrap();
        }
    }
    /// Half of the ticket's question is gone with X.509: there is no subject alternative name
    /// on this wire to read. The other half stands. Whatever the dialler puts in SNI, and
    /// whatever a peer would like to be called, the hostname comes from the table.
    #[test]
    fn verifiers_never_read_the_server_name() {
        let seeds = seeds(0x11, None);
        let pins = pins(&roster(&["bn-a", "bn-b"]), &seeds);
        let key = presented(&seeds.current, "bn-a");
        let dialler = DialerVerifier::new(pins.clone(), host("bn-a"));
        let now = UnixTime::since_unix_epoch(Duration::from_secs(1_800_000_000));

        for name in ["bn-b", PLACEHOLDER_NAME, "10.0.0.1"] {
            let name = ServerName::try_from(name).unwrap();
            dialler
                .verify_server_cert(&key, &[], &name, &[], now)
                .unwrap();
        }

        let entry = AcceptorVerifier::new(pins).identify(&key).unwrap();
        assert_eq!(entry.hostname, host("bn-a"));
    }
    #[test]
    fn previous_seed_key_is_accepted_while_configured_and_rejected_after() {
        let roster = roster(&["bn-a"]);
        let old_key = presented(&FleetSeed::from([0x22; 32]), "bn-a");

        let during = AcceptorVerifier::new(pins(&roster, &seeds(0x11, Some(0x22))))
            .identify(&old_key)
            .unwrap();
        let after = AcceptorVerifier::new(pins(&roster, &seeds(0x11, None)))
            .identify(&old_key)
            .unwrap_err();

        assert_eq!(during.hostname, host("bn-a"));
        assert_eq!(during.seed, SeedGeneration::Previous);
        assert_eq!(after.reason.as_str(), "unknown_key");
    }
    /// What the loopback acceptor made of a connection: an error when it refused the
    /// handshake, `Ok(None)` when the handshake finished without it identifying anybody.
    type Accepted = Vec<Result<Option<PinEntry>, HandshakeFailure>>;

    fn own_key(seeds: &Seeds, name: &str) -> SigningKey {
        derive_tls_keypair(&seeds.current, &host(name))
    }

    fn loopback() -> std::net::SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    /// An acceptor bound on an ephemeral loopback port, and a task reporting what became of
    /// the next `connections` to arrive: an error when the handshake was refused, `None` when
    /// it completed without the acceptor learning whose key it was.
    ///
    /// Each admitted connection is sent a byte and kept open, so a dialler can wait until
    /// everything the acceptor sent after the handshake has reached it.
    fn acceptor_taking(
        pins: &Arc<ArcSwap<PinTable>>,
        seeds: &Seeds,
        name: &str,
        connections: usize,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<Accepted>) {
        let endpoint = quinn::Endpoint::server(
            server_config(pins.clone(), &own_key(seeds, name)).unwrap(),
            loopback(),
        )
        .unwrap();
        let addr = endpoint.local_addr().unwrap();
        let pins = pins.clone();
        let task = tokio::spawn(async move {
            let mut outcomes = Vec::new();
            let mut open = Vec::new();
            for _ in 0..connections {
                let incoming = endpoint.accept().await.expect("the endpoint is still open");
                outcomes.push(match incoming.await {
                    Ok(connection) => {
                        let mut stream = connection.open_uni().await.unwrap();
                        stream.write_all(b".").await.unwrap();
                        stream.finish().unwrap();
                        open.push(connection.clone());
                        Ok(peer_identity(&pins.load(), &connection))
                    }
                    Err(error) => Err(HandshakeFailure::from_connection_error(
                        Role::Accept,
                        &error,
                    )),
                });
            }
            drop(open);
            outcomes
        });
        (addr, task)
    }

    /// [`acceptor_taking`] for the one connection a test is about.
    fn acceptor(
        pins: &Arc<ArcSwap<PinTable>>,
        seeds: &Seeds,
        name: &str,
    ) -> (std::net::SocketAddr, tokio::task::JoinHandle<Accepted>) {
        acceptor_taking(pins, seeds, name, 1)
    }

    /// A sidecar from a fleet running the next protocol major, built here because the ALPN
    /// this crate offers has one source and no knob.
    fn dialler_of_another_major(
        pins: &Arc<ArcSwap<PinTable>>,
        own: &SigningKey,
        peer: &str,
    ) -> quinn::ClientConfig {
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(DialerVerifier::new(pins.clone(), host(peer))))
        .with_client_cert_resolver(Arc::new(
            rustls::client::AlwaysResolvesClientRawPublicKeys::new(identity(own).unwrap()),
        ));
        tls.alpn_protocols = vec![b"fleet-overlay/2".to_vec()];
        quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
        ))
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn quinn_loopback_handshake_succeeds_with_matching_keys_and_fails_with_alpn_mismatch() {
        let seeds = seeds(0x11, None);
        let pins = pins(&roster(&["bn-a", "bn-b"]), &seeds);
        let (addr, accepted) = acceptor(&pins, &seeds, "bn-a");
        let dialler = quinn::Endpoint::client(loopback()).unwrap();
        let key = own_key(&seeds, "bn-b");

        let config = client_config(pins.clone(), &key, &host("bn-a")).unwrap();
        let connection = dialler
            .connect_with(config, addr, PLACEHOLDER_NAME)
            .unwrap()
            .await
            .unwrap();

        assert_eq!(
            peer_identity(&pins.load(), &connection).unwrap().hostname,
            host("bn-a")
        );
        assert_eq!(
            accepted.await.unwrap().remove(0).unwrap().unwrap().hostname,
            host("bn-b")
        );

        let (addr, _) = acceptor(&pins, &seeds, "bn-a");
        let error = dialler
            .connect_with(
                dialler_of_another_major(&pins, &key, "bn-a"),
                addr,
                PLACEHOLDER_NAME,
            )
            .unwrap()
            .await
            .unwrap_err();

        let failure = HandshakeFailure::from_connection_error(Role::Dial, &error);
        assert_eq!(failure.reason.as_str(), "version");
    }
    /// The half of the classification test 8 cannot reach. Worth doing on a real handshake
    /// rather than on the verifier, because TLS 1.3 lets the dialler finish before the
    /// acceptor has looked at its key: a dial that resolves is not yet a peer, and the
    /// rejection turns up on `closed()` afterwards.
    #[tokio::test(flavor = "multi_thread")]
    async fn pin_rejections_are_counted_by_the_role_that_saw_them() {
        let seeds = seeds(0x11, None);
        let pins = pins(&roster(&["bn-a", "bn-b"]), &seeds);
        let dialler = quinn::Endpoint::client(loopback()).unwrap();

        let (addr, _) = acceptor(&pins, &seeds, "bn-a");
        let expecting_the_wrong_host =
            client_config(pins.clone(), &own_key(&seeds, "bn-b"), &host("bn-b")).unwrap();
        let refused = dialler
            .connect_with(expecting_the_wrong_host, addr, PLACEHOLDER_NAME)
            .unwrap()
            .await
            .unwrap_err();

        assert_eq!(
            HandshakeFailure::from_connection_error(Role::Dial, &refused).reason,
            FailureReason::KeyMismatch
        );

        let (addr, accepted) = acceptor(&pins, &seeds, "bn-a");
        let stranger = derive_tls_keypair(&FleetSeed::from([0x99; 32]), &host("bn-b"));
        let connection = dialler
            .connect_with(
                client_config(pins.clone(), &stranger, &host("bn-a")).unwrap(),
                addr,
                PLACEHOLDER_NAME,
            )
            .unwrap()
            .await
            .unwrap();

        assert_eq!(
            accepted.await.unwrap().remove(0).unwrap_err().reason,
            FailureReason::UnknownKey
        );
        assert_eq!(
            HandshakeFailure::from_connection_error(Role::Dial, &connection.closed().await).reason,
            FailureReason::KeyMismatch
        );
    }
    /// One acceptor, one dialler, one configuration each, and a roster that grows in between.
    #[tokio::test(flavor = "multi_thread")]
    async fn roster_reload_rebuilds_pin_table_without_rebuilding_config() {
        let seeds = seeds(0x11, None);
        let pins = pins(&roster(&["bn-a", "bn-b"]), &seeds);
        let (addr, accepting) = acceptor_taking(&pins, &seeds, "bn-a", 2);
        let mut dialler = quinn::Endpoint::client(loopback()).unwrap();
        dialler.set_default_client_config(
            client_config(pins.clone(), &own_key(&seeds, "bn-c"), &host("bn-a")).unwrap(),
        );

        let refused = dialler
            .connect(addr, PLACEHOLDER_NAME)
            .unwrap()
            .await
            .unwrap();
        refused.closed().await;
        pins.store(Arc::new(PinTable::build(
            &roster(&["bn-a", "bn-b", "bn-c"]),
            &seeds,
        )));
        let admitted = dialler
            .connect(addr, PLACEHOLDER_NAME)
            .unwrap()
            .await
            .unwrap();

        let outcomes = accepting.await.unwrap();
        assert_eq!(
            outcomes[0].as_ref().unwrap_err().reason,
            FailureReason::UnknownKey
        );
        assert_eq!(
            outcomes[1].as_ref().unwrap().as_ref().unwrap().hostname,
            host("bn-c")
        );
        assert_eq!(
            peer_identity(&pins.load(), &admitted).unwrap().hostname,
            host("bn-a")
        );
    }
    /// A hostname no name type would take: a slash, a space, no dots. It is a roster key and
    /// a key-derivation input, and it never reaches the wire.
    #[tokio::test(flavor = "multi_thread")]
    async fn hostnames_need_not_be_dns_names() {
        let seeds = seeds(0x11, None);
        let pins = pins(&roster(&["rack3/bn 01", "bn-b"]), &seeds);
        let (addr, accepted) = acceptor(&pins, &seeds, "rack3/bn 01");
        let dialler = quinn::Endpoint::client(loopback()).unwrap();
        let config =
            client_config(pins.clone(), &own_key(&seeds, "bn-b"), &host("rack3/bn 01")).unwrap();

        let connection = dialler
            .connect_with(config, addr, PLACEHOLDER_NAME)
            .unwrap()
            .await
            .unwrap();

        assert_eq!(
            peer_identity(&pins.load(), &connection).unwrap().hostname,
            host("rack3/bn 01")
        );
        assert_eq!(
            accepted.await.unwrap().remove(0).unwrap().unwrap().hostname,
            host("bn-b")
        );
    }
    /// A session ticket is a cached admission decision, and admission here is per roster and
    /// per seed, so resuming one would let a host that has just been removed from the roster
    /// back in for as long as its ticket lasts. `roster_reload_rebuilds_pin_table_without_
    /// rebuilding_config` cannot see this: it lets a host in and never puts one out.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_expelled_host_cannot_resume_an_earlier_session() {
        let seeds = seeds(0x11, None);
        let pins = pins(&roster(&["bn-a", "bn-b", "bn-c"]), &seeds);
        let (addr, accepting) = acceptor_taking(&pins, &seeds, "bn-a", 2);
        let mut dialler = quinn::Endpoint::client(loopback()).unwrap();
        dialler.set_default_client_config(
            client_config(pins.clone(), &own_key(&seeds, "bn-c"), &host("bn-a")).unwrap(),
        );

        let admitted = dialler
            .connect(addr, PLACEHOLDER_NAME)
            .unwrap()
            .await
            .unwrap();
        admitted
            .accept_uni()
            .await
            .unwrap()
            .read_to_end(1)
            .await
            .unwrap();
        pins.store(Arc::new(PinTable::build(
            &roster(&["bn-a", "bn-b"]),
            &seeds,
        )));
        let _resumed = dialler.connect(addr, PLACEHOLDER_NAME).unwrap().await;

        let outcomes = accepting.await.unwrap();
        assert_eq!(
            outcomes[0].as_ref().unwrap().as_ref().unwrap().hostname,
            host("bn-c")
        );
        assert_eq!(
            outcomes[1].as_ref().unwrap_err().reason,
            FailureReason::UnknownKey
        );
    }
    /// None of this shows up in a handshake test, and all of it is load bearing.
    /// `requires_raw_public_keys` is what drives certificate-type negotiation: set it false
    /// on the acceptor and rustls settles on X.509 with anyone who offers it, every sibling
    /// fails with the wrong certificate type counted as `version`, and the module quietly
    /// stops doing what its doc says.
    #[test]
    fn verifiers_ask_for_raw_ed25519_keys_and_mandatory_client_auth() {
        let seeds = seeds(0x11, None);
        let pins = pins(&roster(&["bn-a"]), &seeds);
        let acceptor = AcceptorVerifier::new(pins.clone());
        let dialler = DialerVerifier::new(pins, host("bn-a"));

        assert!(ClientCertVerifier::requires_raw_public_keys(&acceptor));
        assert!(ServerCertVerifier::requires_raw_public_keys(&dialler));
        assert!(acceptor.client_auth_mandatory());
        assert_eq!(
            ClientCertVerifier::supported_verify_schemes(&acceptor),
            vec![SignatureScheme::ED25519]
        );
        assert_eq!(
            ServerCertVerifier::supported_verify_schemes(&dialler),
            vec![SignatureScheme::ED25519]
        );
    }
}
