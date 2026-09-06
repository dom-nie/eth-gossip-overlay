//! The sidecar's own libp2p identity: a random key made once per host and kept on disk, so
//! the peer id the beacon node trusts survives restarts, upgrades and seed rotations. It has
//! nothing to do with the fleet seed on purpose: a peer id that followed the seed would put
//! a new `--trusted-peers` value, and a restart, on every beacon node at each rotation.

use std::fmt;
use std::io::ErrorKind;
use std::path::Path;

pub use libp2p::PeerId;
use libp2p::identity::{Keypair, ed25519};
use overlay_core::identity::{SecretFileError, create_secret_file, read_secret_file};

/// The per-host libp2p key. Held as a keypair rather than raw bytes so the secret lives only
/// inside a signing key that wipes itself on drop; `Debug` prints `NodeKey(..)`.
pub struct NodeKey(Keypair);

/// The node key file has the seed file's format, so its errors are the shared reader's.
pub type NodeKeyError = SecretFileError;

impl NodeKey {
    /// Reads the key at `path`, or makes one there from the OS random number generator when
    /// there is no file. Anything else is returned as is: a file that exists but cannot be
    /// read or parsed is never replaced, because a new key changes the peer id under a
    /// beacon node that trusts the old one.
    pub fn load_or_create(path: &Path) -> Result<Self, NodeKeyError> {
        let mut bytes = match read_secret_file(path) {
            Err(SecretFileError::Io { source, .. }) if source.kind() == ErrorKind::NotFound => {
                create_secret_file(path)?
            }
            result => result?,
        };
        Ok(Self(keypair_from(&mut bytes)))
    }

    /// The identity the BN link's swarm runs under.
    pub fn keypair(&self) -> Keypair {
        self.0.clone()
    }

    /// What the beacon node gets in `--trusted-peers`.
    pub fn peer_id(&self) -> PeerId {
        self.0.public().to_peer_id()
    }
}

/// Wraps 32 secret bytes as a libp2p keypair, wiping `bytes` on the way.
#[expect(
    clippy::expect_used,
    reason = "libp2p only rejects a secret key of the wrong length, and this one has 32 bytes"
)]
fn keypair_from(bytes: &mut [u8; 32]) -> Keypair {
    let secret = ed25519::SecretKey::try_from_bytes(bytes).expect("32-byte Ed25519 secret");
    ed25519::Keypair::from(secret).into()
}

impl fmt::Debug for NodeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NodeKey(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_key_is_created_with_64_hex_chars_newline_and_mode_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key");

        NodeKey::load_or_create(&path).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.len(), 65, "{text:?}");
        let (hex, rest) = text.split_at(64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()), "{hex}");
        assert_eq!(rest, "\n");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{mode:04o}");
        }
    }
    /// The record Lighthouse reads back: `CombinedKeyPublicExt::as_peer_id`
    /// (`common/network_utils/src/enr_ext.rs`) puts the ENR's 32 Ed25519 bytes straight into a
    /// libp2p public key, so those bytes have to be the node key's own for the beacon node to
    /// dial the peer id it already trusts.
    #[test]
    fn enr_carries_the_node_key_peer_id_and_the_listen_address() {
        let dir = tempfile::tempdir().unwrap();
        let key = NodeKey::load_or_create(&dir.path().join("node.key")).unwrap();

        let text = key.enr(&"/ip4/127.0.0.1/tcp/7787".parse().unwrap()).unwrap();

        assert!(text.starts_with("enr:"), "{text}");
        let record: enr::Enr<enr::ed25519_dalek::SigningKey> = text.parse().unwrap();
        assert_eq!(record.ip4(), Some(std::net::Ipv4Addr::LOCALHOST));
        assert_eq!(record.tcp4(), Some(7787));
        let public =
            libp2p::identity::ed25519::PublicKey::try_from_bytes(&record.public_key().to_bytes())
                .unwrap();
        assert_eq!(PeerId::from_public_key(&public.into()), key.peer_id());
    }

    #[test]
    fn enr_rejects_an_address_that_is_not_ip_and_tcp() {
        let dir = tempfile::tempdir().unwrap();
        let key = NodeKey::load_or_create(&dir.path().join("node.key")).unwrap();

        for addr in ["/ip4/127.0.0.1/udp/7787/quic-v1", "/memory/7787"] {
            let err = key.enr(&addr.parse().unwrap()).unwrap_err();

            assert!(err.to_string().contains(addr), "{addr}: {err}");
        }
    }

    #[test]
    fn node_key_second_load_returns_same_peer_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key");

        let first = NodeKey::load_or_create(&path).unwrap().peer_id();
        let second = NodeKey::load_or_create(&path).unwrap().peer_id();

        assert_eq!(first, second);
    }
    #[test]
    fn malformed_node_key_is_an_error_and_file_is_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key");
        let malformed = format!("{}c\n", "ab".repeat(31));
        std::fs::write(&path, &malformed).unwrap();

        let message = NodeKey::load_or_create(&path).unwrap_err().to_string();

        assert!(message.contains(&path.display().to_string()), "{message}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), malformed);
    }
}
