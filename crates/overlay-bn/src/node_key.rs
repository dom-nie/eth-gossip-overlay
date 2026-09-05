//! The sidecar's own libp2p identity: a random key made once per host and kept on disk, so
//! the peer id the beacon node trusts survives restarts, upgrades and seed rotations. It has
//! nothing to do with the fleet seed on purpose: a peer id that followed the seed would put
//! a new `--trusted-peers` value, and a restart, on every beacon node at each rotation.

use std::fmt;
use std::io::ErrorKind;
use std::path::Path;

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
    #[test]
    fn node_key_second_load_returns_same_peer_id() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.key");

        let first = NodeKey::load_or_create(&path).unwrap().peer_id();
        let second = NodeKey::load_or_create(&path).unwrap().peer_id();

        assert_eq!(first, second);
    }
}
