//! Who a sidecar is on the overlay and where that comes from. One seed is shared by the whole
//! fleet, and HKDF over the seed and a hostname gives every host's overlay TLS key, so a host
//! can compute a sibling's expected key from the roster alone. Nothing else derives from the
//! seed: the libp2p identity is a per-host key in `overlay_bn::node_key`, so rotating the seed
//! never touches a beacon node.

use std::fmt;
use std::path::{Path, PathBuf};

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

/// The environment variable systemd sets to the directory `LoadCredential=` populates.
const CREDENTIALS_DIR_ENV: &str = "CREDENTIALS_DIRECTORY";

impl FleetSeed {
    /// Reads the seed the process was given: `$CREDENTIALS_DIRECTORY/seed` when systemd
    /// passed one, else `configured`. The error names whichever file was actually tried.
    pub fn load(configured: &Path) -> Result<Self, SecretFileError> {
        let credentials_dir = std::env::var_os(CREDENTIALS_DIR_ENV).map(PathBuf::from);
        Self::load_from(credentials_dir.as_deref(), configured)
    }

    /// [`FleetSeed::load`] with the credentials directory passed in, so a test can stage any
    /// combination without touching the process environment.
    pub fn load_from(
        credentials_dir: Option<&Path>,
        configured: &Path,
    ) -> Result<Self, SecretFileError> {
        read_secret_file(&resolve_seed_path(credentials_dir, configured)).map(Self)
    }
}

/// `<credentials_dir>/seed` when that file exists, else `configured`. A unit without
/// `LoadCredential=seed:...` still has `CREDENTIALS_DIRECTORY` set if it loads any other
/// credential, which is why the file's presence decides and not the variable's.
fn resolve_seed_path(credentials_dir: Option<&Path>, configured: &Path) -> PathBuf {
    credentials_dir
        .map(|dir| dir.join("seed"))
        .filter(|seed| seed.is_file())
        .unwrap_or_else(|| configured.to_owned())
}

/// Why a seed or node key file could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum SecretFileError {
    /// The file could not be read or created.
    #[error("{}: {source}", .path.display())]
    Io {
        /// The file that was asked for.
        path: PathBuf,
        /// What the filesystem said.
        source: std::io::Error,
    },
    /// The file exists but is not 64 hex characters and an optional newline.
    #[error("{}: {reason}", .path.display())]
    Malformed {
        /// The file that was read.
        path: PathBuf,
        /// What is wrong with the text.
        reason: String,
    },
}

/// Reads 32 secret bytes from `path`, written as 64 hex characters with an optional trailing
/// newline. The seed and the node key share this format. A file that other users can read is
/// reported with a warning rather than refused: configuration management may be halfway
/// through fixing it, and a sidecar that will not start helps nobody.
pub fn read_secret_file(path: &Path) -> Result<Zeroizing<[u8; 32]>, SecretFileError> {
    let io = |source| SecretFileError::Io {
        path: path.to_owned(),
        source,
    };
    let raw = Zeroizing::new(std::fs::read(path).map_err(io)?);
    #[cfg(unix)]
    warn_if_readable_by_others(path, &std::fs::metadata(path).map_err(io)?);
    let hex = raw.strip_suffix(b"\n").unwrap_or(&raw);
    decode_hex(hex).map_err(|reason| SecretFileError::Malformed {
        path: path.to_owned(),
        reason,
    })
}

#[cfg(unix)]
fn warn_if_readable_by_others(path: &Path, metadata: &std::fs::Metadata) {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        tracing::warn!(
            path = %path.display(),
            mode = format_args!("{mode:04o}"),
            "secret file is readable by other users; expected mode 0600"
        );
    }
}

fn decode_hex(hex: &[u8]) -> Result<Zeroizing<[u8; 32]>, String> {
    if hex.len() != 64 {
        return Err(format!("expected 64 hex characters, found {}", hex.len()));
    }
    let mut bytes = Zeroizing::new([0u8; 32]);
    for (byte, [high, low]) in bytes.iter_mut().zip(hex.as_chunks::<2>().0) {
        *byte = (nibble(*high)? << 4) | nibble(*low)?;
    }
    Ok(bytes)
}

fn nibble(c: u8) -> Result<u8, String> {
    (c as char)
        .to_digit(16)
        .map(|digit| digit as u8)
        .ok_or_else(|| format!("{:?} is not a hex digit", c as char))
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

/// The public half of [`derive_tls_keypair`]: what a sibling pins for `hostname`. T-021 builds
/// its pin table by calling this for every roster host.
pub fn expected_tls_public_key(seed: &FleetSeed, hostname: &Hostname) -> [u8; 32] {
    derive_tls_keypair(seed, hostname)
        .verifying_key()
        .to_bytes()
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

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
    #[test]
    fn different_hostnames_give_different_tls_keys() {
        let seed = seed(0x11);

        let one = derive_tls_keypair(&seed, &host("bn-1"));
        let two = derive_tls_keypair(&seed, &host("bn-2"));

        assert_ne!(one.to_bytes(), two.to_bytes());
    }
    #[test]
    fn different_seeds_give_different_tls_keys() {
        let one = derive_tls_keypair(&seed(0x11), &host("bn-1"));
        let two = derive_tls_keypair(&seed(0x22), &host("bn-1"));

        assert_ne!(one.to_bytes(), two.to_bytes());
    }
    fn seed_file(dir: &Path, name: &str, text: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn seed_file_with_63_hex_chars_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = seed_file(dir.path(), "seed", &format!("{}c", "ab".repeat(31)));

        let message = FleetSeed::load_from(None, &path).unwrap_err().to_string();

        assert!(
            message.contains(&path.display().to_string()) && message.contains("63"),
            "{message}"
        );
    }

    #[test]
    fn seed_file_with_trailing_newline_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let path = seed_file(dir.path(), "seed", &format!("{}\n", "ab".repeat(32)));

        let loaded = FleetSeed::load_from(None, &path).unwrap();

        assert_eq!(loaded.0, seed(0xab).0);
    }

    #[test]
    fn seed_file_with_non_hex_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = seed_file(dir.path(), "seed", &"zz".repeat(32));

        let message = FleetSeed::load_from(None, &path).unwrap_err().to_string();

        assert!(
            message.contains(&path.display().to_string()) && message.contains("'z'"),
            "{message}"
        );
    }
    #[test]
    fn expected_tls_public_key_matches_keypair_public_key() {
        let seed = seed(0x11);

        let expected = expected_tls_public_key(&seed, &host("bn-1"));

        let keypair = derive_tls_keypair(&seed, &host("bn-1"));
        assert_eq!(expected, keypair.verifying_key().to_bytes());
    }
    #[test]
    fn seed_load_prefers_credentials_directory() {
        let dir = tempfile::tempdir().unwrap();
        let credentials = dir.path().join("credentials");
        std::fs::create_dir(&credentials).unwrap();
        seed_file(&credentials, "seed", &"11".repeat(32));
        let configured = seed_file(dir.path(), "seed", &"22".repeat(32));

        let loaded = FleetSeed::load_from(Some(&credentials), &configured).unwrap();

        assert_eq!(loaded.0, seed(0x11).0);
    }
    #[test]
    fn seed_load_falls_back_to_path_when_credential_absent() {
        let dir = tempfile::tempdir().unwrap();
        let credentials = dir.path().join("credentials");
        std::fs::create_dir(&credentials).unwrap();
        let configured = seed_file(dir.path(), "seed", &"22".repeat(32));

        let loaded = FleetSeed::load_from(Some(&credentials), &configured).unwrap();

        assert_eq!(loaded.0, seed(0x22).0);
    }
}
