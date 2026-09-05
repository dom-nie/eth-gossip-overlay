//! The sidecar's own libp2p identity: a random key made once per host and kept on disk, so
//! the peer id the beacon node trusts survives restarts, upgrades and seed rotations. It has
//! nothing to do with the fleet seed on purpose: a peer id that followed the seed would put
//! a new `--trusted-peers` value, and a restart, on every beacon node at each rotation.

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
}
