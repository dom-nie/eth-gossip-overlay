//! The `fleet-overlay` subcommands, driven through the built binary.

use std::io;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin;
use overlay_bn::node_key::PeerId;

/// A config whose node key lives in `dir`; every other key keeps its default. No seed, no
/// roster.
fn config_in(dir: &Path) -> io::Result<PathBuf> {
    let path = dir.join("config.yaml");
    let node_key = dir.join("node.key");
    std::fs::write(
        &path,
        format!("bn: {{ node_key_file: {} }}\n", node_key.display()),
    )?;
    Ok(path)
}

fn fleet_overlay() -> Command {
    Command::new(cargo_bin("fleet-overlay"))
}

#[test]
fn peer_id_subcommand_prints_base58_and_exits_zero_without_seed_or_roster() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_in(dir.path()).unwrap();

    let output = fleet_overlay()
        .args(["peer-id", "--config"])
        .arg(&config)
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    let printed = String::from_utf8(output.stdout).unwrap();
    let peer_id: PeerId = printed.trim().parse().unwrap();
    assert!(dir.path().join("node.key").is_file());

    let again = fleet_overlay()
        .args(["peer-id", "--config"])
        .arg(&config)
        .output()
        .unwrap();

    assert!(again.status.success(), "{again:?}");
    assert_eq!(
        String::from_utf8(again.stdout).unwrap().trim(),
        peer_id.to_string()
    );
}

#[test]
fn peer_id_subcommand_fails_on_malformed_node_key() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_in(dir.path()).unwrap();
    let node_key = dir.path().join("node.key");
    std::fs::write(&node_key, format!("{}c\n", "ab".repeat(31))).unwrap();

    let output = fleet_overlay()
        .args(["peer-id", "--config"])
        .arg(&config)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains(&node_key.display().to_string()), "{stderr}");
}

#[test]
fn gen_seed_writes_64_hex_chars_newline_and_mode_0600() {
    let dir = tempfile::tempdir().unwrap();
    let seed = dir.path().join("seed");

    let output = fleet_overlay()
        .args(["gen-seed", "--out"])
        .arg(&seed)
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    let text = std::fs::read_to_string(&seed).unwrap();
    assert_eq!(text.len(), 65, "{text:?}");
    let (hex, rest) = text.split_at(64);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()), "{hex}");
    assert_eq!(rest, "\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&seed).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{mode:04o}");
    }
}

#[test]
fn gen_seed_refuses_to_overwrite_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let seed = dir.path().join("seed");
    std::fs::write(&seed, "keep me\n").unwrap();

    let output = fleet_overlay()
        .args(["gen-seed", "--out"])
        .arg(&seed)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains(&seed.display().to_string()), "{stderr}");
    assert_eq!(std::fs::read_to_string(&seed).unwrap(), "keep me\n");
}
