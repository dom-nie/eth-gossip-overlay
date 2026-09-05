//! The `fleet-overlay` subcommands, driven through the built binary.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use overlay_bn::node_key::PeerId;

/// A config whose node key lives in `dir`; every other key keeps its default. No seed, no
/// roster.
fn config_in(dir: &Path) -> PathBuf {
    let path = dir.join("config.yaml");
    let node_key = dir.join("node.key");
    std::fs::write(
        &path,
        format!("bn: {{ node_key_file: {} }}\n", node_key.display()),
    )
    .unwrap();
    path
}

fn fleet_overlay() -> Command {
    Command::cargo_bin("fleet-overlay").unwrap()
}

#[test]
fn peer_id_subcommand_prints_base58_and_exits_zero_without_seed_or_roster() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_in(dir.path());

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
