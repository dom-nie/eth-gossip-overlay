//! The `fleet-overlay` subcommands, driven through the built binary.

use std::io;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin;
use overlay_bn::node_key::PeerId;
use overlay_core::identity::FleetSeed;

mod common;

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

#[test]
fn gen_seed_output_loads_as_a_valid_fleet_seed() {
    let dir = tempfile::tempdir().unwrap();
    let seed = dir.path().join("seed");

    fleet_overlay()
        .args(["gen-seed", "--out"])
        .arg(&seed)
        .assert()
        .success();

    FleetSeed::load_from(None, &seed).unwrap();
}

#[test]
fn check_config_with_valid_files_exits_0_and_prints_hostname_region_and_peer_id() {
    let fixture = common::Fixture::new();

    let output = fixture
        .command()
        .args(["check-config", "--config"])
        .arg(&fixture.config)
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    let printed = String::from_utf8(output.stdout).unwrap();
    let peer_id = std::fs::read_to_string(&fixture.node_key)
        .map(|_| peer_id_of(&fixture))
        .unwrap();
    for expected in [common::HOSTNAME, common::REGION, common::SITE, &peer_id] {
        assert!(
            printed.contains(expected),
            "{expected} missing from {printed}"
        );
    }
}

#[test]
fn check_config_with_missing_roster_exits_1_and_names_the_path() {
    let fixture = common::Fixture::new();
    std::fs::remove_file(&fixture.roster).unwrap();

    let output = fixture
        .command()
        .args(["check-config", "--config"])
        .arg(&fixture.config)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(
        stderr.contains(&fixture.roster.display().to_string()),
        "{stderr}"
    );
}

#[test]
fn check_config_with_hostname_not_in_roster_exits_1() {
    let fixture = common::Fixture::new();

    let output = fixture
        .command()
        .env("FLEET_OVERLAY_HOSTNAME", "bn-nobody-99")
        .args(["check-config", "--config"])
        .arg(&fixture.config)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("bn-nobody-99"), "{stderr}");
}

/// The peer id `peer-id` prints for this fixture's node key, which is what `check-config` has to
/// agree with.
// A broken fixture is reported by panicking, which is what the unwraps here are.
#[allow(clippy::unwrap_used)]
fn peer_id_of(fixture: &common::Fixture) -> String {
    let output = fixture
        .command()
        .args(["peer-id", "--config"])
        .arg(&fixture.config)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

/// D01: the node key is the sidecar's whole libp2p identity, so `peer-id` runs on a host that
/// has neither a seed nor a roster yet. Which is what an operator does first, to put the id in
/// the beacon node's configuration before the sidecar has ever started.
#[test]
fn peer_id_needs_only_the_node_key() {
    let dir = tempfile::tempdir().unwrap();
    let config = config_in(dir.path()).unwrap();
    let node_key = dir.path().join("node.key");

    let first = fleet_overlay()
        .args(["peer-id", "--config"])
        .arg(&config)
        .output()
        .unwrap();

    assert!(first.status.success(), "{first:?}");
    assert!(node_key.is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&node_key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{mode:04o}");
    }

    let second = fleet_overlay()
        .args(["peer-id", "--config"])
        .arg(&config)
        .output()
        .unwrap();

    assert!(second.status.success(), "{second:?}");
    assert_eq!(second.stdout, first.stdout);
}

/// D29: the first line identifies the build, the second says what it can pair with. T-048
/// asserts on both from the released artefacts, so their shape is fixed here.
#[test]
fn version_prints_crate_version_sha_build_date_and_protocol_line() {
    let output = fleet_overlay().arg("--version").output().unwrap();

    assert!(output.status.success(), "{output:?}");
    let printed = String::from_utf8(output.stdout).unwrap();
    let mut lines = printed.lines();

    let build = lines.next().unwrap();
    assert!(
        build.contains(env!("CARGO_PKG_VERSION")),
        "no crate version in {build:?}"
    );
    let words: Vec<&str> = build.split_whitespace().collect();
    assert_eq!(
        words.len(),
        4,
        "expected name, version, sha and date: {build:?}"
    );
    let date = words[3];
    assert!(
        date.len() == 10 && date.split('-').count() == 3,
        "no yyyy-mm-dd build date in {build:?}"
    );

    let protocol = lines.next().unwrap();
    let (version, features) = protocol
        .strip_prefix("protocol ")
        .and_then(|rest| rest.split_once(" features=0x"))
        .unwrap_or_else(|| panic!("{protocol:?}"));
    let (major, minor) = version.split_once('.').unwrap();
    assert!(
        major.parse::<u8>().is_ok() && minor.parse::<u16>().is_ok(),
        "{version}"
    );
    assert!(
        !features.is_empty()
            && features
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
        "{features}"
    );
    assert_eq!(lines.next(), None, "{printed}");
}
