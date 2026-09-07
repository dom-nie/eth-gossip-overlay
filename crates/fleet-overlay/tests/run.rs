//! The `run` subcommand: the wiring, the lifecycle and what a start does before it can fail.
//! Every test drives the real binary, so what is under test is what ships.

use std::net::UdpSocket;
use std::time::Instant;

mod common;

use common::Fixture;

/// The overlay endpoint is the bind an operator gets wrong, so the failure has to name the
/// address rather than leave them reading a stack of `Os { code: 48 }`.
#[test]
fn run_fails_fast_when_overlay_port_is_taken() {
    let fixture = Fixture::new();
    let _held = UdpSocket::bind(fixture.overlay).unwrap();

    let started = Instant::now();
    let mut sidecar = fixture.run();
    let status = sidecar.wait();

    assert!(!status.success(), "{status:?}");
    assert!(started.elapsed() < common::WAIT, "{:?}", started.elapsed());
    let stderr = sidecar.stderr();
    assert!(
        stderr.contains(&fixture.overlay.to_string()),
        "no address in {stderr:?}"
    );
    assert_eq!(stderr.lines().count(), 1, "{stderr:?}");
}

/// OPS-N1 and MD-01: the beacon node reads this file with `EnvironmentFile=-` at its own start,
/// so it has to be on disk before the sidecar can fail at anything. A start that dies on the
/// overlay bind still leaves a beacon node able to trust and dial the sidecar that comes back.
#[test]
fn lighthouse_env_is_written_before_any_bind() {
    let fixture = Fixture::new();
    let runtime = tempfile::tempdir().unwrap();
    let peer_id = peer_id(&fixture);
    let _held = UdpSocket::bind(fixture.overlay).unwrap();

    let mut sidecar = fixture.run_with(|command| {
        command.env("RUNTIME_DIRECTORY", runtime.path());
    });
    assert!(!sidecar.wait().success());

    let written = std::fs::read_to_string(runtime.path().join("lighthouse.env")).unwrap();
    assert!(
        written.starts_with("FLEET_OVERLAY_TRUSTED_PEER_ARGS=--trusted-peers "),
        "{written:?}"
    );
    assert!(written.contains(&peer_id), "{written:?}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(runtime.path().join("lighthouse.env"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o644, "{mode:04o}");
    }
    let leftovers: Vec<_> = std::fs::read_dir(runtime.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .filter(|name| name != "lighthouse.env")
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

/// The node key this fixture's peer id comes from, created the way an operator creates it.
// A broken fixture is reported by panicking, which is what the unwraps here are.
#[allow(clippy::unwrap_used)]
fn peer_id(fixture: &Fixture) -> String {
    let output = fixture
        .command()
        .args(["peer-id", "--config"])
        .arg(&fixture.config)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}
