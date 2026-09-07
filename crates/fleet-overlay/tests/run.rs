//! The `run` subcommand: the wiring, the lifecycle and what a start does before it can fail.
//! Every test drives the real binary, so what is under test is what ships.

use std::net::UdpSocket;
use std::time::{Duration, Instant};

use nix::sys::signal::Signal;

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

/// §9: a beacon node that is down or restarting is not the sidecar's problem. The link retries
/// on its own and everything else keeps working, including the scrape a local Prometheus is
/// pointed at.
#[test]
fn run_starts_with_bn_down_and_keeps_running() {
    let fixture = Fixture::new();

    let mut sidecar = fixture.run();
    let metrics = sidecar.metrics_addr();
    std::thread::sleep(Duration::from_secs(1));

    let scraped = common::scrape(metrics);
    assert!(scraped.contains("overlay_bn_connected"), "{scraped}");

    sidecar.signal(Signal::SIGTERM);
    assert!(sidecar.wait().success());
}

/// §11's two seconds: `systemctl stop` waits for the process, and a sidecar that lingers holds
/// up whatever the operator is doing next.
#[test]
fn sigterm_shuts_down_within_2_seconds_with_exit_0() {
    let fixture = Fixture::new();
    let mut sidecar = fixture.run();
    sidecar.wait_for(r#""message":"ready""#);

    let asked = Instant::now();
    sidecar.signal(Signal::SIGTERM);
    let status = sidecar.wait();

    assert!(status.success(), "{status:?}");
    assert!(
        asked.elapsed() < Duration::from_secs(2),
        "{:?}",
        asked.elapsed()
    );
}

/// §9: a wedged sidecar is worse than a dead one, because the beacon node keeps a peer that
/// does nothing. A panicking task ends the process so systemd's `Restart=always` takes over.
#[test]
fn task_panic_terminates_the_process_non_zero() {
    let fixture = Fixture::new();

    let mut sidecar = fixture.run_with(|command| {
        command.args(["--test-panic-after-ms", "100"]);
    });
    let status = sidecar.wait();

    assert!(!status.success(), "{status:?}");
    let stderr = sidecar.stderr();
    assert_eq!(stderr.lines().count(), 1, "{stderr:?}");
    assert!(stderr.contains("--test-panic-after-ms"), "{stderr:?}");
}

/// OPS-N5: `READY=1` promises that `fleet-overlayctl` works, so the admin socket has to answer
/// by the time it is sent. `STOPPING=1` is the first thing a shutdown does, so systemd stops
/// counting the process as running before it has finished going.
#[test]
fn ready_and_stopping_reach_the_notify_socket() {
    let fixture = Fixture::new();
    let notify = common::NotifySocket::start();

    let mut sidecar = fixture.run_with(|command| {
        command.env("NOTIFY_SOCKET", notify.path());
    });
    notify.wait_for("READY=1");

    let answer = common::ask_admin(
        &fixture.dir.path().join("admin.sock"),
        r#"{"cmd":"status"}"#,
    );
    assert!(answer.contains(r#""ok":true"#), "{answer}");
    assert!(
        !notify.received().contains("STOPPING=1"),
        "stopping too early"
    );

    sidecar.signal(Signal::SIGTERM);
    assert!(sidecar.wait().success());
    assert!(
        notify.received().contains("STOPPING=1"),
        "{}",
        notify.received()
    );
}

/// OPS-N5: the kick goes out at a third of `WatchdogSec`, so systemd sees three chances to hear
/// from a healthy process before it gives up on it. Two kicks inside four intervals also prove
/// that every core loop's tick arm is running, because a kick needs all four to have advanced.
#[test]
fn watchdog_messages_arrive_at_watchdog_usec_over_3() {
    let fixture = Fixture::new();
    let notify = common::NotifySocket::start();

    let sidecar = fixture.run_with(|command| {
        command
            .env("NOTIFY_SOCKET", notify.path())
            .env("WATCHDOG_USEC", "300000");
    });
    sidecar.wait_for("watchdog started");
    std::thread::sleep(Duration::from_millis(400));

    let kicks = notify.count("WATCHDOG=1");
    assert!(kicks >= 2, "{kicks} kicks in 400 ms: {}", notify.received());
}
