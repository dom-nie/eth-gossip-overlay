//! `fleet-overlayctl` against a stand-in for the sidecar: a socket that answers one canned
//! response, so what is under test is the CLI's requests, its output and its exit codes.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin;
use fleet_overlay::admin::Response;
use fleet_overlay::reload::{ReloadError, ReloadReport, Trigger};
use tempfile::TempDir;

/// A socket that answers every line with the same response and remembers what it was asked.
struct TestServer {
    _dir: TempDir,
    socket: PathBuf,
    asked: Arc<Mutex<Vec<String>>>,
}

// A broken fixture is reported by panicking, which is what the unwraps here are.
#[allow(clippy::unwrap_used)]
impl TestServer {
    fn start(answer: Response) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("admin.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let asked = Arc::new(Mutex::new(Vec::new()));
        let line = serde_json::to_string(&answer).unwrap();
        let seen = Arc::clone(&asked);
        // The thread ends with the process: the test binary has nothing else to wait for, and
        // an accept loop that has to be shut down is more fixture than this needs.
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut request = String::new();
                let read = BufReader::new(stream.try_clone().unwrap()).read_line(&mut request);
                if !matches!(read, Ok(1..)) {
                    continue;
                }
                seen.lock().unwrap().push(request.trim_end().to_owned());
                let _ = writeln!(stream, "{line}");
            }
        });
        Self {
            _dir: dir,
            socket,
            asked,
        }
    }

    fn asked(&self) -> Vec<String> {
        self.asked.lock().unwrap().clone()
    }
}

fn ctl(socket: &Path) -> Command {
    let mut command = Command::new(cargo_bin("fleet-overlayctl"));
    command.arg("--socket").arg(socket);
    command
}

#[test]
fn ctl_inject_off_against_test_server_exits_0_and_prints_confirmation() {
    let server = TestServer::start(Response {
        ok: true,
        inject: Some(false),
        ..Response::default()
    });

    let output = ctl(&server.socket)
        .args(["inject", "off"])
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    assert_eq!(server.asked(), [r#"{"cmd":"inject","value":false}"#]);
    let printed = String::from_utf8(output.stdout).unwrap();
    assert!(printed.contains("inject off"), "{printed}");
}

#[test]
fn ctl_roster_reload_prints_applied_and_restart_required_fields_and_exits_1_on_error() {
    let server = TestServer::start(Response {
        ok: true,
        reload: Some(ReloadReport {
            trigger: Trigger::Manual,
            applied: vec!["inject".to_owned(), "roster".to_owned()],
            restart_required: vec!["overlay.listen".to_owned()],
            error: Some(ReloadError::Roster("roster.yaml: no such file".to_owned())),
        }),
        ..Response::default()
    });

    let output = ctl(&server.socket)
        .args(["roster", "reload"])
        .output()
        .unwrap();

    // The reload ran, so the command reached the sidecar; the report says it did not finish,
    // and configuration management has to see that as a failure.
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(server.asked(), [r#"{"cmd":"reload"}"#]);
    let printed = String::from_utf8(output.stdout).unwrap();
    assert!(printed.contains("applied: inject, roster"), "{printed}");
    assert!(
        printed.contains("restart required: overlay.listen"),
        "{printed}"
    );
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("no such file"), "{stderr}");
}

#[test]
fn ctl_reports_exit_2_when_socket_is_missing() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("admin.sock");

    let output = ctl(&missing).args(["inject", "status"]).output().unwrap();

    // Nothing to talk to is not the same as a refusal, because it usually means the unit is
    // not running rather than that the command was wrong.
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains(&missing.display().to_string()), "{stderr}");
}

#[test]
fn ctl_json_flag_prints_raw_response() {
    let answer = Response {
        ok: true,
        inject: Some(true),
        ..Response::default()
    };
    let server = TestServer::start(answer);

    let output = ctl(&server.socket)
        .args(["--json", "inject", "status"])
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    let printed = String::from_utf8(output.stdout).unwrap();
    // The line the sidecar sent, so `jq` reads the same object the socket wrote.
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(printed.trim()).unwrap(),
        serde_json::json!({"ok": true, "inject": true})
    );
}
