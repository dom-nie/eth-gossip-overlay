//! `fleet-overlayctl` against a stand-in for the sidecar: a socket that answers one canned
//! response, so what is under test is the CLI's requests, its output and its exit codes.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin;
use fleet_overlay::admin::Response;
use tempfile::TempDir;

/// A socket that answers every line with the same response and remembers what it was asked.
struct TestServer {
    _dir: TempDir,
    socket: PathBuf,
    asked: Arc<Mutex<Vec<String>>>,
}

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
