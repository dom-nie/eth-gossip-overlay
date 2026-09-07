//! A sidecar's files on disk and a running sidecar process, for the tests that drive the real
//! binary. Everything lives under one [`tempfile::TempDir`], so nothing here needs a fixed port
//! or a path outside the test.
#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use assert_cmd::cargo::cargo_bin;

/// The host every fixture runs as, and the first entry in its roster.
pub const HOSTNAME: &str = "bn-ams1-07";
/// Its region, which `check-config` and the admin socket both report.
pub const REGION: &str = "eu";
/// Its site label.
pub const SITE: &str = "ams1";

/// Long enough for a process start plus a bind on a loaded machine, short enough that a test
/// which will never pass fails instead of hanging.
pub const WAIT: Duration = Duration::from_secs(10);

/// A config, roster and seed under one temporary directory.
pub struct Fixture {
    pub dir: tempfile::TempDir,
    pub config: PathBuf,
    pub roster: PathBuf,
    pub seed: PathBuf,
    pub node_key: PathBuf,
    /// The overlay port the config asks for, which a test can take first.
    pub overlay: SocketAddr,
}

impl Fixture {
    /// A fixture whose roster holds this host alone, on ports nothing else in the test binary
    /// is using.
    pub fn new() -> Self {
        Self::with_hosts(&[(HOSTNAME, REGION, SITE)])
    }

    /// The same with a roster of `hosts`, each `(hostname, region, site)`.
    pub fn with_hosts(hosts: &[(&str, &str, &str)]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = |name: &str| dir.path().join(name);
        let (config, roster, seed, node_key) = (
            path("config.yaml"),
            path("roster.yaml"),
            path("seed"),
            path("node.key"),
        );

        let overlay = free_port();
        let mut entries = String::from("hosts:\n");
        for (index, (hostname, region, site)) in hosts.iter().enumerate() {
            let addr = if index == 0 { overlay } else { free_port() };
            entries.push_str(&format!(
                "  - hostname: {hostname}\n    region: {region}\n    site: {site}\n    addr: \"{addr}\"\n"
            ));
        }
        std::fs::write(&roster, entries).unwrap();
        std::fs::write(&seed, format!("{}\n", "ab".repeat(32))).unwrap();
        std::fs::write(&config, config_yaml(dir.path(), overlay)).unwrap();

        Self {
            dir,
            config,
            roster,
            seed,
            node_key,
            overlay,
        }
    }

    /// Rewrites `config.yaml` with `edit` applied to the text this fixture wrote.
    pub fn edit_config(&self, edit: impl Fn(&str) -> String) {
        let text = std::fs::read_to_string(&self.config).unwrap();
        std::fs::write(&self.config, edit(&text)).unwrap();
    }

    /// The sidecar under test, not yet started.
    pub fn command(&self) -> Command {
        let mut command = Command::new(cargo_bin("fleet-overlay"));
        command
            .env("FLEET_OVERLAY_HOSTNAME", HOSTNAME)
            .env_remove("RUST_LOG")
            .env_remove("NOTIFY_SOCKET")
            .env_remove("WATCHDOG_USEC")
            .env_remove("CREDENTIALS_DIRECTORY")
            .env_remove("RUNTIME_DIRECTORY");
        command
    }

    /// Starts `run` and returns the process with its output being collected.
    pub fn run(&self) -> Sidecar {
        self.run_with(|_| {})
    }

    /// The same with `setup` applied to the command first, for the environment a test stages.
    pub fn run_with(&self, setup: impl FnOnce(&mut Command)) -> Sidecar {
        let mut command = self.command();
        command
            .arg("run")
            .arg("--config")
            .arg(&self.config)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        setup(&mut command);
        Sidecar::start(command)
    }
}

/// The `config.yaml` every fixture writes: temp paths everywhere, a beacon node nothing is
/// listening for, and ephemeral ports for the two listeners a test reads back out of the log.
fn config_yaml(dir: &Path, overlay: SocketAddr) -> String {
    let path = |name: &str| dir.join(name).display().to_string();
    format!(
        "overlay:\n  \
           listen: \"{overlay}\"\n  \
           roster_file: {}\n  \
           fleet_seed_file: {}\n\
         bn:\n  \
           node_key_file: {}\n  \
           identity_url: \"http://127.0.0.1:{}/eth/v1/node/identity\"\n  \
           libp2p_addr: \"/ip4/127.0.0.1/tcp/{}\"\n  \
           listen_addr: \"/ip4/127.0.0.1/tcp/0\"\n\
         admin_socket: {}\n\
         metrics_listen: \"127.0.0.1:0\"\n\
         log:\n  level: info\n  format: json\n",
        path("roster.yaml"),
        path("seed"),
        path("node.key"),
        free_port().port(),
        free_port().port(),
        path("admin.sock"),
    )
}

/// A loopback address nothing holds. The listener is closed before the caller gets it, so the
/// port is free rather than taken; a test that needs it taken binds it again itself.
pub fn free_port() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

/// A running sidecar with its stdout and stderr drained into memory, so a test can wait for a
/// line without the child ever blocking on a full pipe.
pub struct Sidecar {
    child: Child,
    stdout: Output,
    stderr: Output,
}

/// What one of the child's streams has produced so far.
#[derive(Clone, Default)]
pub struct Output(Arc<Mutex<String>>);

impl Output {
    /// Everything read so far.
    pub fn text(&self) -> String {
        self.0.lock().unwrap().clone()
    }
}

impl Sidecar {
    fn start(mut command: Command) -> Self {
        let mut child = command.spawn().unwrap();
        let stdout = drain(child.stdout.take().unwrap());
        let stderr = drain(child.stderr.take().unwrap());
        Self {
            child,
            stdout,
            stderr,
        }
    }

    /// The child's process id, for the signal a test sends it.
    pub fn id(&self) -> u32 {
        self.child.id()
    }

    pub fn stdout(&self) -> String {
        self.stdout.text()
    }

    pub fn stderr(&self) -> String {
        self.stderr.text()
    }

    /// Waits for a log line holding `needle` and returns it, or panics with everything seen.
    pub fn wait_for(&self, needle: &str) -> String {
        let deadline = Instant::now() + WAIT;
        while Instant::now() < deadline {
            if let Some(line) = self
                .stdout()
                .lines()
                .find(|line| line.contains(needle))
                .map(str::to_owned)
            {
                return line;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("no line holding {needle:?} in:\n{}", self.stdout());
    }

    /// The address the metrics endpoint bound, read out of the startup log.
    pub fn metrics_addr(&self) -> SocketAddr {
        let line = self.wait_for("metrics endpoint");
        field(&line, "addr").parse().unwrap()
    }

    /// Sends `signal` to the child.
    pub fn signal(&self, signal: nix::sys::signal::Signal) {
        let pid = nix::unistd::Pid::from_raw(self.child.id() as i32);
        nix::sys::signal::kill(pid, signal).unwrap();
    }

    /// Waits for the child to exit and returns its status, or panics after [`WAIT`].
    pub fn wait(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + WAIT;
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let _ = self.child.kill();
        panic!("still running after {WAIT:?}:\n{}", self.stdout());
    }
}

impl Drop for Sidecar {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Reads `stream` on a thread of its own until it ends, so the child never blocks on a pipe
/// nobody is emptying.
fn drain(stream: impl Read + Send + 'static) -> Output {
    let output = Output::default();
    let sink = output.clone();
    std::thread::spawn(move || {
        for line in BufReader::new(stream).lines().map_while(Result::ok) {
            let mut held = sink.0.lock().unwrap();
            held.push_str(&line);
            held.push('\n');
        }
    });
    output
}

/// The value of a JSON string field in one log line. The fixtures log JSON, so this is enough
/// to read an address back without a JSON parser in every test.
pub fn field(line: &str, name: &str) -> String {
    let key = format!("\"{name}\":\"");
    let (_, rest) = line.split_once(&key).unwrap_or_else(|| {
        panic!("no {name} field in {line}");
    });
    rest.split_once('"').unwrap().0.to_owned()
}

/// A `GET /metrics` against `addr`, as the local scraper would.
pub fn scrape(addr: SocketAddr) -> String {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    write!(stream, "GET /metrics HTTP/1.0\r\n\r\n").unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    answer
}
