//! What the process owes the init system and what it owes itself: the notification socket, the
//! watchdog, the env file a beacon node reads at its own start, and the panic hook that turns a
//! wedged task into a restart (OPS-N1, OPS-N5, MD-01).
//!
//! Everything systemd-facing degrades to nothing. Without `NOTIFY_SOCKET` the notifications are
//! no-ops said once at debug and the watchdog never starts, so the same binary runs under
//! `docker run` (T-047) and under `cargo run` on a laptop.

use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sd_notify::NotifyState;
use tokio::signal::unix::{SignalKind, signal};

/// The file a beacon node's drop-in reads with `EnvironmentFile=-` (OPS-N1).
pub const ENV_FILE_NAME: &str = "lighthouse.env";

/// Where the env file goes when systemd has not set `RUNTIME_DIRECTORY`, which is the path the
/// shipped drop-in names.
pub const RUNTIME_DIR_FALLBACK: &str = "/run/fleet-overlay";

/// A beacon node reads the file as a different user, so it has to be world readable. It holds a
/// peer id and a loopback address, neither of which is a secret.
const ENV_FILE_MODE: u32 = 0o644;

/// What a panicking task exits with, which is what a plain Rust panic already exits with.
const EXIT_PANIC: i32 = 101;

/// Counters the four core tasks bump at the top of every loop iteration, named after the tasks
/// (OPS-N5). Each is an `Arc<AtomicU64>` because the loop that owns it lives in a crate that
/// knows nothing about systemd; a `fetch_add` is the whole contract.
#[derive(Clone, Debug, Default)]
pub struct Progress {
    /// T-023's supervisor loop.
    pub connection_manager: Arc<AtomicU64>,
    /// T-013's swarm loop.
    pub bn_link: Arc<AtomicU64>,
    /// T-032's fanout loop.
    pub fanout: Arc<AtomicU64>,
    /// T-017's drain loop.
    pub publisher: Arc<AtomicU64>,
}

impl Progress {
    fn counts(&self) -> [u64; 4] {
        [
            &self.connection_manager,
            &self.bn_link,
            &self.fanout,
            &self.publisher,
        ]
        .map(|counter| counter.load(Ordering::Relaxed))
    }
}

/// Decides whether systemd should be told the process is alive: only when every one of the four
/// core tasks has gone round its loop since the last time it was told.
///
/// A task that stops ticking starves the watchdog and systemd restarts the process, which is
/// the point. Each of the four has a periodic tick arm, so an idle fleet still advances all four
/// and a healthy sidecar with nothing to do is never mistaken for a wedged one.
pub struct Watchdog {
    progress: Progress,
    last: [u64; 4],
}

impl Watchdog {
    /// A watchdog that has not kicked yet, holding the counters as they are now.
    pub fn new(progress: Progress) -> Self {
        let last = progress.counts();
        Self { progress, last }
    }

    /// Whether to send `WATCHDOG=1` now. Reading and remembering the counters is all it does:
    /// which loop is behind is the log's business, not the watchdog's.
    pub fn kick_due(&mut self) -> bool {
        let counts = self.progress.counts();
        let advanced = counts
            .iter()
            .zip(&self.last)
            .all(|(now, before)| now > before);
        if advanced {
            self.last = counts;
        }
        advanced
    }
}

/// The notification socket, or nothing at all.
#[derive(Clone, Debug)]
pub struct Notify {
    enabled: bool,
}

impl Notify {
    /// Reads `NOTIFY_SOCKET` once. Without it every method here is a no-op, said once at debug
    /// rather than on every notification.
    pub fn new() -> Self {
        let enabled = std::env::var_os("NOTIFY_SOCKET").is_some();
        if !enabled {
            tracing::debug!("no NOTIFY_SOCKET: readiness, stopping and the watchdog are no-ops");
        }
        Self { enabled }
    }

    /// `READY=1`, sent once the admin socket answers.
    pub fn ready(&self) {
        self.send(&[NotifyState::Ready]);
    }

    /// `STOPPING=1`, the first thing a shutdown does.
    pub fn stopping(&self) {
        self.send(&[NotifyState::Stopping]);
    }

    /// `WATCHDOG=1`, sent only when [`Watchdog::kick_due`] says so.
    pub fn watchdog(&self) {
        self.send(&[NotifyState::Watchdog]);
    }

    /// How often to kick: a third of `WatchdogSec`, so two missed kicks still leave one in
    /// hand. `None` when systemd is not watching, and then no watchdog task starts.
    pub fn watchdog_interval(&self) -> Option<Duration> {
        let Some(watchdog_sec) = self.enabled.then(sd_notify::watchdog_enabled).flatten() else {
            tracing::debug!("no watchdog: WATCHDOG_USEC is not set for this process");
            return None;
        };
        Some(watchdog_sec / 3)
    }

    fn send(&self, state: &[NotifyState]) {
        if self.enabled
            && let Err(err) = sd_notify::notify(state)
        {
            // The socket is systemd's; a process that cannot reach it can only say so.
            tracing::warn!(%err, ?state, "could not reach NOTIFY_SOCKET");
        }
    }
}

impl Default for Notify {
    fn default() -> Self {
        Self::new()
    }
}

/// The `lighthouse.env` file, written before anything binds so that a beacon node starting
/// beside the sidecar finds `--trusted-peers` and `--libp2p-addresses` already there (OPS-N1,
/// MD-01).
pub struct TrustedPeerEnv;

impl TrustedPeerEnv {
    /// Where the file goes: `$RUNTIME_DIRECTORY` when systemd set one from `RuntimeDirectory=`,
    /// else [`RUNTIME_DIR_FALLBACK`].
    pub fn directory() -> PathBuf {
        std::env::var_os("RUNTIME_DIRECTORY")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(RUNTIME_DIR_FALLBACK))
    }

    /// Writes `line` into `dir` through a temporary file and a rename, so a beacon node reading
    /// the file at the same moment sees either the whole previous content or the whole new one.
    /// The temporary file is removed on any failure, because the directory is one systemd
    /// hands over whole and a leftover would outlive the process.
    pub fn write(dir: &Path, line: &str) -> io::Result<PathBuf> {
        let path = dir.join(ENV_FILE_NAME);
        let temporary = dir.join(format!("{ENV_FILE_NAME}.tmp"));
        let written = std::fs::write(&temporary, format!("{line}\n"))
            .and_then(|()| set_mode(&temporary))
            .and_then(|()| std::fs::rename(&temporary, &path));
        match written {
            Ok(()) => Ok(path),
            Err(err) => {
                let _ = std::fs::remove_file(&temporary);
                Err(err)
            }
        }
    }
}

#[cfg(unix)]
fn set_mode(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(ENV_FILE_MODE))
}

/// Makes a panic anywhere in the process fatal: one line on stderr and a non-zero exit, so
/// systemd restarts a sidecar whose task died instead of leaving it half alive (§9).
///
/// The default hook runs instead while `RUST_BACKTRACE` is set, because the operator who set it
/// asked for the backtrace.
pub fn exit_on_panic() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if std::env::var_os("RUST_BACKTRACE").is_some() {
            default(info);
        } else {
            eprintln!("fleet-overlay: {info}");
        }
        std::process::exit(EXIT_PANIC);
    }));
}

/// Resolves on the first `SIGTERM` or `SIGINT`, which is the shutdown future the app runs
/// until. `systemctl stop` sends the first and a terminal sends the second.
pub fn terminated() -> io::Result<impl Future<Output = ()> + Send> {
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    Ok(async move {
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn progress() -> Progress {
        Progress::default()
    }

    /// OPS-N5: the kick means every core task is alive, so three out of four is a process one
    /// loop away from wedged and systemd should hear nothing.
    #[test]
    fn watchdog_kick_requires_progress_from_every_core_task() {
        let progress = progress();
        let mut watchdog = Watchdog::new(progress.clone());

        for counter in [
            &progress.connection_manager,
            &progress.bn_link,
            &progress.fanout,
        ] {
            counter.fetch_add(1, Ordering::Relaxed);
        }
        assert!(!watchdog.kick_due(), "three of four advanced");

        progress.publisher.fetch_add(1, Ordering::Relaxed);
        assert!(watchdog.kick_due(), "all four advanced");
    }

    /// A kick is about the interval that just passed, so the counters have to advance again
    /// before the next one. Otherwise one round of progress would feed the watchdog forever.
    #[test]
    fn watchdog_does_not_kick_twice_on_one_round_of_progress() {
        let progress = progress();
        let mut watchdog = Watchdog::new(progress.clone());
        for counter in [
            &progress.connection_manager,
            &progress.bn_link,
            &progress.fanout,
            &progress.publisher,
        ] {
            counter.fetch_add(1, Ordering::Relaxed);
        }

        assert!(watchdog.kick_due());
        assert!(!watchdog.kick_due());
    }

    #[test]
    fn trusted_peer_env_writes_the_line_and_leaves_no_temporary_behind() {
        let dir = tempfile::tempdir().unwrap();

        let path =
            TrustedPeerEnv::write(dir.path(), "FLEET_OVERLAY_TRUSTED_PEER_ARGS=--x").unwrap();

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "FLEET_OVERLAY_TRUSTED_PEER_ARGS=--x\n"
        );
        assert!(!dir.path().join("lighthouse.env.tmp").exists());
    }

    /// A container has no `/run/fleet-overlay` and no `RuntimeDirectory=`, so the write fails
    /// and the caller warns. It must not leave anything behind when it does.
    #[test]
    fn trusted_peer_env_reports_a_directory_it_cannot_write() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("not-created-by-systemd");

        assert!(TrustedPeerEnv::write(&missing, "x").is_err());
        assert!(!missing.exists());
    }
}
