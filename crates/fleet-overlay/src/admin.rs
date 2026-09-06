//! The local admin socket and the types `fleet-overlayctl` speaks to it with (§11, D31).
//!
//! One JSON object per line each way, so the far end is a `nc` and a `jq` when it has to be.
//! [`Request`] and [`Response`] are the whole protocol and both binaries share them: the daemon
//! is the only writer of a response and the CLI the only reader, and one definition is what
//! keeps them from drifting.
//!
//! Access control is the socket's file mode and nothing else (§11): mode 0660 under a directory
//! systemd's `RuntimeDirectory=` owns, so the service user and its group can use it and nobody
//! else can. There is no remote access and no authentication to add.

use std::io;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use overlay_bn::compat::BnInfo;
use overlay_core::roster::{Roster, SelfIdentity};
use overlay_core::topic::SubscriptionSets;
use overlay_transport::manager::LiveSource;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::debug;

use crate::reload::ReloadHandle;

/// The longest line the socket reads. A request is a few dozen bytes and the bound is only
/// against a client that never sends a newline, so it is generous rather than tight.
pub const MAX_LINE_BYTES: usize = 64 * 1024;

/// The socket's file mode: the service user and its group, nobody else (§11).
const SOCKET_MODE: u32 = 0o660;

/// One line from `fleet-overlayctl`.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Flip the inject kill switch, or ask what it is with no `value` (§5.7).
    Inject {
        /// The value to set; absent asks without changing anything.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        value: Option<bool>,
    },
}

/// One line back. `ok` says whether the sidecar ran the command, and at most one of the payload
/// fields is set, so `jq .inject` reads an answer without knowing which command produced it.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Response {
    /// Whether the sidecar ran the command at all.
    pub ok: bool,
    /// Why it did not, when `ok` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The kill switch as it stands, after an `inject` command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inject: Option<bool>,
}

impl Response {
    /// The sidecar could not run the command.
    fn failed(reason: impl std::fmt::Display) -> Self {
        Self {
            error: Some(reason.to_string()),
            ..Self::default()
        }
    }

    /// The kill switch as it stands now.
    fn inject(value: bool) -> Self {
        Self {
            ok: true,
            inject: Some(value),
            ..Self::default()
        }
    }
}

/// What the socket answers from. Every field is a handle to something the running sidecar owns,
/// so an answer is a read of the live values and never a copy the socket keeps in step itself.
#[derive(Clone)]
pub struct State {
    /// Who this host is, for the head of a `status` answer.
    pub self_id: SelfIdentity,
    /// The kill switch T-017's publisher reads per message.
    pub inject: Arc<AtomicBool>,
    /// The live set, read afresh on every `status`.
    pub live: LiveSource,
    /// The beacon node link's own connected flag (T-013).
    pub bn_connected: Arc<AtomicBool>,
    /// What the compatibility watch last heard from the beacon node (T-018, D09).
    pub bn: watch::Receiver<BnInfo>,
    /// The beacon node's subscriptions, as the mirror keeps them (T-014).
    pub subscriptions: watch::Receiver<SubscriptionSets>,
    /// The roster in force, as a reload leaves it (T-043).
    pub roster: watch::Receiver<Roster>,
    /// How a `roster reload` runs the same reload SIGHUP does (D26).
    pub reload: ReloadHandle,
}

/// Serves the admin protocol on `path`, one task per connection.
///
/// The socket is bound before this returns, so a caller that reports the sidecar ready is
/// telling the truth: `fleet-overlayctl` works from the moment T-045 signals readiness. A
/// socket file left behind by a killed process is removed first, because the path is the
/// sidecar's own and a stale one refuses every bind.
pub fn serve(path: &Path, state: State) -> io::Result<JoinHandle<()>> {
    match std::fs::remove_file(path) {
        Ok(()) => tracing::info!(path = %path.display(), "removed a stale admin socket"),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    let listener = UnixListener::bind(path)?;
    set_mode(path)?;

    let state = Arc::new(state);
    Ok(tokio::spawn(async move {
        loop {
            // A failed accept is that connection's alone; the listener is still good, so the
            // next `fleet-overlayctl` is unaffected.
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let state = Arc::clone(&state);
            tokio::spawn(async move {
                if let Err(err) = session(stream, &state).await {
                    debug!(%err, "admin connection ended early");
                }
            });
        }
    }))
}

#[cfg(unix)]
fn set_mode(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE))
}

/// One connection: a request per line until the client goes away, or until a line this cannot
/// read. A malformed line leaves the reader out of step with whoever wrote it, so the error
/// response is the last thing the connection carries and the client reconnects.
async fn session(stream: UnixStream, state: &State) -> io::Result<()> {
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    loop {
        let mut line = Vec::new();
        let read = (&mut reader)
            .take(MAX_LINE_BYTES as u64)
            .read_until(b'\n', &mut line)
            .await?;
        if read == 0 {
            return Ok(());
        }
        if !line.ends_with(b"\n") {
            let too_long = Response::failed(format!("line longer than {MAX_LINE_BYTES} bytes"));
            return reply(&mut write, &too_long).await;
        }
        let request = match serde_json::from_slice::<Request>(&line) {
            Ok(request) => request,
            Err(err) => return reply(&mut write, &Response::failed(err)).await,
        };
        reply(&mut write, &answer(request, state).await).await?;
    }
}

async fn reply(write: &mut (impl AsyncWriteExt + Unpin), response: &Response) -> io::Result<()> {
    // Serializing a response cannot fail: every field is a string, a bool or a number.
    let mut line = serde_json::to_vec(response).unwrap_or_default();
    line.push(b'\n');
    write.write_all(&line).await
}

async fn answer(request: Request, state: &State) -> Response {
    match request {
        Request::Inject { value } => {
            if let Some(value) = value {
                state.inject.store(value, Ordering::Relaxed);
            }
            Response::inject(state.inject.load(Ordering::Relaxed))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use overlay_core::config::Log;
    use overlay_core::identity::FleetSeed;
    use overlay_core::roster::{Hostname, Region, Roster, SelfIdentity};
    use overlay_core::topic::SubscriptionSets;
    use overlay_transport::manager::{LiveSource, LiveView};
    use tempfile::TempDir;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;
    use tokio::sync::watch;
    use tokio::task::JoinHandle;

    use super::*;
    use crate::logging::testing;
    use crate::reload::{Deps, Reloader};
    use overlay_bn::compat::BnInfo;

    /// Every await in this file is bounded: a socket that never answers has to fail the test
    /// rather than hang the suite.
    const PATIENCE: Duration = Duration::from_secs(5);

    /// A config document with the roster path filled in by [`Fixture::start`].
    const CONFIG: &str = "overlay:\n  roster_file: ROSTER\ninject: true\n";

    /// `n` hosts named `bn-1` upwards, all in one region.
    fn roster_yaml(n: usize) -> String {
        let mut text = "hosts:\n".to_owned();
        for i in 1..=n {
            text.push_str(&format!(
                "  - hostname: bn-{i}\n    region: eu\n    addr: \"127.0.0.{i}:7788\"\n"
            ));
        }
        text
    }

    /// A served socket under a temp directory, holding the sending end of everything the
    /// status answer reads so a test can decide what the sidecar looks like.
    struct Fixture {
        _dir: TempDir,
        socket: PathBuf,
        inject: Arc<AtomicBool>,
        _reload_task: JoinHandle<()>,
        _server: JoinHandle<()>,
    }

    impl Fixture {
        async fn start(live: LiveView) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("admin.sock");
            let config_path = dir.path().join("config.yaml");
            let roster_path = dir.path().join("roster.yaml");
            std::fs::write(&roster_path, roster_yaml(3)).unwrap();
            std::fs::write(
                &config_path,
                CONFIG.replace("ROSTER", &roster_path.display().to_string()),
            )
            .unwrap();

            let inject = Arc::new(AtomicBool::new(true));
            let (roster_tx, roster_rx) =
                watch::channel(Roster::from_yaml(&roster_yaml(3)).unwrap());
            let (seed_tx, _seed_rx) = watch::channel::<Option<FleetSeed>>(None);
            let (limits_tx, _limits_rx) = watch::channel(Default::default());
            let (_sink, _dispatch, log) = testing::subscriber(&Log::default(), false, None);
            let reloader = Reloader::new(
                config_path.clone(),
                Deps {
                    inject: inject.clone(),
                    roster: roster_tx,
                    previous_seed: seed_tx,
                    limits: limits_tx,
                    log: Arc::new(log),
                    stats: Arc::new(()),
                },
            )
            .unwrap();
            let (reload, reload_task) = crate::reload::spawn(reloader);
            let (_bn, bn_rx) = watch::channel(BnInfo::default());
            let (_subscriptions, subscriptions_rx) = watch::channel(SubscriptionSets::default());
            let state = State {
                self_id: SelfIdentity {
                    hostname: Hostname("bn-1".to_owned()),
                    region: Region("eu".to_owned()),
                    site: Some("ams1".to_owned()),
                },
                inject: inject.clone(),
                live: LiveSource::fixed(live),
                bn_connected: Arc::new(AtomicBool::new(true)),
                bn: bn_rx,
                subscriptions: subscriptions_rx,
                roster: roster_rx,
                reload,
            };
            let server = serve(&socket, state).unwrap();
            Self {
                _dir: dir,
                socket,
                inject,
                _reload_task: reload_task,
                _server: server,
            }
        }

        /// One request over a connection of its own, as `fleet-overlayctl` makes it.
        async fn send(&self, request: &Request) -> Response {
            let line = self
                .send_line(&serde_json::to_string(request).unwrap())
                .await;
            serde_json::from_str(&line).unwrap_or_else(|err| panic!("{line:?}: {err}"))
        }

        /// The raw answer to a raw line, for the requests a well-formed [`Request`] cannot be.
        async fn send_line(&self, line: &str) -> String {
            let stream = tokio::time::timeout(PATIENCE, UnixStream::connect(&self.socket))
                .await
                .expect("the admin socket answers")
                .unwrap();
            let (read, mut write) = stream.into_split();
            tokio::time::timeout(PATIENCE, write.write_all(format!("{line}\n").as_bytes()))
                .await
                .unwrap()
                .unwrap();
            let mut answer = String::new();
            tokio::time::timeout(PATIENCE, BufReader::new(read).read_line(&mut answer))
                .await
                .expect("an answer within the timeout")
                .unwrap();
            answer
        }
    }

    #[tokio::test]
    async fn inject_off_request_flips_shared_flag_and_replies_ok() {
        let h = Fixture::start(LiveView::default()).await;

        let response = h.send(&Request::Inject { value: Some(false) }).await;

        assert!(response.ok, "{response:?}");
        assert_eq!(response.inject, Some(false));
        assert!(!h.inject.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn inject_query_reports_current_value() {
        let h = Fixture::start(LiveView::default()).await;

        let first = h.send(&Request::Inject { value: None }).await;
        h.send(&Request::Inject { value: Some(false) }).await;
        let second = h.send(&Request::Inject { value: None }).await;

        assert_eq!(first.inject, Some(true));
        assert!(first.ok, "{first:?}");
        assert_eq!(second.inject, Some(false));
        // A query says what the flag is and never sets it: the first one left it alone.
        assert!(!h.inject.load(Ordering::Relaxed));
    }
}
