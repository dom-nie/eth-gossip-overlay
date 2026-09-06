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
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use overlay_bn::compat::BnInfo;
use overlay_core::roster::{Roster, SelfIdentity};
use overlay_core::topic::{Class, SubscriptionSets};
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
    /// Everything an operator looks at during a rollout (D29).
    Status,
    /// The roster in force, as the sidecar reads it.
    Roster,
}

/// What `status` answers: this host, then one entry per live peer in hostname order.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Status {
    /// This host's name, which is its identity everywhere (Appendix A).
    pub hostname: String,
    /// The region this host fans out in.
    pub region: String,
    /// This host's site label, `null` when it has none.
    pub site: Option<String>,
    /// The kill switch: false means the sidecar observes and reports but publishes nothing.
    pub inject: bool,
    /// The beacon node this sidecar is attached to.
    pub bn: Bn,
    /// Every peer with a live connection.
    pub peers: Vec<Peer>,
}

/// The local beacon node, as the link and the compatibility watch last left it (D09).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Bn {
    /// Whether the gossipsub link is up.
    pub connected: bool,
    /// The beacon node's version string, `null` until it has answered the probe. T-018 checks
    /// it against the supported range, and a rollout is read off it.
    pub version: Option<String>,
    /// Whether the beacon node lists the sidecar as a trusted peer: `null` while it has not
    /// said, which is a different answer from `false` and alerted on separately.
    pub trusted: Option<bool>,
    /// How many topics the beacon node is subscribed to, which is the size of the advertised
    /// set the mirror follows.
    pub subscriptions: usize,
}

/// One live peer. `software_version` and `features` are what a rollout is read off: they show
/// which hosts are upgraded and which pairs are running the fallback (D29).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Peer {
    /// The peer's hostname.
    pub hostname: String,
    /// The region the peer declared, which is where its second hop fans out (D15).
    pub region: String,
    /// The peer's site label, `null` when it has none.
    pub site: Option<String>,
    /// The connection's round-trip estimate when the answer was built.
    pub rtt_ms: f64,
    /// How long the connection has been up. An age and not a timestamp: hosts' clocks differ
    /// and "up for four minutes" is what an operator reads.
    pub connected_for_ms: u64,
    /// What this host still has queued for the peer, the same numbers `peer_queue_depth`
    /// carries (T-033).
    pub queue: Queue,
    /// The release the peer is running.
    pub software_version: String,
    /// The feature bits the pair negotiated, as a bitset; `fleet-overlayctl` renders the names.
    pub features: u64,
}

/// One roster entry, as `roster.yaml` gives it (Appendix A). The dump is the roster in force,
/// which after a refused reload is not what the file on disk says.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Host {
    /// The host's name, its identity everywhere.
    pub hostname: String,
    /// The region it fans out in.
    pub region: String,
    /// Its site label, `null` when it has none.
    pub site: Option<String>,
    /// The address this host dials it on.
    pub addr: SocketAddr,
}

/// A peer's two send lanes, in both units each is bounded by (§5.7).
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
pub struct Queue {
    /// Frames waiting in the small lane.
    pub small_frames: usize,
    /// Bytes waiting in the small lane.
    pub small_bytes: usize,
    /// Frames waiting in the large lane.
    pub large_frames: usize,
    /// Bytes waiting in the large lane.
    pub large_bytes: usize,
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
    /// What `status` found.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Status>,
    /// The roster in force, from `roster`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roster: Option<Vec<Host>>,
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

    /// What the sidecar looks like right now.
    fn status(status: Status) -> Self {
        Self {
            ok: true,
            status: Some(status),
            ..Self::default()
        }
    }

    /// The roster in force.
    fn roster(hosts: Vec<Host>) -> Self {
        Self {
            ok: true,
            roster: Some(hosts),
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
        Request::Status => Response::status(status(state)),
        Request::Roster => Response::roster(
            state
                .roster
                .borrow()
                .hosts
                .iter()
                .map(|host| Host {
                    hostname: host.hostname.0.clone(),
                    region: host.region.0.clone(),
                    site: host.site.clone(),
                    addr: host.addr,
                })
                .collect(),
        ),
    }
}

/// The beacon node section, read from the three owners of its parts: the link's own connected
/// flag, the compatibility watch and the subscription mirror. Nothing is derived a second time
/// here, so `status` and the gauges cannot tell an operator different things.
fn bn(state: &State) -> Bn {
    let info = state.bn.borrow();
    Bn {
        connected: state.bn_connected.load(Ordering::Relaxed),
        version: info.version.clone(),
        trusted: info.trusted,
        subscriptions: state.subscriptions.borrow().advertised.len(),
    }
}

/// Reads the live values once, so every line of one answer describes the same moment.
fn status(state: &State) -> Status {
    let live = state.live.live();
    Status {
        hostname: state.self_id.hostname.0.clone(),
        region: state.self_id.region.0.clone(),
        site: state.self_id.site.clone(),
        inject: state.inject.load(Ordering::Relaxed),
        bn: bn(state),
        peers: live
            .iter()
            .map(|(hostname, peer)| {
                let (small, large) = (
                    peer.sender.depth(Class::Small),
                    peer.sender.depth(Class::Large),
                );
                Peer {
                    hostname: hostname.0.clone(),
                    region: peer.region.0.clone(),
                    site: peer.site.clone(),
                    rtt_ms: peer.rtt.as_secs_f64() * 1000.0,
                    connected_for_ms: u64::try_from(peer.connected_since.elapsed().as_millis())
                        .unwrap_or(u64::MAX),
                    queue: Queue {
                        small_frames: small.frames,
                        small_bytes: small.bytes,
                        large_frames: large.frames,
                        large_bytes: large.bytes,
                    },
                    software_version: peer.software_version.clone(),
                    features: peer.negotiated.features,
                }
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use overlay_core::config::Log;
    use overlay_core::identity::FleetSeed;
    use overlay_core::roster::{Hostname, Region, Roster, SelfIdentity};
    use overlay_core::topic::{Class, SubscriptionSets, Topic};
    use overlay_transport::hello::Negotiated;
    use overlay_transport::manager::{LivePeer, LiveSource, LiveView};
    use overlay_transport::sender::{
        self, LARGE_QUEUED_BYTES_MAX, LargeLedger, PeerSender, SenderHandle,
    };
    use overlay_transport::testutil::{
        Builder, NodeKind, SendSpy, eventually, peer_state, view_of,
    };
    use tempfile::TempDir;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;
    use tokio::sync::watch;
    use tokio::task::JoinHandle;

    use super::*;
    use crate::logging::testing;
    use crate::reload::{Deps, Reloader};
    use overlay_bn::compat::{self, BnInfo};

    /// Every await in this file is bounded: a socket that never answers has to fail the test
    /// rather than hang the suite.
    const PATIENCE: Duration = Duration::from_secs(5);

    /// A config document with the roster path filled in by [`Fixture::start`].
    const CONFIG: &str = "overlay:\n  roster_file: ROSTER\ninject: true\n";

    /// A topic on one fork digest, for the subscription count.
    fn topic(name: &str) -> Topic {
        Topic::parse(&format!("/eth2/6a95a1a9/{name}/ssz_snappy")).unwrap()
    }

    /// `n` hosts named `bn-1` upwards, all in one region, the first of them with a site so a
    /// dump has both answers to show.
    fn roster_yaml(n: usize) -> String {
        let mut text = "hosts:\n".to_owned();
        for i in 1..=n {
            text.push_str(&format!(
                "  - hostname: bn-{i}\n    region: eu\n    addr: \"127.0.0.{i}:7788\"\n"
            ));
            if i == 1 {
                text.push_str("    site: ams1\n");
            }
        }
        text
    }

    /// A served socket under a temp directory, holding the sending end of everything the
    /// status answer reads so a test can decide what the sidecar looks like.
    struct Fixture {
        _dir: TempDir,
        socket: PathBuf,
        inject: Arc<AtomicBool>,
        bn_connected: Arc<AtomicBool>,
        bn: watch::Sender<BnInfo>,
        subscriptions: watch::Sender<SubscriptionSets>,
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
            let bn_connected = Arc::new(AtomicBool::new(true));
            let (bn, bn_rx) = watch::channel(BnInfo::default());
            let (subscriptions, subscriptions_rx) = watch::channel(SubscriptionSets::default());
            let state = State {
                self_id: SelfIdentity {
                    hostname: Hostname("bn-1".to_owned()),
                    region: Region("eu".to_owned()),
                    site: Some("ams1".to_owned()),
                },
                inject: inject.clone(),
                live: LiveSource::fixed(live),
                bn_connected: bn_connected.clone(),
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
                bn_connected,
                bn,
                subscriptions,
                _reload_task: reload_task,
                _server: server,
            }
        }

        /// The `bn` section of a fresh `status` answer.
        async fn bn_section(&self) -> Bn {
            self.send(&Request::Status)
                .await
                .status
                .expect("a status")
                .bn
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

    /// A live peer built by hand, because the fields `status` reports are exactly the ones a
    /// routing test leaves at their defaults. Two peers that differ in every reported field, so
    /// a value taken from the wrong peer or dropped on the way out shows up.
    #[tokio::test(flavor = "multi_thread")]
    async fn status_lists_live_peers_with_region_site_rtt_software_version_and_features() {
        let cluster = Builder::new(&[NodeKind::Bare, NodeKind::Bare])
            .start()
            .await;
        let (connection, _accepted) = cluster.connected_pair(0, 1).await;
        let link = SendSpy::stalled();
        let queued = PeerSender::spawn(
            Hostname("bn-2".to_owned()),
            link.clone(),
            sender::Deps {
                ledger: Arc::new(LargeLedger::new(LARGE_QUEUED_BYTES_MAX)),
                stats: Arc::new(()),
            },
        );
        let now = Instant::now();
        queued
            .push(Class::Large, Bytes::from(vec![0; 4096]), now)
            .unwrap();
        queued
            .push(Class::Large, Bytes::from(vec![0; 2048]), now)
            .unwrap();
        queued
            .push(Class::Small, Bytes::from(vec![0; 300]), now)
            .unwrap();
        // The drain task takes the first large frame and stalls writing it, so what the lanes
        // hold from here on is what the status answer has to report.
        eventually("the sender to stall on its first frame", || {
            queued.depth(Class::Large).frames == 1
        })
        .await;

        let live = |hostname: &str,
                    region: &str,
                    site: Option<&str>,
                    software_version: &str,
                    features: u64,
                    sender: SenderHandle,
                    connected_since: Instant| {
            (
                Hostname(hostname.to_owned()),
                LivePeer {
                    region: Region(region.to_owned()),
                    site: site.map(str::to_owned),
                    rtt: Duration::from_millis(7),
                    connected_since,
                    instance_id: 1,
                    software_version: software_version.to_owned(),
                    negotiated: Negotiated {
                        minor: 0,
                        features,
                        peer_max_frame_bytes: 1024,
                        peer_max_batch_entries: 16,
                    },
                    connection: connection.clone(),
                    sender,
                    state: Arc::new(Mutex::new(peer_state(&[], &[]))),
                },
            )
        };
        let view = view_of(vec![
            live(
                "bn-2",
                "eu",
                Some("ams1"),
                "0.2.0",
                3,
                queued.clone(),
                now - Duration::from_secs(4),
            ),
            live(
                "bn-3",
                "us",
                None,
                "0.1.0",
                0,
                SenderHandle::stopped(Hostname("bn-3".to_owned())),
                now,
            ),
        ]);
        let h = Fixture::start(view).await;

        let status = h.send(&Request::Status).await.status.expect("a status");

        assert_eq!(status.hostname, "bn-1");
        assert_eq!(status.region, "eu");
        assert_eq!(status.site.as_deref(), Some("ams1"));
        assert!(status.inject);
        let names: Vec<&str> = status.peers.iter().map(|p| p.hostname.as_str()).collect();
        assert_eq!(names, ["bn-2", "bn-3"]);
        let first = &status.peers[0];
        assert_eq!(first.region, "eu");
        assert_eq!(first.site.as_deref(), Some("ams1"));
        assert_eq!(first.rtt_ms, 7.0);
        assert_eq!(first.software_version, "0.2.0");
        assert_eq!(first.features, 3);
        assert_eq!(
            (first.queue.large_frames, first.queue.large_bytes),
            (1, 2048)
        );
        assert_eq!(
            (first.queue.small_frames, first.queue.small_bytes),
            (1, 300)
        );
        assert!(
            (4000..6000).contains(&first.connected_for_ms),
            "{:?}",
            first.connected_for_ms
        );
        let second = &status.peers[1];
        assert_eq!(second.region, "us");
        assert_eq!(second.site, None);
        assert_eq!(second.features, 0);
        assert_eq!(
            (second.queue.large_frames, second.queue.small_frames),
            (0, 0)
        );
        assert!(
            second.connected_for_ms < 1000,
            "{:?}",
            second.connected_for_ms
        );
    }

    /// `trusted` has three answers and an operator has to be able to tell them apart: the
    /// beacon node says yes, says no, or has not said, which is `null` on the wire and what the
    /// `OverlayNotTrustedByBn` alert waits out (D09).
    #[tokio::test]
    async fn status_reports_bn_version_and_trust() {
        let h = Fixture::start(LiveView::default()).await;
        let version = "Lighthouse/v8.2.2-e423a66/x86_64-linux";
        h.subscriptions.send_replace(SubscriptionSets {
            advertised: [topic("beacon_block"), topic("beacon_aggregate_and_proof")]
                .into_iter()
                .collect(),
            local: [topic("beacon_block")].into_iter().collect(),
        });

        let unknown = h.bn_section().await;
        let raw = h.send_line(r#"{"cmd":"status"}"#).await;
        h.bn.send_replace(BnInfo {
            version: Some(version.to_owned()),
            trusted: Some(true),
            state: Some(compat::STATE_SUPPORTED),
        });
        let trusted = h.bn_section().await;
        h.bn.send_modify(|info| info.trusted = Some(false));
        let untrusted = h.bn_section().await;
        h.bn_connected.store(false, Ordering::Relaxed);
        let gone = h.bn_section().await;

        assert_eq!((unknown.version, unknown.trusted), (None, None));
        assert!(raw.contains(r#""trusted":null"#), "{raw}");
        assert_eq!(trusted.version.as_deref(), Some(version));
        assert_eq!(trusted.trusted, Some(true));
        assert_eq!(untrusted.trusted, Some(false));
        // The advertised set is what the beacon node itself is subscribed to (§12).
        assert_eq!(trusted.subscriptions, 2);
        assert!(trusted.connected);
        assert!(!gone.connected);
    }

    #[tokio::test]
    async fn roster_dump_matches_loaded_roster() {
        let h = Fixture::start(LiveView::default()).await;

        let dumped = h.send(&Request::Roster).await.roster.expect("a roster");

        let loaded = Roster::from_yaml(&roster_yaml(3)).unwrap();
        assert_eq!(dumped.len(), 3);
        for (dumped, host) in dumped.iter().zip(&loaded.hosts) {
            assert_eq!(dumped.hostname, host.hostname.0);
            assert_eq!(dumped.region, host.region.0);
            assert_eq!(dumped.site, host.site);
            assert_eq!(dumped.addr, host.addr);
        }
        assert_eq!(dumped[0].site.as_deref(), Some("ams1"));
        assert_eq!(dumped[1].site, None);
    }
}
