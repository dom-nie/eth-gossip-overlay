//! The local admin socket and the types `fleet-overlayctl` speaks to it with (§11, D31).

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
    use crate::reload::{Deps, ReloadHandle, Reloader};
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
        config_path: PathBuf,
        roster_path: PathBuf,
        inject: Arc<AtomicBool>,
        bn_connected: Arc<AtomicBool>,
        bn: watch::Sender<BnInfo>,
        subscriptions: watch::Sender<SubscriptionSets>,
        reload: ReloadHandle,
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
            let (roster_tx, roster_rx) = watch::channel(Roster::from_yaml(&roster_yaml(3)).unwrap());
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
                reload: reload.clone(),
            };
            let server = serve(&socket, state).unwrap();
            Self {
                _dir: dir,
                socket,
                config_path,
                roster_path,
                inject,
                bn_connected,
                bn,
                subscriptions,
                reload,
                _reload_task: reload_task,
                _server: server,
            }
        }

        /// One request over a connection of its own, as `fleet-overlayctl` makes it.
        async fn send(&self, request: &Request) -> Response {
            let line = self.send_line(&serde_json::to_string(request).unwrap()).await;
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
}
