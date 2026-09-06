//! Re-reading `config.yaml` and `roster.yaml` under a running sidecar (§5.3, §5.7, D26).
//!
//! One [`Reloader`] owns the current configuration and roster and applies what may change at
//! runtime; everything else reaches it through a [`ReloadHandle`], so SIGHUP, `fleet-overlayctl
//! roster reload` (T-042) and the roster file watcher (T-086) all run the same code.

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use overlay_core::config::{Log, PublishRateLimit};
    use overlay_core::identity::FleetSeed;
    use overlay_core::roster::Roster;
    use tempfile::TempDir;
    use tokio::sync::watch;

    use super::*;
    use crate::logging::testing;

    /// A config document with the roster path filled in by [`Fixture::write_config`].
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

    /// A reloader over files in a temp directory, holding the receiving end of every channel
    /// an applier writes to.
    struct Fixture {
        _dir: TempDir,
        config_path: PathBuf,
        roster_path: PathBuf,
        inject: Arc<AtomicBool>,
        roster: watch::Receiver<Roster>,
        previous_seed: watch::Receiver<Option<FleetSeed>>,
        limits: watch::Receiver<PublishRateLimit>,
        reloader: Reloader,
    }

    impl Fixture {
        fn new(config: &str, roster: &str) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let config_path = dir.path().join("config.yaml");
            let roster_path = dir.path().join("roster.yaml");
            fs::write(&roster_path, roster).unwrap();
            fs::write(
                &config_path,
                config.replace("ROSTER", &roster_path.display().to_string()),
            )
            .unwrap();
            let inject = Arc::new(AtomicBool::new(true));
            let (roster_tx, roster_rx) = watch::channel(Roster::from_yaml(roster).unwrap());
            let (seed_tx, previous_seed) = watch::channel(None);
            let (limits_tx, limits) = watch::channel(PublishRateLimit::default());
            let (_, _, log) = testing::subscriber(&Log::default(), false, None);
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
            Self {
                _dir: dir,
                config_path,
                roster_path,
                inject,
                roster: roster_rx,
                previous_seed,
                limits,
                reloader,
            }
        }

        fn write_config(&self, text: &str) {
            fs::write(
                &self.config_path,
                text.replace("ROSTER", &self.roster_path.display().to_string()),
            )
            .unwrap();
        }
    }

    #[test]
    fn manual_reload_applies_new_inject_value() {
        let mut h = Fixture::new(CONFIG, &roster_yaml(3));
        h.write_config("overlay:\n  roster_file: ROSTER\ninject: false\n");

        let report = h.reloader.reload(Trigger::Manual);

        assert_eq!(report.applied, ["inject"]);
        assert!(report.restart_required.is_empty(), "{report:?}");
        assert!(report.error.is_none(), "{report:?}");
        assert!(!h.inject.load(Ordering::Relaxed));
        assert!(!h.reloader.config().inject);
    }
}
