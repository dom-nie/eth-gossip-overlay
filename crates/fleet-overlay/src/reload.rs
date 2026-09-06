//! Re-reading `config.yaml` and `roster.yaml` under a running sidecar (§5.3, §5.7, D26).
//!
//! One [`Reloader`] owns the current configuration and roster and applies what may change at
//! runtime; everything else reaches it through a [`ReloadHandle`], so SIGHUP, `fleet-overlayctl
//! roster reload` (T-042) and the roster file watcher (T-086) all run the same code.
//!
//! # What changed is read off the two documents
//!
//! A reload diffs the old and the new `config.yaml` as YAML documents flattened into dotted
//! paths, not as two serialized [`Config`] values. The documents already are the key paths an
//! operator edits, so nothing has to be derived and the report names what they actually
//! changed in the file; a [`Config`] would have to serialize back to the file's spelling
//! first, which the `_ms` keys alone make a second implementation to keep in step. The typed
//! [`Config`] is still parsed and validated first, so a file that does not fit the schema is
//! refused before any path is reported.
//!
//! The one consequence: adding or removing a key whose value equals the default reads as a
//! change, because the documents differ even though the effective configuration does not. That
//! is honest about the file and costs one applier run.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use overlay_core::config::{Config, PublishRateLimit};
use overlay_core::identity::{FleetSeed, read_secret_file};
use overlay_core::roster::Roster;
use serde::Serialize;
use serde_yaml_bw as yaml;
use tokio::sync::watch;

use crate::logging::LogHandle;

/// What asked for a reload (D26). A human means what the files say; a tool that writes them
/// may be broken, which is what the roster shrink guard protects against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Trigger {
    /// SIGHUP or `fleet-overlayctl roster reload`.
    Manual,
    /// The roster file watcher (T-086).
    Automatic,
}

/// What one reload did, returned to whoever asked for it and serialized verbatim by T-042's
/// admin socket.
#[derive(Debug, Serialize)]
pub struct ReloadReport {
    /// What asked for this reload.
    pub trigger: Trigger,
    /// The keys that took effect, and `roster` when the roster itself changed.
    pub applied: Vec<String>,
    /// Keys that changed in the file but only take effect on a restart.
    pub restart_required: Vec<String>,
    /// Why the reload did not finish, if it did not. The previous values stay in force.
    pub error: Option<ReloadError>,
}

/// Why a reload kept the previous values.
#[derive(Debug, PartialEq, Eq, Serialize, thiserror::Error)]
pub enum ReloadError {
    /// `config.yaml` could not be read, does not parse, or holds a value the sidecar cannot
    /// run with. Also how an applier reports a file it could not read.
    #[error("config: {0}")]
    Config(String),
    /// `roster.yaml` could not be read or does not parse.
    #[error("roster: {0}")]
    Roster(String),
    /// An automatic reload would have removed more than half of the hosts, which is likelier
    /// to be a broken discovery tool than a halved fleet.
    #[error("roster shrinks from {before} to {after} hosts, more than half: rejected")]
    RosterShrinkRejected {
        /// Hosts in the roster in force.
        before: usize,
        /// Hosts the refused file would have left.
        after: usize,
    },
}

/// Where reloads count. T-041 binds this to `config_reload_total{outcome}` and
/// `roster_reload_rejected_total`; `()` counts nothing.
pub trait ReloadStats: Send + Sync {
    /// A reload finished. The report says whether it ended in an error and which one, which is
    /// all the two counters need.
    fn reloaded(&self, report: &ReloadReport);
}

impl ReloadStats for () {
    fn reloaded(&self, _: &ReloadReport) {}
}

/// Everything a reload writes into, from the parts of the sidecar that own the running values.
pub struct Deps {
    /// The kill switch every publish is checked against (T-017).
    pub inject: Arc<AtomicBool>,
    /// The roster the connection manager (T-023) and the pin table (T-021) follow.
    pub roster: watch::Sender<Roster>,
    /// The outgoing seed while a rotation is in progress (DX-N2).
    pub previous_seed: watch::Sender<Option<FleetSeed>>,
    /// The ceilings the publisher rebuilds its token buckets from (DX-N3).
    pub limits: watch::Sender<PublishRateLimit>,
    /// The running subscriber, whose level and format are reloadable (D32).
    pub log: Arc<LogHandle>,
    /// Where the two reload counters live.
    pub stats: Arc<dyn ReloadStats>,
}

/// One reloadable key's consumer: it takes the new configuration and puts the key where the
/// running sidecar reads it, or says why it could not.
type Applier = Box<dyn FnMut(&Config) -> Result<(), String> + Send>;

/// The current configuration and roster, and the appliers that carry a change into the running
/// sidecar. Owned by one task; [`ReloadHandle`] is how everything else reaches it.
pub struct Reloader {
    config_path: PathBuf,
    /// Fixed at construction: `overlay.roster_file` takes a restart, so the file a reload reads
    /// is the one the sidecar started from whatever a new document says.
    roster_path: PathBuf,
    document: yaml::Value,
    config: Config,
    roster: watch::Sender<Roster>,
    appliers: Vec<(&'static str, Applier)>,
    stats: Arc<dyn ReloadStats>,
}

impl Reloader {
    /// Reads `config_path` for the document the first reload is diffed against, and registers
    /// an applier for every reloadable key this release consumes.
    ///
    /// The file is read here rather than taken as a parsed [`Config`] because the diff needs
    /// the document as written, and re-reading it is how the two can never disagree.
    pub fn new(config_path: PathBuf, deps: Deps) -> Result<Self, ReloadError> {
        let (document, config) = read_config(&config_path)?;
        let inject = deps.inject;
        let previous_seed = deps.previous_seed;
        let appliers: Vec<(&'static str, Applier)> = vec![
            (
                "inject",
                Box::new(move |cfg: &Config| {
                    inject.store(cfg.inject, Ordering::Relaxed);
                    Ok(())
                }),
            ),
            (
                "overlay.fleet_seed_previous_file",
                Box::new(move |cfg: &Config| {
                    let seed = match &cfg.overlay.fleet_seed_previous_file {
                        Some(path) => Some(FleetSeed::from(
                            *read_secret_file(path).map_err(|err| err.to_string())?,
                        )),
                        None => None,
                    };
                    previous_seed.send_replace(seed);
                    Ok(())
                }),
            ),
        ];
        Ok(Self {
            config_path,
            roster_path: config.overlay.roster_file.clone(),
            document,
            config,
            roster: deps.roster,
            appliers,
            stats: deps.stats,
        })
    }

    /// The configuration in force: the file as last read, minus the keys that only take effect
    /// on a restart.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Re-reads both files and applies what may change at runtime, keeping the previous values
    /// for anything it cannot.
    pub fn reload(&mut self, trigger: Trigger) -> ReloadReport {
        let mut report = ReloadReport {
            trigger,
            applied: Vec::new(),
            restart_required: Vec::new(),
            error: None,
        };
        match read_config(&self.config_path) {
            Ok((document, config)) => {
                self.apply_config(document, config, &mut report);
                self.apply_roster(&mut report);
            }
            // A config the sidecar cannot run with stops the reload before the roster is read:
            // one broken file, one error, and the next reload applies both.
            Err(error) => report.error = Some(error),
        }
        self.stats.reloaded(&report);
        match &report.error {
            None => tracing::info!(
                trigger = ?report.trigger,
                applied = ?report.applied,
                restart_required = ?report.restart_required,
                "reloaded"
            ),
            Some(error) => tracing::warn!(
                %error,
                trigger = ?report.trigger,
                applied = ?report.applied,
                restart_required = ?report.restart_required,
                "reloaded with an error, previous values kept"
            ),
        }
        report
    }

    /// Runs the applier of every changed key that has one, and records the rest.
    fn apply_config(&mut self, document: yaml::Value, config: Config, report: &mut ReloadReport) {
        let mut applied = Vec::new();
        for path in changed_paths(&self.document, &document) {
            match self.appliers.iter_mut().find(|(key, _)| covers(key, &path)) {
                Some((_, apply)) => match apply(&config) {
                    Ok(()) => applied.push(path),
                    Err(reason) => report.error = Some(ReloadError::Config(reason)),
                },
                None => report.restart_required.push(path),
            }
        }
        // Only what took effect is copied onto the configuration in force: a key that needs a
        // restart, or whose applier refused it, must keep answering with the value the running
        // process is using.
        let mut effective = self.document.clone();
        for path in &applied {
            copy_path(&mut effective, &document, path);
        }
        match config_of(&effective) {
            Ok(config) => self.config = config,
            Err(error) => report.error = Some(error),
        }
        self.document = document;
        report.applied.extend(applied);
    }
}

impl Reloader {
    /// Publishes the roster on the watch channel when the file says something new. A file that
    /// does not parse leaves the roster in force where it is.
    fn apply_roster(&mut self, report: &mut ReloadReport) {
        match Roster::load(&self.roster_path) {
            Ok(roster) if *self.roster.borrow() == roster => {}
            Ok(roster) => {
                self.roster.send_replace(roster);
                report.applied.push("roster".to_owned());
            }
            Err(error) => report.error = Some(ReloadError::Roster(error.to_string())),
        }
    }
}

/// The document at `path` and the [`Config`] it parses into, validated before anything is
/// diffed so a file the sidecar cannot run with is refused whole.
fn read_config(path: &Path) -> Result<(yaml::Value, Config), ReloadError> {
    let text = std::fs::read_to_string(path).map_err(|err| in_file(path, &err))?;
    let document = yaml::from_str(&text).map_err(|err| in_file(path, &err))?;
    let config = Config::from_yaml(&text).map_err(|err| in_file(path, &err))?;
    Ok((document, config))
}

/// The typed configuration a document holds, which is how the merged document becomes the
/// configuration in force.
fn config_of(document: &yaml::Value) -> Result<Config, ReloadError> {
    let text = yaml::to_string(document).map_err(|err| ReloadError::Config(err.to_string()))?;
    Config::from_yaml(&text).map_err(|err| ReloadError::Config(err.to_string()))
}

/// A configuration error under the file it came from, because a reload reads two files and the
/// operator has to know which one to fix.
fn in_file(path: &Path, error: &dyn std::fmt::Display) -> ReloadError {
    ReloadError::Config(format!("{}: {error}", path.display()))
}

/// Copies `path`'s value from `from` into `into`, removing it where `from` does not have it.
/// Missing parents are created: a key an operator adds to a section the file never had needs
/// the section too.
fn copy_path(into: &mut yaml::Value, from: &yaml::Value, path: &str) {
    let value = path.split('.').try_fold(from, |node, key| node.get(key));
    let mut node = into;
    let mut keys = path.split('.').peekable();
    while let Some(key) = keys.next() {
        let Some(map) = node.as_mapping_mut() else {
            return;
        };
        if keys.peek().is_none() {
            match value {
                Some(value) => map.set(key, value.clone()),
                None => {
                    map.remove(key);
                }
            }
            return;
        }
        node = map
            .entry(yaml::Value::String(key.to_owned(), None))
            .or_insert(yaml::Value::Mapping(yaml::Mapping::new()));
    }
}

/// Every dotted path whose value differs between the two documents, in file-independent order
/// so a report and a log line read the same way twice.
fn changed_paths(old: &yaml::Value, new: &yaml::Value) -> Vec<String> {
    let (old, new) = (flatten(old), flatten(new));
    old.keys()
        .chain(new.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|path| old.get(*path) != new.get(*path))
        .cloned()
        .collect()
}

/// A document as the dotted paths of its leaves. A mapping under a non-string key, and an empty
/// mapping, are leaves themselves: neither is a configuration key.
fn flatten(document: &yaml::Value) -> BTreeMap<String, yaml::Value> {
    let mut leaves = BTreeMap::new();
    walk(String::new(), document, &mut leaves);
    leaves
}

fn walk(path: String, value: &yaml::Value, into: &mut BTreeMap<String, yaml::Value>) {
    match value.as_mapping() {
        Some(map) if !map.is_empty() && map.keys().all(|key| key.as_str().is_some()) => {
            for (key, value) in map {
                let key = key.as_str().unwrap_or_default();
                let child = if path.is_empty() {
                    key.to_owned()
                } else {
                    format!("{path}.{key}")
                };
                walk(child, value, into);
            }
        }
        _ => {
            into.insert(path, value.clone());
        }
    }
}

/// Whether the applier registered on `key` owns `path`: the key itself, or anything under it,
/// so one closure covers a whole section such as `bn.publish_rate_limit`.
fn covers(key: &str, path: &str) -> bool {
    path == key
        || path
            .strip_prefix(key)
            .is_some_and(|rest| rest.starts_with('.'))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use overlay_core::config::{Log, PublishRateLimit};
    use overlay_core::identity::{FleetSeed, write_secret_file};
    use overlay_core::roster::{Hostname, Roster};
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
            let (limits_tx, _) = watch::channel(PublishRateLimit::default());
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
                reloader,
            }
        }

        fn write_roster(&self, text: &str) {
            fs::write(&self.roster_path, text).unwrap();
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

    #[test]
    fn reload_publishes_new_roster_on_the_watch_channel() {
        let mut h = Fixture::new(CONFIG, &roster_yaml(3));
        h.write_roster(&roster_yaml(4));

        let report = h.reloader.reload(Trigger::Manual);

        assert_eq!(report.applied, ["roster"]);
        assert!(report.error.is_none(), "{report:?}");
        let published = h.roster.borrow_and_update();
        assert_eq!(published.hosts.len(), 4);
        assert_eq!(published.hosts[3].hostname, Hostname("bn-4".to_owned()));
    }

    #[test]
    fn reload_publishes_previous_seed_when_fleet_seed_previous_file_is_set_and_none_when_removed() {
        let mut h = Fixture::new(CONFIG, &roster_yaml(3));
        let seed = h.roster_path.with_file_name("seed.previous");
        write_secret_file(&seed, &[7; 32]).unwrap();
        h.write_config(&format!(
            "overlay:\n  roster_file: ROSTER\n  fleet_seed_previous_file: {}\ninject: true\n",
            seed.display()
        ));

        let report = h.reloader.reload(Trigger::Manual);

        assert_eq!(report.applied, ["overlay.fleet_seed_previous_file"]);
        assert!(h.previous_seed.borrow_and_update().is_some(), "{report:?}");

        h.write_config(CONFIG);
        let report = h.reloader.reload(Trigger::Manual);

        assert_eq!(report.applied, ["overlay.fleet_seed_previous_file"]);
        assert!(h.previous_seed.borrow_and_update().is_none(), "{report:?}");
    }

    #[test]
    fn an_unreadable_previous_seed_is_a_reload_error() {
        let mut h = Fixture::new(CONFIG, &roster_yaml(3));
        let missing = h.roster_path.with_file_name("seed.previous");
        h.write_config(&format!(
            "overlay:\n  roster_file: ROSTER\n  fleet_seed_previous_file: {}\ninject: true\n",
            missing.display()
        ));

        let report = h.reloader.reload(Trigger::Manual);

        assert!(report.applied.is_empty(), "{report:?}");
        assert!(
            matches!(&report.error, Some(ReloadError::Config(reason)) if reason.contains("seed.previous")),
            "{report:?}"
        );
        assert!(h.previous_seed.borrow_and_update().is_none());
    }

    #[test]
    fn invalid_config_yaml_keeps_previous_values_and_reports_error() {
        let mut h = Fixture::new(CONFIG, &roster_yaml(3));
        h.write_config("overlay:\n  roster_file: ROSTER\ninject: yes please\n");
        h.write_roster(&roster_yaml(4));

        let report = h.reloader.reload(Trigger::Manual);

        assert!(report.applied.is_empty(), "{report:?}");
        assert!(
            matches!(report.error, Some(ReloadError::Config(_))),
            "{report:?}"
        );
        assert!(h.reloader.config().inject);
        assert!(h.inject.load(Ordering::Relaxed));
        assert_eq!(h.roster.borrow_and_update().hosts.len(), 3);
    }

    #[test]
    fn invalid_roster_yaml_keeps_previous_roster() {
        let mut h = Fixture::new(CONFIG, &roster_yaml(3));
        h.write_roster(
            "hosts:\n  - hostname: bn-1\n    region: eu\n    addr: \"not an address\"\n",
        );

        let report = h.reloader.reload(Trigger::Manual);

        assert!(
            matches!(report.error, Some(ReloadError::Roster(_))),
            "{report:?}"
        );
        assert_eq!(h.roster.borrow_and_update().hosts.len(), 3);
    }

    #[test]
    fn changed_non_reloadable_key_is_listed_as_restart_required_and_old_value_stays() {
        let mut h = Fixture::new(
            "overlay:\n  roster_file: ROSTER\n  listen: \"[::]:7788\"\nbn:\n  node_key_file: /var/lib/fleet-overlay/node.key\ninject: true\n",
            &roster_yaml(3),
        );
        h.write_config(
            "overlay:\n  roster_file: ROSTER\n  listen: \"[::]:9999\"\nbn:\n  node_key_file: /var/lib/fleet-overlay/other.key\ninject: true\n",
        );

        let report = h.reloader.reload(Trigger::Manual);

        assert!(report.applied.is_empty(), "{report:?}");
        assert_eq!(
            report.restart_required,
            ["bn.node_key_file", "overlay.listen"]
        );
        assert!(report.error.is_none(), "{report:?}");
        assert_eq!(h.reloader.config().overlay.listen.port(), 7788);
        assert_eq!(
            h.reloader.config().bn.node_key_file,
            PathBuf::from("/var/lib/fleet-overlay/node.key")
        );
    }
}
