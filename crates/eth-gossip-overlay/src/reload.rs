//! Re-reading `config.yaml` and `roster.yaml` under a running sidecar (§5.3, §5.7, D26).
//!
//! One [`Reloader`] owns the current configuration and roster and applies what may change at
//! runtime; everything else reaches it through a [`ReloadHandle`], so SIGHUP, `eth-gossip-overlayctl
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
//!
//! # Who consumes each reloadable key
//!
//! [`RELOADABLE`] is the whole set (Appendix A), and each key has at most one applier, which is
//! whatever puts it where its consumer already reads it:
//!
//! - `inject`: the `AtomicBool` T-017's publisher reads per item, so the kill switch takes hold
//!   on the next message either way it is flipped.
//! - `bn.publish_rate_limit.*`: one applier for the section, sending the three ceilings to
//!   T-017's publisher, which rebuilds its token buckets.
//! - `bn.by_root_cache.enabled`: the `AtomicBool` T-085's responder reads per request, so
//!   turning the cache off puts T-019's `ResourceUnavailable` back on the next lookup. The
//!   window `bn.by_root_cache.slots` names is not reloadable: the recent store is sized once,
//!   against the memory budget the process started under.
//! - `overlay.fleet_seed_previous_file`: loaded with T-004's reader, and T-021's pin table is
//!   rebuilt with it so the verifier accepts keys from the outgoing seed for as long as the
//!   file is configured (DX-N2).
//! - `log.level` and `log.format`: T-044's [`LogHandle`], which leaves the level alone while
//!   `RUST_LOG` is set and says so (D32).
//! - `classes.small.batch_window_ms` and `classes.small.stale_after_ms`: one applier for the
//!   section, sending both bounds to T-062's batcher task, which closes what it is holding under
//!   the old ones and collects under the new.
//! - `overlay.fanout.small.*` and `overlay.fanout.large.stripe_min_recipients`: an applier
//!   each, both composing the whole fanout T-063's and T-072's router reads and sending it to
//!   the fanout task, so a file that changed keys in one section carries the other's too.
//!   `large.in_region` and `large.cross_region` keep the values the process started with,
//!   because they need a restart and this must not smuggle them in.
//! - `classes.large.repair_deadline_ms` and `classes.large.column_repair`: the channels T-082's
//!   repair scheduler reads on every tick, so a change takes hold on the next one (D24, T-087).
//!   Turning column repair off leaves the beacon node fetching its own columns, which is what it
//!   did before the feature existed.
//!
//! The roster is not a config key and has no applier. It goes on its own watch channel, which
//! T-023's connection manager and [`spawn_pin_table`] follow, and is the one entry in
//! [`ReloadReport::applied`] that is not a dotted path.
//!
//! Adding a reloadable key is one path in [`RELOADABLE`] and one closure in [`Reloader::new`],
//! registered on that path or on the section it belongs to.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use overlay_core::config::{Config, Fanout, LargeFanout, PublishRateLimit, SmallClass};
use overlay_core::identity::{FleetSeed, Seeds, read_secret_file};
use overlay_core::roster::Roster;
use overlay_transport::tls::PinTable;
use serde::{Deserialize, Serialize};
use serde_yaml_bw as yaml;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::logging::{LogHandle, directive};

/// Every key that may change under a running sidecar (Appendix A), as the dotted paths of
/// `config.yaml`. Anything else that changed is reported as needing a restart.
///
/// A changed path here runs the applier registered for it, and is otherwise reported applied
/// and answered by [`Reloader::config`], which is where the ticket that ships its consumer
/// reads it. Adding a key means adding its path here and one closure in [`Reloader::new`].
pub const RELOADABLE: &[&str] = &[
    "bn.by_root_cache.enabled",
    "bn.publish_rate_limit.bytes_per_s",
    "bn.publish_rate_limit.large_per_s",
    "bn.publish_rate_limit.small_per_s",
    "classes.large.column_repair",
    "classes.large.repair_deadline_ms",
    "classes.small.batch_window_ms",
    "classes.small.stale_after_ms",
    "inject",
    "log.format",
    "log.level",
    "overlay.fanout.large.stripe_min_recipients",
    "overlay.fanout.small.cross_region",
    "overlay.fanout.small.relay_min_remote_hosts",
    "overlay.fanout.small.relays_per_remote_region",
    PREVIOUS_SEED,
];

/// The one reloadable key applied by the reloader itself rather than by a registered closure:
/// the seeds it reads into are the ones `apply_roster` builds the pin table from.
const PREVIOUS_SEED: &str = "overlay.fleet_seed_previous_file";

/// What asked for a reload (D26). A human means what the files say; a tool that writes them
/// may be broken, which is what the roster shrink guard protects against.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Trigger {
    /// SIGHUP or `eth-gossip-overlayctl roster reload`.
    Manual,
    /// The roster file watcher (T-086).
    Automatic,
}

impl Trigger {
    /// The trigger as a log line and the report's JSON spell it.
    fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Automatic => "automatic",
        }
    }
}

/// What one reload did, returned to whoever asked for it and serialized verbatim by T-042's
/// admin socket, which is also where `eth-gossip-overlayctl` reads it back.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReloadReport {
    /// What asked for this reload.
    pub trigger: Trigger,
    /// The keys that took effect, and `roster` when the roster itself changed.
    pub applied: Vec<String>,
    /// Keys changed in the file that only a restart reads, every one since the process
    /// started: an edit the roster watcher's reload saw first is still pending when the
    /// operator runs their own.
    pub restart_required: Vec<String>,
    /// Why the reload did not finish, if it did not. The previous values stay in force. One
    /// slot: a reload that hits two problems reports the later one, which is the roster's,
    /// because that is the one an alert watches.
    pub error: Option<ReloadError>,
}

/// Why a reload kept the previous values.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize, thiserror::Error)]
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
    /// Whether the responder answers the beacon node's by-root lookups out of the recent store
    /// (§5.8). Only the flag reloads: the store's window is sized once, at startup, because the
    /// memory budget it is priced in is.
    pub by_root_cache: Arc<AtomicBool>,
    /// The roster the connection manager (T-023) follows.
    pub roster: watch::Sender<Roster>,
    /// The pin table every handshake is verified against (T-021). A reload rebuilds it before
    /// it publishes the roster, so the dial the manager starts for an added host is checked
    /// against a table that already holds the host (T-104).
    pub pins: Arc<ArcSwap<PinTable>>,
    /// The seeds the table is built from: the one in force, which takes a restart to change,
    /// and the outgoing one while a rotation is in progress (DX-N2).
    pub seeds: Seeds,
    /// The ceilings the publisher rebuilds its token buckets from (DX-N3).
    pub limits: watch::Sender<PublishRateLimit>,
    /// The window and stale bound the batcher collects under (D21).
    pub small: watch::Sender<SmallClass>,
    /// Where the fanout task reads the plan it routes under (T-063).
    pub fanout: watch::Sender<Fanout>,
    /// How long T-082's repair scheduler waits after a message's first chunk before asking a
    /// peer for what is missing (D24).
    pub repair_deadline: watch::Sender<Duration>,
    /// Whether that scheduler also asks for the custody columns the beacon node is short of
    /// (§6.4, T-087).
    pub column_repair: watch::Sender<bool>,
    /// The running subscriber, whose level and format are reloadable (D32).
    pub log: Arc<LogHandle>,
    /// Where the two reload counters live.
    pub stats: Arc<dyn ReloadStats>,
}

/// What one caller asks the reload task for: a trigger and somewhere to put the report.
type Request = (Trigger, oneshot::Sender<ReloadReport>);

/// How everything but the reload task itself asks for a reload. Cloneable, and every clone
/// reaches the one [`Reloader`], so SIGHUP, the admin socket (T-042) and the roster file
/// watcher (T-086) cannot run two reloads at once.
#[derive(Clone)]
pub struct ReloadHandle(mpsc::Sender<Request>);

impl ReloadHandle {
    /// Runs one reload and waits for its report. `None` means the task that owns the reloader
    /// has ended, which happens when the process is shutting down.
    pub async fn reload(&self, trigger: Trigger) -> Option<ReloadReport> {
        let (reply, answer) = oneshot::channel();
        self.0.send((trigger, reply)).await.ok()?;
        answer.await.ok()
    }
}

/// Starts the task that owns `reloader` and returns the handle every caller reaches it by.
/// The task ends when the last handle is dropped.
pub fn spawn(reloader: Reloader) -> (ReloadHandle, JoinHandle<()>) {
    let (requests, receiver) = mpsc::channel(REQUEST_QUEUE);
    (
        ReloadHandle(requests),
        tokio::spawn(run(reloader, receiver)),
    )
}

/// Reloads are rare and a caller waits for its own report, so the queue only has to hold the
/// handful of callers there are.
const REQUEST_QUEUE: usize = 8;

async fn run(mut reloader: Reloader, mut requests: mpsc::Receiver<Request>) {
    while let Some((trigger, reply)) = requests.recv().await {
        // A caller that stopped waiting still gets its reload; the report simply has nowhere
        // to go.
        let _ = reply.send(reloader.reload(trigger));
    }
}

/// The SIGHUP loop the sidecar runs for the lifetime of the process: `systemctl reload
/// eth-gossip-overlay` sends the signal, and every one of them is a manual reload.
///
/// The handler is installed before the future is returned, so a signal that arrives between
/// this call and the spawn is still delivered. Each report is logged by the reload itself.
pub fn sighup_loop(handle: ReloadHandle) -> std::io::Result<impl Future<Output = ()> + Send> {
    let mut hangups = signal(SignalKind::hangup())?;
    Ok(async move {
        while hangups.recv().await.is_some() {
            if handle.reload(Trigger::Manual).await.is_none() {
                return;
            }
        }
    })
}

/// How often the roster file's modification time is read (D26). Ten seconds is the bound
/// `docs/configuration.md` promises a discovery tool, and a constant rather than a key because
/// no fleet has a reason to want another number: inotify would notice sooner, at the cost of a
/// Linux-only dependency for a saving a membership change does not need.
pub const ROSTER_POLL_INTERVAL: Duration = Duration::from_secs(10);

/// The task that notices a discovery tool rewriting `roster.yaml`, beside the signal loop
/// (T-086, D26).
///
/// It is the only [`Trigger::Automatic`] caller, which is what puts the shrink guard between a
/// tool that wrote half a file and a fleet that loses half its hosts. The reload it runs is the
/// one SIGHUP runs, so a roster picked up here drops no connection either.
///
/// The modification time is remembered before the file is read rather than after, so a writer
/// that is not finished cannot be applied and then forgotten: a half-written file fails to parse
/// and leaves the roster alone, and the write that finishes it moves the time again, so the next
/// poll reads the whole file. Writing to a temp file and renaming it, which
/// `docs/configuration.md` asks for, spares that poll.
pub struct RosterWatcher {
    path: PathBuf,
    handle: ReloadHandle,
    seen: Option<SystemTime>,
}

impl RosterWatcher {
    /// Watches `path`, taking what it says now as the roster already in force.
    pub fn new(path: PathBuf, handle: ReloadHandle) -> Self {
        let seen = mtime(&path);
        Self { path, handle, seen }
    }

    /// Polls until the reloader ends, which is the process shutting down.
    pub async fn run(mut self) {
        let mut tick = tokio::time::interval(ROSTER_POLL_INTERVAL);
        loop {
            tick.tick().await;
            if !self.poll().await {
                return;
            }
        }
    }

    /// One poll, and whether there is any point in another.
    async fn poll(&mut self) -> bool {
        let Some(mtime) = mtime(&self.path) else {
            return true;
        };
        if self.seen == Some(mtime) {
            return true;
        }
        self.seen = Some(mtime);
        self.handle.reload(Trigger::Automatic).await.is_some()
    }
}

/// The file's modification time, or nothing when it cannot be read. A roster that is missing for
/// a moment is one the sidecar keeps running on, so the failure is a line an operator can find
/// afterwards and the next poll tries again.
fn mtime(path: &Path) -> Option<SystemTime> {
    match std::fs::metadata(path).and_then(|meta| meta.modified()) {
        Ok(mtime) => Some(mtime),
        Err(err) => {
            tracing::warn!(%err, path = %path.display(), "cannot stat the roster file");
            None
        }
    }
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
    /// What `ReloadReport::restart_required` lists, kept until the process restarts.
    pending_restart: BTreeSet<String>,
    config: Config,
    roster: watch::Sender<Roster>,
    /// Rebuilt from the roster and `seeds` before either is changed for anyone else. The
    /// verifier reads it through the `ArcSwap` on every handshake, so a rebuild drops nothing.
    pins: Arc<ArcSwap<PinTable>>,
    seeds: Seeds,
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
        let started_with = config.overlay.fanout.large.clone();
        let by_root_cache = deps.by_root_cache;
        let column_repair = deps.column_repair;
        let appliers: Vec<(&'static str, Applier)> = vec![
            (
                "inject",
                Box::new(move |cfg: &Config| {
                    inject.store(cfg.inject, Ordering::Relaxed);
                    Ok(())
                }),
            ),
            (
                "classes.large.column_repair",
                Box::new(move |cfg: &Config| {
                    let _ = column_repair.send(cfg.classes.large.column_repair);
                    Ok(())
                }),
            ),
            (
                "bn.by_root_cache.enabled",
                Box::new(move |cfg: &Config| {
                    by_root_cache.store(cfg.bn.by_root_cache.enabled, Ordering::Relaxed);
                    Ok(())
                }),
            ),
            (
                // One applier for the whole section: the publisher takes the three ceilings
                // together, so a file that changes two of them still rebuilds its buckets once.
                "bn.publish_rate_limit",
                {
                    let limits = deps.limits;
                    Box::new(move |cfg: &Config| {
                        limits.send_replace(cfg.bn.publish_rate_limit.clone());
                        Ok(())
                    })
                },
            ),
            (
                // One applier for the section, as above: the batcher takes the window and the
                // stale bound together.
                "classes.small",
                {
                    let small = deps.small;
                    Box::new(move |cfg: &Config| {
                        small.send_replace(cfg.classes.small.clone());
                        Ok(())
                    })
                },
            ),
            (
                // One applier for the three relay keys, which the router weighs together, and
                // one for the stripe threshold beside it. Both build the whole fanout, so a
                // file that changed keys in either section ends up with both.
                "overlay.fanout.small",
                {
                    let (fanout, large) = (deps.fanout.clone(), started_with.clone());
                    Box::new(move |cfg: &Config| {
                        fanout.send_replace(fanout_of(cfg, &large));
                        Ok(())
                    })
                },
            ),
            ("overlay.fanout.large.stripe_min_recipients", {
                let (fanout, large) = (deps.fanout, started_with);
                Box::new(move |cfg: &Config| {
                    fanout.send_replace(fanout_of(cfg, &large));
                    Ok(())
                })
            }),
            ("classes.large.repair_deadline_ms", {
                let deadline = deps.repair_deadline;
                Box::new(move |cfg: &Config| {
                    deadline.send_replace(cfg.classes.large.repair_deadline);
                    Ok(())
                })
            }),
            ("log.level", {
                let log = deps.log.clone();
                Box::new(move |cfg: &Config| {
                    log.set_level(directive(cfg.log.level));
                    Ok(())
                })
            }),
            ("log.format", {
                let log = deps.log;
                Box::new(move |cfg: &Config| {
                    log.set_format(cfg.log.format);
                    Ok(())
                })
            }),
        ];
        Ok(Self {
            config_path,
            roster_path: config.overlay.roster_file.clone(),
            document,
            pending_restart: BTreeSet::new(),
            config,
            roster: deps.roster,
            pins: deps.pins,
            seeds: deps.seeds,
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
                self.apply_roster(trigger, &mut report);
            }
            // A config the sidecar cannot run with stops the reload before the roster is read:
            // one broken file, one error, and the next reload applies both.
            Err(error) => report.error = Some(error),
        }
        report.restart_required = self.pending_restart.iter().cloned().collect();
        self.stats.reloaded(&report);
        let (applied, restart_required) = (
            report.applied.join(", "),
            report.restart_required.join(", "),
        );
        match &report.error {
            None => tracing::info!(
                trigger = report.trigger.as_str(),
                applied,
                restart_required,
                "reloaded"
            ),
            Some(error) => tracing::warn!(
                %error,
                trigger = report.trigger.as_str(),
                applied,
                restart_required,
                "reloaded with an error, previous values kept"
            ),
        }
        report
    }

    /// Runs the applier of every changed key that has one, and records the rest.
    fn apply_config(&mut self, document: yaml::Value, config: Config, report: &mut ReloadReport) {
        let mut applied = Vec::new();
        let mut restart_required = Vec::new();
        for path in changed_paths(&self.document, &document) {
            let outcome = if covers(PREVIOUS_SEED, &path) {
                Some(self.apply_previous_seed(&config))
            } else {
                self.appliers
                    .iter_mut()
                    .find(|(key, _)| covers(key, &path))
                    .map(|(_, apply)| apply(&config))
            };
            match outcome {
                Some(Ok(())) => applied.push(path),
                Some(Err(reason)) => report.error = Some(ReloadError::Config(reason)),
                None if reloadable(&path) => applied.push(path),
                None => restart_required.push(path),
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
        // The next diff runs against what was taken in plus the restart-required keys, which
        // stay pending rather than being diffed again. A key whose applier refused it stays at
        // its old value, so the corrected file reads as a change again and the applier gets
        // another go.
        for path in &restart_required {
            copy_path(&mut effective, &document, path);
        }
        self.document = effective;
        self.pending_restart.extend(restart_required);
        report.applied.extend(applied);
    }

    /// Reads the outgoing seed the document names, or forgets it, and rebuilds the pin table so
    /// the verifier accepts keys from it for as long as the key is configured (DX-N2).
    fn apply_previous_seed(&mut self, cfg: &Config) -> Result<(), String> {
        self.seeds.previous = match &cfg.overlay.fleet_seed_previous_file {
            Some(path) => Some(FleetSeed::from(
                *read_secret_file(path).map_err(|err| err.to_string())?,
            )),
            None => None,
        };
        self.pins.store(Arc::new(PinTable::build(
            &self.roster.borrow(),
            &self.seeds,
        )));
        Ok(())
    }

    /// Publishes the roster on the watch channel when the file says something new. A file that
    /// does not parse, or one the shrink guard refuses, leaves the roster in force where it is.
    fn apply_roster(&mut self, trigger: Trigger, report: &mut ReloadReport) {
        let roster = match Roster::load(&self.roster_path) {
            Ok(roster) => roster,
            Err(error) => {
                report.error = Some(ReloadError::Roster(error.to_string()));
                return;
            }
        };
        if *self.roster.borrow() == roster {
            return;
        }
        let (before, removed) = {
            let current = self.roster.borrow();
            let removed = current
                .hosts
                .iter()
                .filter(|host| roster.get(&host.hostname).is_none())
                .count();
            (current.hosts.len(), removed)
        };
        // A discovery tool that writes a half-empty roster is likelier to be broken than right,
        // so an automatic reload stops here; a human who means to halve the fleet says so with
        // SIGHUP or `eth-gossip-overlayctl roster reload` (D26).
        if trigger == Trigger::Automatic && removed * 2 > before {
            report.error = Some(ReloadError::RosterShrinkRejected {
                before,
                after: roster.hosts.len(),
            });
            return;
        }
        // The table first. The manager dials an added host the moment it sees the roster, and
        // the handshake reads the table; the other order verified that dial against a table
        // that did not hold the host yet (R3.2). What is left is an inbound dial landing
        // between the two stores, refused as `hostname` for the microseconds in between.
        self.pins
            .store(Arc::new(PinTable::build(&roster, &self.seeds)));
        self.roster.send_replace(roster);
        report.applied.push("roster".to_owned());
    }
}

/// The fanout the router routes under: what the file says, except for the two `large` keys that
/// need a restart, which stay as `started_with` has them. An applier that sent the section as
/// the file spells it would apply what the same reload had just reported as restart-required.
fn fanout_of(cfg: &Config, started_with: &LargeFanout) -> Fanout {
    Fanout {
        large: LargeFanout {
            stripe_min_recipients: cfg.overlay.fanout.large.stripe_min_recipients,
            ..started_with.clone()
        },
        small: cfg.overlay.fanout.small.clone(),
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

/// Whether `path` names a key that may change under a running sidecar.
fn reloadable(path: &str) -> bool {
    RELOADABLE.iter().any(|key| covers(key, path))
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use arc_swap::ArcSwap;
    use overlay_core::config::{
        LargeClass, LargeFanout, Log, LogFormat, LogLevel, PublishRateLimit, SmallCrossRegion,
    };
    use overlay_core::identity::{FleetSeed, Seeds, expected_tls_public_key, write_secret_file};
    use overlay_core::roster::{Hostname, Roster};
    use overlay_transport::tls::PinTable;
    use tempfile::TempDir;
    use tokio::sync::{Notify, watch};

    use serde_json::{Map, Value};
    use tracing::Dispatch;

    use super::*;
    use crate::logging::testing;
    use crate::logging::testing::Sink;

    /// A config document with the roster path filled in by [`Fixture::write_config`].
    const CONFIG: &str = "overlay:\n  roster_file: ROSTER\ninject: true\n";

    /// The seed in force for every fixture.
    const SEED: [u8; 32] = [1; 32];

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

    /// Every report the reloader finished, which is what T-041 binds the two counters to, and
    /// a permit per report so a test can wait for one without polling.
    #[derive(Default)]
    struct Recorded {
        reports: Mutex<Vec<ReloadReport>>,
        reloaded: Notify,
    }

    impl Recorded {
        /// Reloads that ended in an error, the `outcome="error"` series.
        fn errors(&self) -> usize {
            self.reports
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.error.is_some())
                .count()
        }

        /// Reloads that ended clean, the `outcome="ok"` series.
        fn ok(&self) -> usize {
            self.reports
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.error.is_none())
                .count()
        }

        /// Rosters the shrink guard refused, `roster_reload_rejected_total`.
        fn rejected(&self) -> usize {
            self.reports
                .lock()
                .unwrap()
                .iter()
                .filter(|r| matches!(r.error, Some(ReloadError::RosterShrinkRejected { .. })))
                .count()
        }

        fn first(&self) -> ReloadReport {
            self.reports.lock().unwrap()[0].clone()
        }

        /// How many reloads ran at all, which is what a poll that must not reload asserts on.
        fn count(&self) -> usize {
            self.reports.lock().unwrap().len()
        }

        fn last(&self) -> ReloadReport {
            self.reports.lock().unwrap().last().unwrap().clone()
        }
    }

    impl ReloadStats for Recorded {
        fn reloaded(&self, report: &ReloadReport) {
            self.reports.lock().unwrap().push(report.clone());
            self.reloaded.notify_one();
        }
    }

    /// A reloader over files in a temp directory, holding the receiving end of every channel
    /// an applier writes to.
    struct Fixture {
        _dir: TempDir,
        config_path: PathBuf,
        roster_path: PathBuf,
        inject: Arc<AtomicBool>,
        roster: watch::Receiver<Roster>,
        pins: Arc<ArcSwap<PinTable>>,
        limits: watch::Receiver<PublishRateLimit>,
        small: watch::Receiver<SmallClass>,
        fanout: watch::Receiver<Fanout>,
        repair_deadline: watch::Receiver<Duration>,
        column_repair: watch::Receiver<bool>,
        stats: Arc<Recorded>,
        reloader: Reloader,
    }

    impl Fixture {
        fn new(config: &str, roster: &str) -> Self {
            Fixture::with_log(config, roster, &Log::default(), None).0
        }

        /// A fixture whose log appliers write through an in-memory subscriber, returned with
        /// the dispatch a test has to install around the code it wants captured.
        fn with_log(
            config: &str,
            roster: &str,
            log_cfg: &Log,
            rust_log: Option<&str>,
        ) -> (Self, Sink, Dispatch) {
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
            let by_root_cache = Arc::new(AtomicBool::new(false));
            let (roster_tx, roster_rx) = watch::channel(Roster::from_yaml(roster).unwrap());
            let seeds = Seeds {
                current: FleetSeed::from(SEED),
                previous: None,
            };
            let pins = Arc::new(ArcSwap::from_pointee(PinTable::build(
                &roster_tx.borrow(),
                &seeds,
            )));
            let (limits_tx, limits) = watch::channel(PublishRateLimit::default());
            let (small_tx, small) = watch::channel(SmallClass::default());
            let (fanout_tx, fanout) = watch::channel(Fanout::default());
            let (deadline_tx, repair_deadline) =
                watch::channel(LargeClass::default().repair_deadline);
            let (column_repair_tx, column_repair) =
                watch::channel(LargeClass::default().column_repair);
            let (sink, dispatch, log) = testing::subscriber(log_cfg, false, rust_log);
            let stats = Arc::new(Recorded::default());
            let reloader = Reloader::new(
                config_path.clone(),
                Deps {
                    inject: inject.clone(),
                    by_root_cache: by_root_cache.clone(),
                    roster: roster_tx,
                    pins: pins.clone(),
                    seeds,
                    limits: limits_tx,
                    small: small_tx,
                    fanout: fanout_tx,
                    repair_deadline: deadline_tx,
                    column_repair: column_repair_tx,
                    log: Arc::new(log),
                    stats: stats.clone(),
                },
            )
            .unwrap();
            let fixture = Self {
                _dir: dir,
                config_path,
                roster_path,
                inject,
                roster: roster_rx,
                pins,
                limits,
                small,
                fanout,
                repair_deadline,
                column_repair,
                stats,
                reloader,
            };
            (fixture, sink, dispatch)
        }

        fn write_roster(&self, text: &str) {
            fs::write(&self.roster_path, text).unwrap();
        }

        /// Whether the pin table holds `host`'s key under `seed`.
        fn pinned(&self, seed: &FleetSeed, host: &str) -> bool {
            let key = expected_tls_public_key(seed, &Hostname(host.to_owned()));
            self.pins.load().lookup(&key).is_some()
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

    /// DX-N2: the table accepts keys from the outgoing seed for as long as the key names it,
    /// beside the seed in force, and drops them once the key goes.
    #[test]
    fn pin_table_follows_the_roster_and_the_previous_seed() {
        let mut h = Fixture::new(CONFIG, &roster_yaml(2));
        let (current, previous) = (FleetSeed::from(SEED), FleetSeed::from([7; 32]));
        assert!(!h.pinned(&current, "bn-3"));

        h.write_roster(&roster_yaml(3));
        let report = h.reloader.reload(Trigger::Manual);

        assert_eq!(report.applied, ["roster"]);
        assert!(h.pinned(&current, "bn-3"));

        let seed = h.roster_path.with_file_name("seed.previous");
        write_secret_file(&seed, &[7; 32]).unwrap();
        h.write_config(&format!(
            "overlay:\n  roster_file: ROSTER\n  fleet_seed_previous_file: {}\ninject: true\n",
            seed.display()
        ));
        let report = h.reloader.reload(Trigger::Manual);

        assert_eq!(report.applied, ["overlay.fleet_seed_previous_file"]);
        assert!(h.pinned(&previous, "bn-1"), "{report:?}");
        assert!(h.pinned(&current, "bn-1"));

        h.write_config(CONFIG);
        let report = h.reloader.reload(Trigger::Manual);

        assert_eq!(report.applied, ["overlay.fleet_seed_previous_file"]);
        assert!(!h.pinned(&previous, "bn-1"), "{report:?}");
        assert!(h.pinned(&current, "bn-1"));
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
        assert!(h.pinned(&FleetSeed::from(SEED), "bn-1"));
    }

    /// `docs/security.md` step 1 on a host where the key reaches `config.yaml` before the seed
    /// file reaches disk: the first reload fails, and the next one, with the file in place, has
    /// to apply it. It cannot if the failed value already sits in the baseline (R5.3).
    #[test]
    fn a_reload_whose_applier_fails_keeps_the_old_value_in_the_baseline() {
        let mut h = Fixture::new(CONFIG, &roster_yaml(3));
        let seed = h.roster_path.with_file_name("seed.previous");
        h.write_config(&format!(
            "overlay:\n  roster_file: ROSTER\n  fleet_seed_previous_file: {}\ninject: true\n",
            seed.display()
        ));
        let first = h.reloader.reload(Trigger::Manual);
        assert!(first.error.is_some(), "{first:?}");

        write_secret_file(&seed, &[7; 32]).unwrap();
        let second = h.reloader.reload(Trigger::Manual);

        assert_eq!(second.applied, [PREVIOUS_SEED], "{second:?}");
        assert!(second.error.is_none(), "{second:?}");
        assert!(h.pinned(&FleetSeed::from([7; 32]), "bn-1"));
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
            "overlay:\n  roster_file: ROSTER\n  listen: \"[::]:7788\"\nbn:\n  node_key_file: /var/lib/eth-gossip-overlay/node.key\ninject: true\n",
            &roster_yaml(3),
        );
        h.write_config(
            "overlay:\n  roster_file: ROSTER\n  listen: \"[::]:9999\"\nbn:\n  node_key_file: /var/lib/eth-gossip-overlay/other.key\ninject: true\n",
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
            PathBuf::from("/var/lib/eth-gossip-overlay/node.key")
        );
    }

    /// The roster watcher's reload can be the first to see a restart-required edit. The operator
    /// who then runs their own reload has to be told too, not answered `none` because the
    /// journal already was (R5.4a).
    #[test]
    fn a_restart_required_key_is_reported_on_every_reload_until_restart() {
        let mut h = Fixture::new(
            "overlay:\n  roster_file: ROSTER\n  listen: \"[::]:7788\"\ninject: true\n",
            &roster_yaml(3),
        );
        h.write_config("overlay:\n  roster_file: ROSTER\n  listen: \"[::]:9999\"\ninject: true\n");

        let automatic = h.reloader.reload(Trigger::Automatic);
        let manual = h.reloader.reload(Trigger::Manual);

        assert_eq!(automatic.restart_required, ["overlay.listen"]);
        assert_eq!(manual.restart_required, ["overlay.listen"], "{manual:?}");
        assert!(manual.applied.is_empty(), "{manual:?}");
    }

    /// The repair deadline reaches T-082's scheduler, which reads it on every tick, so a canary
    /// that finds 250 ms firing during ordinary column bursts moves it without a restart (D24).
    ///
    /// It was the example of a reloadable key with no applier until this ticket gave it one, and
    /// there is no such key left: the shape changed rather than the key, because the two halves
    /// it proved, that a change is reported applied and that `config()` answers with it, are
    /// owed by every reloadable key whether or not an applier reads it.
    #[test]
    fn changed_repair_deadline_is_applied_reported_and_visible_in_config() {
        let mut h = Fixture::new(
            "overlay:\n  roster_file: ROSTER\nclasses:\n  large:\n    repair_deadline_ms: 250\ninject: true\n",
            &roster_yaml(3),
        );
        h.write_config(
            "overlay:\n  roster_file: ROSTER\nclasses:\n  large:\n    repair_deadline_ms: 400\ninject: true\n",
        );

        let report = h.reloader.reload(Trigger::Manual);

        assert_eq!(report.applied, ["classes.large.repair_deadline_ms"]);
        assert!(report.restart_required.is_empty(), "{report:?}");
        assert_eq!(
            h.reloader.config().classes.large.repair_deadline,
            Duration::from_millis(400)
        );
        assert_eq!(
            *h.repair_deadline.borrow_and_update(),
            Duration::from_millis(400)
        );
    }

    /// The switch an operator throws when column repair is costing more than it returns. SIGHUP
    /// and the scheduler stops asking on the next tick, with no restart and no rebuild (T-087).
    #[test]
    fn changed_column_repair_reaches_the_scheduler() {
        let mut h = Fixture::new(
            "overlay:\n  roster_file: ROSTER\nclasses:\n  large:\n    column_repair: true\ninject: true\n",
            &roster_yaml(3),
        );
        h.write_config(
            "overlay:\n  roster_file: ROSTER\nclasses:\n  large:\n    column_repair: false\ninject: true\n",
        );

        let report = h.reloader.reload(Trigger::Manual);

        assert_eq!(report.applied, ["classes.large.column_repair"]);
        assert!(report.restart_required.is_empty(), "{report:?}");
        assert!(!h.reloader.config().classes.large.column_repair);
        assert!(!*h.column_repair.borrow_and_update());
    }

    #[test]
    fn every_key_an_applier_owns_is_reloadable() {
        let h = Fixture::new(CONFIG, &roster_yaml(3));

        for (key, _) in &h.reloader.appliers {
            assert!(
                RELOADABLE.iter().any(|path| covers(key, path)),
                "{key} has an applier but is not in RELOADABLE"
            );
        }
    }

    #[test]
    fn unchanged_files_report_nothing_applied() {
        let mut h = Fixture::new(CONFIG, &roster_yaml(3));

        let report = h.reloader.reload(Trigger::Manual);

        assert!(report.applied.is_empty(), "{report:?}");
        assert!(report.restart_required.is_empty(), "{report:?}");
        assert!(report.error.is_none(), "{report:?}");
        assert!(!h.roster.has_changed().unwrap());
    }

    #[test]
    fn automatic_reload_removing_more_than_half_the_hosts_is_rejected_and_counted() {
        let mut h = Fixture::new(CONFIG, &roster_yaml(10));
        h.write_roster(&roster_yaml(4));
        h.write_config("overlay:\n  roster_file: ROSTER\ninject: false\n");

        let report = h.reloader.reload(Trigger::Automatic);

        assert_eq!(report.applied, ["inject"]);
        assert_eq!(
            report.error,
            Some(ReloadError::RosterShrinkRejected {
                before: 10,
                after: 4
            })
        );
        assert_eq!(h.roster.borrow_and_update().hosts.len(), 10);
        assert!(!h.inject.load(Ordering::Relaxed));
        assert_eq!(
            (h.stats.ok(), h.stats.errors(), h.stats.rejected()),
            (0, 1, 1)
        );

        h.write_roster(&roster_yaml(5));
        let report = h.reloader.reload(Trigger::Automatic);

        assert_eq!(report.applied, ["roster"]);
        assert!(report.error.is_none(), "{report:?}");
        assert_eq!(h.roster.borrow_and_update().hosts.len(), 5);
        assert_eq!(
            (h.stats.ok(), h.stats.errors(), h.stats.rejected()),
            (1, 1, 1)
        );
    }

    #[test]
    fn manual_reload_of_the_same_shrinking_roster_applies() {
        let mut h = Fixture::new(CONFIG, &roster_yaml(10));
        h.write_roster(&roster_yaml(4));

        let report = h.reloader.reload(Trigger::Manual);

        assert_eq!(report.applied, ["roster"]);
        assert!(report.error.is_none(), "{report:?}");
        assert_eq!(h.roster.borrow_and_update().hosts.len(), 4);
        assert_eq!(h.stats.rejected(), 0);
    }

    #[test]
    fn reload_applies_log_level_and_format() {
        let (mut h, sink, dispatch) = Fixture::with_log(
            "overlay:\n  roster_file: ROSTER\nlog:\n  level: info\n  format: text\n",
            &roster_yaml(3),
            &Log {
                level: LogLevel::Info,
                format: LogFormat::Text,
            },
            None,
        );
        h.write_config("overlay:\n  roster_file: ROSTER\nlog:\n  level: debug\n  format: json\n");

        let report = tracing::dispatcher::with_default(&dispatch, || {
            tracing::debug!("below the configured level");
            let report = h.reloader.reload(Trigger::Manual);
            tracing::debug!("above it now");
            report
        });

        assert_eq!(report.applied, ["log.format", "log.level"]);
        assert!(
            !sink.text().contains("below the configured level"),
            "{}",
            sink.text()
        );
        // Every line parses as JSON, which is the format having changed, and the debug line
        // after the reload is there, which is the level having changed.
        let messages: Vec<String> = sink
            .objects()
            .iter()
            .map(|line| line["message"].to_string())
            .collect();
        assert!(
            messages
                .iter()
                .any(|message| message.contains("above it now")),
            "{messages:?}"
        );
    }

    #[test]
    fn rust_log_set_leaves_the_level_untouched_and_says_so() {
        let (mut h, sink, dispatch) = Fixture::with_log(
            "overlay:\n  roster_file: ROSTER\nlog:\n  level: info\n  format: json\n",
            &roster_yaml(3),
            &Log {
                level: LogLevel::Info,
                format: LogFormat::Json,
            },
            Some("debug"),
        );
        h.write_config("overlay:\n  roster_file: ROSTER\nlog:\n  level: error\n  format: json\n");

        let report = tracing::dispatcher::with_default(&dispatch, || {
            let report = h.reloader.reload(Trigger::Manual);
            tracing::debug!("the environment still lets this through");
            report
        });

        assert_eq!(report.applied, ["log.level"]);
        let messages: Vec<String> = sink
            .objects()
            .iter()
            .map(|line| line["message"].to_string())
            .collect();
        assert!(
            messages
                .iter()
                .any(|message| message.contains("RUST_LOG is set, so log.level is not applied")),
            "{messages:?}"
        );
        assert!(
            messages
                .iter()
                .any(|message| message.contains("the environment still lets this through")),
            "{messages:?}"
        );
    }

    #[tokio::test]
    async fn sighup_triggers_a_manual_reload_through_the_handle() {
        let h = Fixture::new(CONFIG, &roster_yaml(3));
        let stats = h.stats.clone();
        let (handle, _task) = spawn(h.reloader);
        tokio::spawn(sighup_loop(handle).unwrap());

        nix::sys::signal::raise(nix::sys::signal::Signal::SIGHUP).unwrap();

        tokio::time::timeout(Duration::from_secs(1), stats.reloaded.notified())
            .await
            .expect("no reload within a second of the signal");
        assert_eq!(stats.first().trigger, Trigger::Manual);
    }

    #[test]
    fn reload_publishes_the_new_publish_rate_limits() {
        let mut h = Fixture::new(CONFIG, &roster_yaml(3));
        h.write_config(
            "overlay:\n  roster_file: ROSTER\nbn:\n  publish_rate_limit:\n    small_per_s: 100\n    large_per_s: 20\ninject: true\n",
        );

        let report = h.reloader.reload(Trigger::Manual);

        assert_eq!(
            report.applied,
            [
                "bn.publish_rate_limit.large_per_s",
                "bn.publish_rate_limit.small_per_s"
            ]
        );
        assert!(report.error.is_none(), "{report:?}");
        let limits = h.limits.borrow_and_update();
        assert_eq!((limits.small_per_s, limits.large_per_s), (100, 20));
    }

    /// The two `classes.small` keys reach the batcher (T-062) the way the publish ceilings
    /// reach the publisher: one applier for the section, because the batcher takes both bounds
    /// together and a file that changed one should not rebuild it twice.
    #[test]
    fn reload_publishes_the_new_small_class_bounds() {
        let mut h = Fixture::new(CONFIG, &roster_yaml(3));
        h.write_config(
            "overlay:\n  roster_file: ROSTER\nclasses:\n  small:\n    batch_window_ms: 25\n    stale_after_ms: 750\ninject: true\n",
        );

        let report = h.reloader.reload(Trigger::Manual);

        assert_eq!(
            report.applied,
            [
                "classes.small.batch_window_ms",
                "classes.small.stale_after_ms"
            ]
        );
        assert!(report.error.is_none(), "{report:?}");
        let small = h.small.borrow_and_update();
        assert_eq!(
            (small.batch_window, small.stale_after),
            (Duration::from_millis(25), Duration::from_millis(750))
        );
    }

    /// The three `overlay.fanout.small` keys reach the router (T-063), one applier for the
    /// three: the plan is decided from all of them at once, and a file that changed two should
    /// not rebuild it twice. `large` is left where the running process has it, because its keys
    /// need a restart and an applier that took the whole section would apply them anyway.
    #[test]
    fn reload_publishes_the_new_relay_settings() {
        let mut h = Fixture::new(CONFIG, &roster_yaml(3));
        h.write_config(
            "overlay:\n  roster_file: ROSTER\n  fanout:\n    small:\n      cross_region: direct\n      relays_per_remote_region: 5\n      relay_min_remote_hosts: 6\ninject: true\n",
        );

        let report = h.reloader.reload(Trigger::Manual);

        assert_eq!(
            report.applied,
            [
                "overlay.fanout.small.cross_region",
                "overlay.fanout.small.relay_min_remote_hosts",
                "overlay.fanout.small.relays_per_remote_region"
            ]
        );
        assert!(report.error.is_none(), "{report:?}");
        let fanout = h.fanout.borrow_and_update();
        assert_eq!(fanout.small.cross_region, SmallCrossRegion::Direct);
        assert_eq!(fanout.small.relays_per_remote_region, 5);
        assert_eq!(fanout.small.relay_min_remote_hosts, 6);
        assert_eq!(fanout.large, LargeFanout::default());
    }

    /// `stripe_min_recipients` reaches the same router (T-072), so an operator whose regions
    /// turn out to be the wrong side of the threshold moves it without a restart. The two keys
    /// beside it in `overlay.fanout.large` still need one, which is why this applier composes a
    /// fanout rather than sending the section as it stands.
    #[test]
    fn reload_publishes_the_new_stripe_threshold() {
        let mut h = Fixture::new(CONFIG, &roster_yaml(3));
        h.write_config(
            "overlay:\n  roster_file: ROSTER\n  fanout:\n    large:\n      stripe_min_recipients: 4\ninject: true\n",
        );

        let report = h.reloader.reload(Trigger::Manual);

        assert_eq!(
            report.applied,
            ["overlay.fanout.large.stripe_min_recipients"]
        );
        assert!(report.error.is_none(), "{report:?}");
        let fanout = h.fanout.borrow_and_update();
        assert_eq!(fanout.large.stripe_min_recipients, 4);
        assert_eq!(fanout.large.in_region, LargeFanout::default().in_region);
        assert_eq!(
            fanout.large.cross_region,
            LargeFanout::default().cross_region
        );
    }

    /// The one line an operator reads after a reload, as JSON so the fields can be asserted by
    /// name rather than by matching a rendered string.
    fn line(sink: &Sink, at: usize) -> Map<String, Value> {
        sink.objects()[at].clone()
    }

    #[test]
    fn the_reload_line_names_the_trigger_and_the_keys() {
        let (mut h, sink, dispatch) = Fixture::with_log(
            "overlay:\n  roster_file: ROSTER\n  listen: \"[::]:7788\"\ninject: true\n",
            &roster_yaml(3),
            &Log::default(),
            None,
        );
        h.write_config("overlay:\n  roster_file: ROSTER\n  listen: \"[::]:9999\"\ninject: false\n");

        tracing::dispatcher::with_default(&dispatch, || {
            h.reloader.reload(Trigger::Manual);
        });

        let line = line(&sink, 0);
        assert_eq!(line["level"], "INFO");
        assert_eq!(line["trigger"], "manual");
        assert_eq!(line["applied"], "inject");
        assert_eq!(line["restart_required"], "overlay.listen");
    }

    #[test]
    fn a_rejected_roster_logs_both_host_counts_at_warn() {
        let (mut h, sink, dispatch) =
            Fixture::with_log(CONFIG, &roster_yaml(10), &Log::default(), None);
        h.write_roster(&roster_yaml(4));

        tracing::dispatcher::with_default(&dispatch, || {
            h.reloader.reload(Trigger::Automatic);
        });

        let line = line(&sink, 0);
        assert_eq!(line["level"], "WARN");
        assert_eq!(line["trigger"], "automatic");
        let error = line["error"].to_string();
        assert!(error.contains("10") && error.contains('4'), "{error}");
    }

    #[test]
    fn no_reloadable_key_has_two_appliers() {
        let h = Fixture::new(CONFIG, &roster_yaml(3));

        for path in RELOADABLE {
            let owners = h
                .reloader
                .appliers
                .iter()
                .filter(|(key, _)| covers(key, path))
                .count();
            assert!(owners <= 1, "{path} is applied by {owners} appliers");
        }
    }

    /// The roster file watcher (T-086) over T-043's real reloader, on a paused clock.
    mod watcher {
        use std::sync::atomic::AtomicU64;

        use super::*;

        /// A watcher polling a roster file in a temp directory, holding everything a test
        /// asserts on: the roster the reload publishes, the reports it recorded, and the handle
        /// a manual reload goes through.
        struct Watched {
            _dir: TempDir,
            roster_path: PathBuf,
            roster: watch::Receiver<Roster>,
            stats: Arc<Recorded>,
            handle: ReloadHandle,
            _tasks: Vec<JoinHandle<()>>,
        }

        impl Watched {
            /// A fleet of `hosts` hosts, with the watcher already polling its roster file.
            async fn start(hosts: usize) -> Self {
                let f = Fixture::new(CONFIG, &roster_yaml(hosts));
                let (roster_path, roster, stats) =
                    (f.roster_path.clone(), f.roster.clone(), f.stats.clone());
                let (handle, reloads) = spawn(f.reloader);
                let watcher =
                    tokio::spawn(RosterWatcher::new(roster_path.clone(), handle.clone()).run());
                let watched = Self {
                    _dir: f._dir,
                    roster_path,
                    roster,
                    stats,
                    handle,
                    _tasks: vec![reloads, watcher],
                };
                watched.settle().await;
                watched
            }

            fn write(&self, roster: &str) {
                fs::write(&self.roster_path, roster).unwrap();
            }

            /// The next poll, and whatever it does. The clock is paused, so the interval only
            /// comes round when a test says so, and the yields are every task reaching its next
            /// await, which is when the poll has finished.
            async fn poll(&self) {
                tokio::time::advance(ROSTER_POLL_INTERVAL).await;
                self.settle().await;
            }

            async fn settle(&self) {
                for _ in 0..16 {
                    tokio::task::yield_now().await;
                }
            }
        }

        #[tokio::test(start_paused = true)]
        async fn changed_mtime_triggers_an_automatic_reload_on_the_next_poll() {
            let mut h = Watched::start(3).await;
            h.write(&roster_yaml(4));

            h.poll().await;

            let report = h.stats.last();
            assert_eq!(report.trigger, Trigger::Automatic);
            assert_eq!(report.applied, ["roster"]);
            let published = h.roster.borrow_and_update();
            assert_eq!(published.hosts.len(), 4);
            assert_eq!(published.hosts[3].hostname, Hostname("bn-4".to_owned()));
        }

        #[tokio::test(start_paused = true)]
        async fn unchanged_file_does_not_reload() {
            let h = Watched::start(3).await;

            h.poll().await;
            h.poll().await;

            assert_eq!(h.stats.count(), 0);
        }

        #[tokio::test(start_paused = true)]
        async fn missing_or_unparseable_file_keeps_the_current_roster_and_the_next_poll_recovers() {
            let mut h = Watched::start(3).await;
            fs::remove_file(&h.roster_path).unwrap();

            h.poll().await;

            assert_eq!(h.stats.count(), 0, "a file that is gone is not a reload");
            assert_eq!(h.roster.borrow_and_update().hosts.len(), 3);

            h.write("hosts:\n  - hostname: bn-1\n    region: eu\n    addr: \"not one\"\n");
            h.poll().await;

            let report = h.stats.last();
            assert!(
                matches!(report.error, Some(ReloadError::Roster(_))),
                "{report:?}"
            );
            assert_eq!(h.roster.borrow_and_update().hosts.len(), 3);

            h.write(&roster_yaml(4));
            h.poll().await;

            assert_eq!(h.stats.last().applied, ["roster"]);
            assert_eq!(h.roster.borrow_and_update().hosts.len(), 4);
        }

        #[tokio::test(start_paused = true)]
        async fn automatic_reload_removing_more_than_half_the_hosts_is_rejected_and_counted() {
            let mut h = Watched::start(8).await;
            h.write(&roster_yaml(3));

            h.poll().await;

            assert_eq!(
                h.stats.last().error,
                Some(ReloadError::RosterShrinkRejected {
                    before: 8,
                    after: 3
                })
            );
            assert_eq!(h.stats.rejected(), 1);
            assert!(!h.roster.has_changed().unwrap(), "the roster was published");
            assert_eq!(h.roster.borrow_and_update().hosts.len(), 8);
        }

        #[tokio::test(start_paused = true)]
        async fn automatic_reload_removing_exactly_half_is_applied() {
            let mut h = Watched::start(8).await;
            h.write(&roster_yaml(4));

            h.poll().await;

            let report = h.stats.last();
            assert_eq!(report.applied, ["roster"]);
            assert!(report.error.is_none(), "{report:?}");
            assert_eq!(h.stats.rejected(), 0);
            assert_eq!(h.roster.borrow_and_update().hosts.len(), 4);
        }

        #[tokio::test(start_paused = true)]
        async fn manual_reload_of_the_same_shrinking_roster_applies() {
            let mut h = Watched::start(8).await;
            h.write(&roster_yaml(3));
            h.poll().await;
            assert_eq!(h.stats.rejected(), 1);

            let report = h.handle.reload(Trigger::Manual).await.unwrap();

            assert_eq!(report.applied, ["roster"]);
            assert!(report.error.is_none(), "{report:?}");
            assert_eq!(h.roster.borrow_and_update().hosts.len(), 3);
        }

        /// A stand-in for T-023's connection manager: one connection per roster host, opened
        /// when the host appears and abandoned when it goes, which is what `manager::reconcile`
        /// does with a dial task. Each connection is numbered, so a test can tell one that
        /// stayed up from one that was replaced.
        #[derive(Default)]
        struct FakeManager {
            connections: Mutex<BTreeMap<Hostname, u64>>,
            opened: AtomicU64,
        }

        impl FakeManager {
            /// Follows the roster a reload publishes, for as long as the reloader owns it.
            fn follow(self: &Arc<Self>, mut roster: watch::Receiver<Roster>) -> JoinHandle<()> {
                let manager = self.clone();
                tokio::spawn(async move {
                    loop {
                        manager.reconcile(&roster.borrow_and_update());
                        if roster.changed().await.is_err() {
                            return;
                        }
                    }
                })
            }

            fn reconcile(&self, roster: &Roster) {
                let mut connections = self.connections.lock().unwrap();
                connections.retain(|host, _| roster.get(host).is_some());
                for host in &roster.hosts {
                    connections
                        .entry(host.hostname.clone())
                        .or_insert_with(|| self.opened.fetch_add(1, Ordering::Relaxed));
                }
            }

            /// The connection held to `host`, if there is one.
            fn connection(&self, host: &str) -> Option<u64> {
                self.connections
                    .lock()
                    .unwrap()
                    .get(&Hostname(host.to_owned()))
                    .copied()
            }
        }

        #[tokio::test(start_paused = true)]
        async fn automatic_reload_adds_hosts_without_dropping_existing_connections() {
            let h = Watched::start(2).await;
            let manager = Arc::new(FakeManager::default());
            let _task = manager.follow(h.roster.clone());
            h.settle().await;
            let before = manager
                .connection("bn-2")
                .expect("bn-2 was never connected");

            h.write(&roster_yaml(4));
            h.poll().await;

            assert_eq!(h.stats.last().applied, ["roster"]);
            assert_eq!(
                manager.connection("bn-2"),
                Some(before),
                "the reload replaced a connection it did not have to"
            );
            assert!(manager.connection("bn-4").is_some(), "bn-4 was not dialled");
        }
    }
}
