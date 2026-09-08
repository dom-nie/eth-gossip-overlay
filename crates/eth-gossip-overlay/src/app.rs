//! The wiring: every component the earlier tickets built, assembled into a running sidecar.
//!
//! Startup order is the whole point of this module and §11 fixes it. The configuration is
//! parsed by the caller, because a parse error is the one failure that has to be reported
//! before a subscriber exists. Everything after it happens here, in this order and no other:
//!
//! 1. the roster, this host's identity in it, the fleet seed and the node key, which is
//!    everything read off disk;
//! 2. `lighthouse.env`, written before anything binds so a beacon node starting alongside the
//!    sidecar finds the flags it needs (OPS-N1, MD-01);
//! 3. the memory budget, logged against the cgroup ceiling (OPS-N4);
//! 4. the metrics registry, so every component after it registers on one registry;
//! 5. the seen cache, the beacon node link and the publisher;
//! 6. the overlay endpoint and the connection manager, which are the two binds that can fail;
//! 7. the fanout task and the per-peer receivers;
//! 8. the reload task and the admin socket, which is what readiness means (OPS-N5).
//!
//! `App::run` then waits for its shutdown future, tells systemd it is stopping, cancels every
//! task and joins them under a deadline. What a task holds is a connection that is already
//! closing, so the join is a courtesy and the deadline is what makes it one.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use overlay_bn::bn_http::BnClient;
use overlay_bn::compat;
use overlay_bn::inbound::Inbound;
use overlay_bn::link::{self, BnCommand, BnEvent, BnLink, LinkConfig};
use overlay_bn::mirror;
use overlay_bn::node_key::NodeKey;
use overlay_bn::publish::Publisher;
use overlay_bn::spec::spec_watch;
use overlay_core::budget::{self, FanoutBudget, MemoryBudget, SendLaneBounds};
use overlay_core::config::Config;
use overlay_core::identity::{Seeds, derive_tls_keypair};
use overlay_core::lanes::ClassLanes;
use overlay_core::reassemble::{ReassembleConfig, Reassembler};
use overlay_core::recent::{RECENT_MAX_BYTES, RECENT_TTL, RecentLarge, SharedRecentLarge};
use overlay_core::roster::{Hostname, Roster, SelfIdentity, resolve_self};
use overlay_core::seen::{SEEN_CAPACITY, SEEN_TTL, SeenCache, SharedSeenCache};
use overlay_core::time::SystemClock;
use overlay_core::topic::SubscriptionSets;
use overlay_transport::batching::Batching;
use overlay_transport::endpoint;
use overlay_transport::fanout::Fanout;
use overlay_transport::hello::{HelloAdmission, OwnTopics, SelfHello};
use overlay_transport::manager::{ConnectionManager, Handle, Local, PeerEvent};
use overlay_transport::receive::{Deps as ReceiveDeps, PeerReceiver, Relaying};
use overlay_transport::sender::{
    self, LARGE_LANE_BYTES, LARGE_QUEUED_BYTES_MAX, LargeLedger, SMALL_LANE_FRAMES,
};
use overlay_transport::subs;
use overlay_transport::tls::{self, PinTable};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::admin;
use crate::lifecycle::{Notify, Progress, TrustedPeerEnv, Watchdog};
use crate::logging::LogHandle;
use crate::metrics::{self, BnInbound, Metrics};
use crate::reload::{self, Reloader};

/// How long the beacon node's HTTP API has to answer. On localhost this is generous, and a
/// beacon node slower than this is one the link should give up on and come back to.
const BN_HTTP_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a shutdown has before the process exits anyway (§11's two seconds). Whatever is
/// still running past it holds a connection that is already closed.
pub const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(2);

/// Commands the swarm loop has not drained yet. It never waits on anything, so this only has to
/// hold the burst a fork boundary's subscriptions make.
const COMMAND_QUEUE: usize = 1024;

/// Peer events the exchange has not drained yet. One `Up` and one `Down` per peer per
/// reconnect, so a full roster reconnecting at once fits with room to spare.
const PEER_EVENT_QUEUE: usize = 256;

/// The per-peer send-lane bounds the memory budget is computed from (T-033). They live in
/// `overlay-transport`, which `overlay-core` must not depend on, so the wiring is what brings
/// the two together. Public so that the generator behind `docs/performance.md` states the
/// budget at the same bounds a running sidecar does.
pub const SEND_LANES: SendLaneBounds = SendLaneBounds {
    small_frames: SMALL_LANE_FRAMES,
    large_bytes: LARGE_LANE_BYTES,
    large_bytes_max: LARGE_QUEUED_BYTES_MAX,
};

/// Anything that stops the sidecar from starting. Every variant's message names the file or the
/// address an operator has to fix, because one line on stderr is all a failed start prints.
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    /// The roster could not be read, or this host is not in it.
    #[error(transparent)]
    Roster(#[from] overlay_core::roster::RosterError),
    /// The fleet seed or the node key could not be read or created.
    #[error(transparent)]
    Secret(#[from] overlay_core::identity::SecretFileError),
    /// The TLS identity could not be derived from the seed.
    #[error(transparent)]
    Tls(#[from] tls::TlsError),
    /// `bn.libp2p_addr` or `bn.listen_addr` is not a multiaddress.
    #[error("bn.libp2p_addr or bn.listen_addr: {0}")]
    BnAddress(String),
    /// The overlay endpoint could not bind `overlay.listen`.
    #[error(transparent)]
    Endpoint(#[from] endpoint::EndpointError),
    /// A §12 metric could not be registered, which is a programming error rather than an
    /// operator's.
    #[error("metrics registry: {0}")]
    Registry(#[from] prometheus::Error),
    /// The metrics endpoint or the admin socket could not bind.
    #[error("{what}: {source}")]
    Bind {
        /// The address or path that could not be bound.
        what: String,
        /// What the kernel said.
        source: std::io::Error,
    },
    /// `config.yaml` could not be read again for the reload task.
    #[error(transparent)]
    Reload(#[from] reload::ReloadError),
}

/// This host's name, from `ETH_GOSSIP_OVERLAY_HOSTNAME` or the kernel. `overlay-core` never reads
/// either, so the binary is where the two meet (T-003).
fn hostname() -> String {
    nix::unistd::gethostname()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Everything the sidecar reads off disk, in the order §11 reads it: the roster, who this host
/// is in it, the fleet seed and the libp2p node key.
///
/// `check-config` runs exactly this and stops, which is what makes it a rehearsal of a start
/// rather than a second implementation of one.
pub struct Identity {
    /// The roster in force.
    pub roster: Roster,
    /// Which roster host this process is.
    pub self_id: SelfIdentity,
    /// The seed in force and, during a rotation, the outgoing one (DX-N2).
    pub seeds: Seeds,
    /// The libp2p key the beacon node trusts (D01).
    pub node_key: NodeKey,
}

impl Identity {
    /// Reads all four, creating the node key on first start.
    pub fn load(cfg: &Config) -> Result<Self, StartupError> {
        let roster = Roster::load(&cfg.overlay.roster_file)?;
        let self_id = resolve_self(&roster, &|key| std::env::var(key).ok(), &hostname)?;
        let seeds = Seeds::load(
            &cfg.overlay.fleet_seed_file,
            cfg.overlay.fleet_seed_previous_file.as_deref(),
        )?;
        let node_key = NodeKey::load_or_create(&cfg.bn.node_key_file)?;
        Ok(Self {
            roster,
            self_id,
            seeds,
            node_key,
        })
    }
}

/// What `check-config` prints: the identity a start would run under and the memory budget it
/// would log, from the same code a start uses.
pub fn check_config(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let cfg = Config::load(path)?;
    let me = Identity::load(&cfg)?;
    // Deriving the key is the check: a seed that reads as 32 bytes but cannot make a keypair
    // would otherwise only fail at the first handshake.
    tls::identity(&derive_tls_keypair(&me.seeds.current, &me.self_id.hostname))?;
    let budget = MemoryBudget::compute(
        &cfg,
        me.roster.hosts.len(),
        budget::memory_max(),
        SEND_LANES,
    );
    Ok(format!(
        "hostname: {}\nregion: {}\nsite: {}\npeer id: {}\nroster: {} {}\nmemory budget: {} \
         ({} in bounded structures plus {}% headroom)\n",
        me.self_id.hostname,
        me.self_id.region,
        me.self_id.site.as_deref().unwrap_or("none"),
        me.node_key.peer_id(),
        me.roster.hosts.len(),
        if me.roster.hosts.len() == 1 {
            "host"
        } else {
            "hosts"
        },
        mib(budget.total_bytes),
        mib(budget.bounded_bytes),
        budget::HEADROOM_PERCENT,
    ))
}

/// Bytes as whole mebibytes, which is the unit `MemoryMax` is written in.
fn mib(bytes: u64) -> String {
    format!("{} MiB", bytes.div_ceil(1024 * 1024))
}

/// A running sidecar: every task the wiring started, and what is needed to stop them.
///
/// The tasks are held rather than detached because a shutdown has to be able to end them, and
/// the log handle is held because the writer's worker thread lives as long as it does: dropping
/// the app last is what flushes the lines still in flight.
pub struct App {
    notify: Notify,
    progress: Progress,
    manager: Handle,
    /// The swarm task, stopped last: every other task holds a command sender, and the link's
    /// loop ends when the last one is dropped, which is the swarm's cue to disconnect.
    link: JoinHandle<()>,
    tasks: Vec<JoinHandle<()>>,
    commands: mpsc::Sender<BnCommand>,
    /// True once a shutdown has begun, which is what the watchdog task waits on.
    stop: watch::Sender<bool>,
    _log: Arc<LogHandle>,
}

impl App {
    /// Wires every component together in §11's order and leaves it running.
    ///
    /// The configuration is already parsed, because a parse error has to be reported before a
    /// subscriber exists; `log` is the subscriber that parse then installed.
    pub async fn build(
        config_path: PathBuf,
        cfg: Config,
        log: Arc<LogHandle>,
    ) -> Result<Self, StartupError> {
        let me = Identity::load(&cfg)?;
        let peer_id = me.node_key.peer_id();
        tracing::info!(
            hostname = %me.self_id.hostname,
            region = %me.self_id.region,
            site = me.self_id.site.as_deref().unwrap_or_default(),
            %peer_id,
            roster = me.roster.hosts.len(),
            "identity resolved"
        );

        let link_cfg = LinkConfig::from_config(&cfg.bn)
            .map_err(|err| StartupError::BnAddress(err.to_string()))?;
        write_trusted_peer_env(&link::lighthouse_env_line(&peer_id, &link_cfg.listen_addr));

        let budget = MemoryBudget::compute(
            &cfg,
            me.roster.hosts.len(),
            budget::memory_max(),
            SEND_LANES,
        );
        budget::check(&budget);

        let registry = prometheus::Registry::new();
        let metrics = Arc::new(Metrics::new(&registry)?);
        let gossipsub = Arc::new(Mutex::new(prometheus_client::registry::Registry::default()));
        let (metrics_bound, metrics_task) =
            metrics::serve(cfg.metrics_listen, registry, gossipsub.clone())
                .await
                .map_err(|source| StartupError::Bind {
                    what: format!("metrics_listen {}", cfg.metrics_listen),
                    source,
                })?;
        tracing::info!(addr = %metrics_bound, "metrics endpoint bound");

        let clock = Arc::new(SystemClock);
        let seen = SharedSeenCache::new(
            SeenCache::new(SEEN_TTL, SEEN_CAPACITY, clock.clone()).with_stats(metrics.clone()),
        );
        tracing::info!(
            ttl_secs = SEEN_TTL.as_secs(),
            capacity = SEEN_CAPACITY,
            "seen cache ready"
        );
        // What a repair request is answered from, filled by the beacon node link and by the
        // reassembler, which is why both are handed the one handle (§5.6).
        let recent = SharedRecentLarge::new(RecentLarge::new(RECENT_TTL, RECENT_MAX_BYTES));

        let progress = Progress::default();
        let (spec_tx, spec_rx) = spec_watch();
        let (sets_tx, sets_rx) = watch::channel(SubscriptionSets::default());
        let (commands, commands_rx) = mpsc::channel(COMMAND_QUEUE);
        let bn_lanes = ClassLanes::new(metrics.clone());
        let link = BnLink::spawn(
            link_cfg,
            &me.node_key,
            BnClient::new(cfg.bn.identity_url.clone(), BN_HTTP_TIMEOUT),
            &mut lock(&gossipsub),
            bn_lanes.pusher(),
            spec_tx,
            sets_rx.clone(),
            commands_rx,
            progress.bn_link.clone(),
        );
        let bn_connected = link.connected.clone();
        // One consumer may hold the link's events, and both halves of the beacon node's state
        // need them: the mirror turns subscriptions into commands, the watch reads `BnInfo`.
        let (to_mirror, mirror_events) = mpsc::channel(link::CONTROL_CHANNEL_CAPACITY);
        let (to_compat, compat_events) = mpsc::channel(link::CONTROL_CHANNEL_CAPACITY);
        let fan = tokio::spawn(fan_bn_events(
            link.events,
            to_mirror,
            to_compat,
            metrics.clone(),
        ));
        let mirror = mirror::run(mirror_events, commands.clone(), sets_tx, spec_rx.clone());
        let (compat, bn_info) =
            compat::Watch::spawn(compat_events, spec_rx.clone(), metrics.clone());
        tracing::info!(url = %cfg.bn.identity_url, "beacon node link started");

        let inject = Arc::new(AtomicBool::new(cfg.inject));
        let (limits_tx, limits_rx) = watch::channel(cfg.bn.publish_rate_limit.clone());
        let (publish, publisher) = Publisher::spawn(
            commands.clone(),
            inject.clone(),
            limits_rx,
            metrics.clone(),
            clock.clone(),
            progress.publisher.clone(),
        );
        let node = Arc::new(me.self_id.clone());
        let fanout_lanes = ClassLanes::new(metrics.clone());
        let inbound = Inbound::spawn(
            bn_lanes,
            commands.clone(),
            seen.clone(),
            recent.clone(),
            fanout_lanes.pusher(),
            node.clone(),
            clock.clone(),
            Arc::new(BnInbound(metrics.clone())),
        );

        let pins = Arc::new(ArcSwap::from_pointee(PinTable::build(
            &me.roster, &me.seeds,
        )));
        let own_key = derive_tls_keypair(&me.seeds.current, &me.self_id.hostname);
        let endpoint = endpoint::bind(
            &cfg.overlay,
            budget.receive_window,
            tls::server_config(pins.clone(), &own_key)?,
        )?;
        tracing::info!(listen = %cfg.overlay.listen, "overlay endpoint bound");

        let (roster_tx, _) = watch::channel(me.roster.clone());
        let (peer_events, peer_events_rx) = mpsc::channel(PEER_EVENT_QUEUE);
        let topics = Arc::new(Mutex::new(OwnTopics::default()));
        let manager = ConnectionManager::spawn(
            Local {
                cfg: cfg.overlay.clone(),
                receive_window: budget.receive_window,
                self_id: me.self_id.clone(),
                pins: pins.clone(),
                own_key,
            },
            endpoint,
            roster_tx.subscribe(),
            HelloAdmission::new(SelfHello::new(&me.self_id), topics.clone(), metrics.clone()),
            peer_events,
            metrics.clone(),
            sender::Deps {
                ledger: Arc::new(LargeLedger::new(LARGE_QUEUED_BYTES_MAX)),
                stats: metrics.clone(),
            },
            progress.connection_manager.clone(),
        );
        tracing::info!(
            peers = me.roster.hosts.len() - 1,
            "connection manager started"
        );

        let (small_tx, small_rx) = watch::channel(cfg.classes.small.clone());
        let (fanout_tx, fanout_rx) = watch::channel(cfg.overlay.fanout.clone());
        let (batches, batching) = Batching::spawn(small_rx, metrics.clone());
        let (to_exchange, exchanged) = mpsc::channel(PEER_EVENT_QUEUE);
        let receivers = tokio::spawn(receive_peers(
            peer_events_rx,
            to_exchange,
            ReceiveDeps {
                seen,
                recent,
                publish: Arc::new(publish),
                sets: sets_rx.clone(),
                reassembler: Arc::new(
                    Reassembler::new(ReassembleConfig::default()).with_stats(metrics.clone()),
                ),
                stats: metrics.clone(),
                node,
                clock,
                budget: FanoutBudget::default_for(
                    me.roster.hosts.len(),
                    cfg.classes.large.chunk_bytes,
                    spec_rx.borrow().seconds_per_slot,
                    Instant::now(),
                ),
                // The second hop a relay makes, handed over rather than reached for: one hop is
                // structural everywhere else on this path (D20, T-063).
                relaying: Relaying {
                    live: manager.live_source(),
                    topics: topics.clone(),
                    batches: batches.clone(),
                },
            },
        ));
        let exchange = subs::spawn(exchanged, sets_rx.clone(), topics.clone(), metrics.clone());
        let fanout = Fanout::spawn(
            fanout_lanes,
            manager.live_source(),
            me.self_id.clone(),
            fanout_rx,
            topics,
            batches,
            metrics.clone(),
            cfg.classes.large.clone(),
            progress.fanout.clone(),
        );
        tracing::info!("fanout and overlay receive path started");

        let (previous_seed_tx, previous_seed_rx) = watch::channel(None);
        let pin_table = reload::spawn_pin_table(
            pins,
            me.seeds.current,
            roster_tx.subscribe(),
            previous_seed_rx,
        );
        let admin_roster = roster_tx.subscribe();
        let (reload, reload_task) = reload::spawn(Reloader::new(
            config_path,
            reload::Deps {
                inject: inject.clone(),
                roster: roster_tx,
                previous_seed: previous_seed_tx,
                limits: limits_tx,
                small: small_tx,
                fanout: fanout_tx,
                log: log.clone(),
                stats: metrics.clone(),
            },
        )?);
        let hangups = tokio::spawn(reload::sighup_loop(reload.clone()).map_err(|source| {
            StartupError::Bind {
                what: "SIGHUP handler".to_owned(),
                source,
            }
        })?);
        let admin = admin::serve(
            &cfg.admin_socket,
            admin::State {
                self_id: me.self_id,
                inject,
                live: manager.live_source(),
                bn_connected,
                bn: bn_info,
                subscriptions: sets_rx,
                roster: admin_roster,
                reload,
            },
        )
        .map_err(|source| StartupError::Bind {
            what: format!("admin_socket {}", cfg.admin_socket.display()),
            source,
        })?;
        tracing::info!(path = %cfg.admin_socket.display(), "admin socket bound");

        Ok(Self {
            notify: Notify::new(),
            progress,
            manager,
            link: link.task,
            tasks: vec![
                metrics_task,
                fan,
                mirror,
                compat,
                publisher,
                inbound,
                receivers,
                exchange,
                fanout,
                batching,
                pin_table,
                reload_task,
                hangups,
                admin,
            ],
            commands,
            stop: watch::channel(false).0,
            _log: log,
        })
    }

    /// Reports readiness, then runs until `shutdown` resolves and stops everything.
    ///
    /// Readiness is sent here rather than in [`build`](Self::build) because the admin socket is
    /// bound by the time build returns, which is exactly what `READY=1` promises (OPS-N5).
    pub async fn run(self, shutdown: impl Future<Output = ()>) {
        self.notify.ready();
        tracing::info!("ready");
        let watchdog = self.spawn_watchdog();

        shutdown.await;
        tracing::info!("shutting down");
        if let Some(watchdog) = watchdog {
            watchdog.abort();
        }
        if tokio::time::timeout(SHUTDOWN_DEADLINE, self.stop())
            .await
            .is_err()
        {
            tracing::warn!(
                deadline_ms = SHUTDOWN_DEADLINE.as_millis(),
                "shutdown deadline passed; exiting anyway"
            );
        }
    }

    /// The watchdog task, or nothing at all when systemd is not watching this process.
    fn spawn_watchdog(&self) -> Option<JoinHandle<()>> {
        let period = self.notify.watchdog_interval()?;
        tracing::info!(period_ms = period.as_millis(), "watchdog started");
        let mut watchdog = Watchdog::new(self.progress.clone());
        let notify = self.notify.clone();
        let mut stop = self.stop.subscribe();
        Some(tokio::spawn(async move {
            let mut tick = tokio::time::interval(period);
            loop {
                tokio::select! {
                    _ = stop.wait_for(|stop| *stop) => return,
                    _ = tick.tick() => {
                        if watchdog.kick_due() {
                            notify.watchdog();
                        }
                    }
                }
            }
        }))
    }

    /// `STOPPING=1`, then every task, then the connections.
    ///
    /// The order is what §9 asks for: the beacon node sees the sidecar go and its peer count
    /// drop by one, and every sibling gets a QUIC close with the `Shutdown` code rather than an
    /// idle timeout five seconds later.
    async fn stop(mut self) {
        self.notify.stopping();
        self.stop.send_replace(true);
        for task in self.tasks.drain(..) {
            task.abort();
            let _ = task.await;
        }
        // Every one of those tasks held a command sender; this is the last, and the swarm loop
        // ends when it goes.
        drop(self.commands);
        let _ = self.link.await;
        self.manager.shutdown().await;
    }
}

/// The `lighthouse.env` file, before anything binds. A failure is a warning: a container has no
/// `/run/eth-gossip-overlay` and a beacon node without the file simply starts without a trusted peer,
/// which `OverlayNotTrustedByBn` reports (OPS-N1).
fn write_trusted_peer_env(line: &str) {
    let dir = TrustedPeerEnv::directory();
    match TrustedPeerEnv::write(&dir, line) {
        Ok(path) => tracing::info!(path = %path.display(), "wrote the lighthouse env file"),
        Err(err) => tracing::warn!(
            %err,
            dir = %dir.display(),
            "no lighthouse env file; the beacon node will not trust or dial this sidecar"
        ),
    }
}

/// The link's events, to the mirror shell and the compatibility watch. The gauge rides along
/// because this task already sees every connect and disconnect the flag it mirrors follows.
async fn fan_bn_events(
    mut events: mpsc::Receiver<BnEvent>,
    mirror: mpsc::Sender<BnEvent>,
    compat: mpsc::Sender<BnEvent>,
    metrics: Arc<Metrics>,
) {
    while let Some(event) = events.recv().await {
        match event {
            BnEvent::Connected { .. } => metrics.set_bn_connected(true),
            BnEvent::Disconnected => metrics.set_bn_connected(false),
            _ => {}
        }
        if mirror.send(event.clone()).await.is_err() || compat.send(event).await.is_err() {
            return;
        }
    }
}

/// A receiver per live peer, then the event on to T-027's exchange, which owns the peer's
/// control stream. Both halves need the manager's events and only one consumer may hold them.
async fn receive_peers(
    mut events: mpsc::Receiver<PeerEvent>,
    exchange: mpsc::Sender<PeerEvent>,
    deps: ReceiveDeps,
) {
    let mut receivers: BTreeMap<Hostname, PeerReceiver> = BTreeMap::new();
    while let Some(event) = events.recv().await {
        match &event {
            PeerEvent::Up(peer) => {
                receivers.insert(
                    peer.hostname.clone(),
                    PeerReceiver::spawn(peer, deps.clone()),
                );
            }
            PeerEvent::Down(peer, _) => {
                receivers.remove(peer);
            }
        }
        if exchange.send(event).await.is_err() {
            return;
        }
    }
}

/// The gossipsub registry, recovering the guard from a poisoned lock: what it holds is a
/// registry of counters, which a panic elsewhere cannot have left half written.
fn lock<T>(held: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    held.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Builds the sidecar and runs it until `SIGTERM` or `SIGINT`.
///
/// `test_panic` is the hidden `--test-panic` flag: a task that panics the moment the wiring is
/// up, so one test can prove that a panicking task takes the process down. It waits for nothing
/// and sleeps for nothing, so what the test observes does not depend on how long a loaded
/// machine took to get here.
pub async fn serve(
    config_path: PathBuf,
    cfg: Config,
    log: Arc<LogHandle>,
    test_panic: bool,
) -> Result<(), StartupError> {
    let app = App::build(config_path, cfg, log).await?;
    if test_panic {
        tokio::spawn(async { panic!("--test-panic") });
    }
    let terminated = crate::lifecycle::terminated().map_err(|source| StartupError::Bind {
        what: "SIGTERM handler".to_owned(),
        source,
    })?;
    app.run(terminated).await;
    Ok(())
}
