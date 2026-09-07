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

use std::path::Path;

use overlay_bn::node_key::NodeKey;
use overlay_core::budget::{self, MemoryBudget, SendLaneBounds};
use overlay_core::config::Config;
use overlay_core::identity::{Seeds, derive_tls_keypair};
use overlay_core::roster::{Roster, SelfIdentity, resolve_self};
use overlay_transport::sender::{LARGE_LANE_BYTES, LARGE_QUEUED_BYTES_MAX, SMALL_LANE_FRAMES};
use overlay_transport::tls;

/// The per-peer send-lane bounds the memory budget is computed from (T-033). They live in
/// `overlay-transport`, which `overlay-core` must not depend on, so the wiring is what brings
/// the two together.
const SEND_LANES: SendLaneBounds = SendLaneBounds {
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
}

/// This host's name, from `FLEET_OVERLAY_HOSTNAME` or the kernel. `overlay-core` never reads
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
    let budget = MemoryBudget::compute(me.roster.hosts.len(), SEND_LANES);
    Ok(format!(
        "hostname: {}\nregion: {}\nsite: {}\npeer id: {}\nroster: {} hosts\nmemory budget: {} \
         ({} in bounded structures plus {}% headroom)\n",
        me.self_id.hostname,
        me.self_id.region,
        me.self_id.site.as_deref().unwrap_or("none"),
        me.node_key.peer_id(),
        me.roster.hosts.len(),
        mib(budget.total_bytes),
        mib(budget.bounded_bytes),
        budget::HEADROOM_PERCENT,
    ))
}

/// Bytes as whole mebibytes, which is the unit `MemoryMax` is written in.
fn mib(bytes: u64) -> String {
    format!("{} MiB", bytes.div_ceil(1024 * 1024))
}
