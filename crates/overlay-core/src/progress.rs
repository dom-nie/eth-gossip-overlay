//! How a core loop tells the systemd watchdog it is still going round (OPS-N5).
//!
//! Four loops carry a progress counter: the connection manager, the beacon node link, the
//! fanout task and the publisher. Each bumps it at the top of every iteration with a plain
//! `fetch_add(1, Relaxed)` on an `Arc<AtomicU64>` the wiring hands it, and each has a tick arm
//! at [`PROGRESS_TICK`] so an idle fleet still advances all four. The watchdog kicks only when
//! every one of them has moved since the last kick, so a loop that stops going round starves it
//! and systemd restarts the process.
//!
//! The counter is the whole contract, which is why it is a bare atomic rather than a type: the
//! crates that own the loops know nothing about systemd, and `fleet-overlay` is where the four
//! are read together.

use std::time::Duration;

/// How often a core loop wakes to go round when nothing else has happened.
///
/// It has to be well inside the kick interval, which is a third of `WatchdogSec`, or an idle
/// process would miss kicks it should have made. `WatchdogSec=30` kicks every ten seconds and
/// this leaves two hundred ticks of margin, at four timers per process, which is a rounding
/// error against one QUIC keepalive per peer per second.
pub const PROGRESS_TICK: Duration = Duration::from_millis(50);
