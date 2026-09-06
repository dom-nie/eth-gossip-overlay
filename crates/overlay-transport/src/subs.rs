//! Telling every live peer what this host's beacon node wants, and keeping what each of them
//! says it wants.

use std::sync::{Mutex, MutexGuard};

use overlay_core::subs::PeerState;

/// A peer's state, recovering the guard from a poisoned lock rather than propagating the panic.
/// Nothing between a lock and its release can panic, so the state is whole; refusing to answer
/// for every other peer because one task died holding this one would take the overlay down for
/// an unrelated reason.
pub(crate) fn state(peer: &Mutex<PeerState>) -> MutexGuard<'_, PeerState> {
    peer.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}
