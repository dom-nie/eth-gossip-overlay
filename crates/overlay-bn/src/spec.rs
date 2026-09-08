//! The channel the sidecar's spec snapshot arrives on (CL-N3). The values themselves are
//! [`overlay_core::spec::SpecSnapshot`], because `overlay-core` sizes itself by them too.

pub use overlay_core::spec::SpecSnapshot;

use tokio::sync::watch;

/// The channel consumers read the snapshot from, seeded with mainnet so a value is there
/// before the beacon node has answered. The BN link keeps the sender.
pub fn spec_watch() -> (watch::Sender<SpecSnapshot>, watch::Receiver<SpecSnapshot>) {
    watch::channel(SpecSnapshot::MAINNET)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_watch_starts_at_mainnet_defaults() {
        let (_tx, rx) = spec_watch();

        assert_eq!(*rx.borrow(), SpecSnapshot::MAINNET);
    }
}
