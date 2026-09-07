//! The deployment examples under `deploy/`. They are text files an operator copies into their
//! own configuration management, so the tests are lint-style checks that read them from the
//! repository and hold them to what the sidecar and the two systemd units actually need.

use std::path::{Path, PathBuf};

const UNIT: &str = "deploy/systemd/fleet-overlay.service";
const DROP_IN: &str = "deploy/systemd/lighthouse-bn.service.d/10-fleet-overlay-trusted-peer.conf";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(relative: &str) -> String {
    let path = workspace_root().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

/// §5.7 and OPS-N1: the two units order each other and nothing else. A `BindsTo=`, `PartOf=` or
/// `Requires=` in either direction would let a sidecar restart take the beacon node with it,
/// which is the one thing the split into two units exists to prevent.
#[test]
fn unit_files_have_no_binding_directives() {
    for file in [UNIT, DROP_IN] {
        let text = read(file);
        for directive in ["BindsTo", "PartOf", "Requires"] {
            assert!(!text.contains(directive), "{file} has {directive}=");
        }
    }
}
