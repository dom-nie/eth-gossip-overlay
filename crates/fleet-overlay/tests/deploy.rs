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

/// Whether the file sets exactly this directive on a line of its own, so a mention in a comment
/// never stands in for the real thing.
fn has_directive(text: &str, directive: &str) -> bool {
    text.lines().any(|line| line.trim() == directive)
}

/// OPS-N5: the sidecar reports ready once its admin socket answers and feeds the watchdog only
/// while all four core loops go round, so systemd restarts a wedged process. The backoff then
/// stretches a crash loop out to a minute, and no start limit ever stops the unit for good.
#[test]
fn unit_has_notify_watchdog_and_restart_backoff_directives() {
    let text = read(UNIT);

    for directive in [
        "Type=notify",
        "NotifyAccess=main",
        "WatchdogSec=30",
        "Restart=always",
        "RestartSec=2",
        "RestartSteps=6",
        "RestartMaxDelaySec=60",
        "StartLimitIntervalSec=0",
    ] {
        assert!(
            has_directive(&text, directive),
            "{UNIT} is missing {directive}"
        );
    }
}
