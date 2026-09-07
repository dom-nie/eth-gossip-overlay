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

/// Whether the file sets `key` at all, on a line of its own. A commented-out line sets nothing,
/// which is how the unit can explain in place why a directive is missing.
fn sets(text: &str, key: &str) -> bool {
    text.lines()
        .any(|line| line.trim_start().starts_with(&format!("{key}=")))
}

/// §5.7: the sidecar gets a memory ceiling it was sized for and never a CPU quota, because CFS
/// throttling would stall a fanout in the middle of a block.
#[test]
fn unit_has_no_cpuquota_and_has_memorymax_512m() {
    let text = read(UNIT);

    assert!(
        has_directive(&text, "MemoryMax=512M"),
        "{UNIT} is missing MemoryMax=512M"
    );
    assert!(!sets(&text, "CPUQuota"), "{UNIT} sets a CPU quota");
}

/// The sandbox and the two directories systemd hands over: `/run/fleet-overlay` for the admin
/// socket and the `lighthouse.env` the drop-in reads, `/var/lib/fleet-overlay` for the node key
/// the beacon node's trust is pinned to.
#[test]
fn unit_has_protectsystem_strict_privatetmp_runtimedirectory_and_statedirectory() {
    let text = read(UNIT);

    for directive in [
        "ProtectSystem=strict",
        "PrivateTmp=yes",
        "RuntimeDirectory=fleet-overlay",
        "StateDirectory=fleet-overlay",
    ] {
        assert!(
            has_directive(&text, directive),
            "{UNIT} is missing {directive}"
        );
    }
}
