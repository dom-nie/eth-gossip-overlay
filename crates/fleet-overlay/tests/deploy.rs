//! The deployment examples under `deploy/`. They are text files an operator copies into their
//! own configuration management, so the tests are lint-style checks that read them from the
//! repository and hold them to what the sidecar and the two systemd units actually need.

use std::path::{Path, PathBuf};

use overlay_core::config::{Config, LogFormat, LogLevel, Steering};
use overlay_core::roster::Roster;

const UNIT: &str = "deploy/systemd/fleet-overlay.service";
const DROP_IN: &str = "deploy/systemd/lighthouse-bn.service.d/10-fleet-overlay-trusted-peer.conf";
const SYSCTL: &str = "deploy/sysctl/90-fleet-overlay.conf";
const NFT_TEMPLATE: &str = "deploy/nftables/fleet-overlay.nft.j2";
const NFT_EXAMPLE: &str = "deploy/nftables/fleet-overlay.nft.example";
const ROSTER: &str = "deploy/examples/roster.yaml";
const CONFIG: &str = "deploy/examples/config.yaml";

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

/// OPS-N3 and D01: the seed arrives as a systemd credential, which the sidecar reads from
/// `$CREDENTIALS_DIRECTORY`, so no service user has to own the file and none has to exist.
#[test]
fn unit_loads_the_seed_as_a_credential_and_uses_dynamicuser() {
    let text = read(UNIT);

    for directive in [
        "LoadCredential=seed:/etc/fleet-overlay/seed",
        "DynamicUser=yes",
    ] {
        assert!(
            has_directive(&text, directive),
            "{UNIT} is missing {directive}"
        );
    }
}

/// OPS-N1: the drop-in is two directives and nothing else. The dash on `EnvironmentFile=` is
/// what makes the file optional, and without it a beacon node whose sidecar has never started
/// would fail its own start on a missing file.
#[test]
fn drop_in_contains_only_after_and_optional_environmentfile() {
    let text = read(DROP_IN);

    let directives: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with('['))
        .collect();

    assert_eq!(
        directives,
        [
            "After=fleet-overlay.service",
            "EnvironmentFile=-/run/fleet-overlay/lighthouse.env",
        ]
    );
    for forbidden in ["ExecStartPre", "Wants", "Requires"] {
        assert!(!text.contains(forbidden), "{DROP_IN} has {forbidden}=");
    }
}

/// §11: 16 MB socket buffers, so the endpoint's own 8 MiB request is granted rather than capped,
/// `fq` for pacing and the flow table the RFS fallback steers with. `net.core.busy_poll` is
/// system wide, so setting it would make the beacon node's epoll busy-poll too; it stays out.
#[test]
fn sysctl_file_has_the_four_keys_and_not_busy_poll() {
    let text = read(SYSCTL);

    for setting in [
        "net.core.rmem_max = 16777216",
        "net.core.wmem_max = 16777216",
        "net.core.default_qdisc = fq",
        "net.core.rps_sock_flow_entries = 32768",
    ] {
        assert!(
            has_directive(&text, setting),
            "{SYSCTL} is missing {setting}"
        );
    }
    assert!(!text.contains("busy_poll"), "{SYSCTL} sets busy_poll");
}

/// Renders the nftables template over a context that is the roster document itself, which is
/// what an operator's own configuration management hands it.
fn render_nft(roster_yaml: &str) -> String {
    let roster: serde_yaml_bw::Value = serde_yaml_bw::from_str(roster_yaml).unwrap();
    let template = read(NFT_TEMPLATE);
    let mut env = minijinja::Environment::new();
    env.add_template("nft", &template).unwrap();
    env.get_template("nft").unwrap().render(roster).unwrap()
}

/// The allowlist regenerated whenever the roster changes. Key pinning is the fence that
/// matters, so this one only has to keep every address in the roster reachable on UDP 7788 and
/// nothing else open. The shipped rendering has to be what the template makes of the shipped
/// roster, or the two rot apart the first time either changes.
#[test]
fn rendered_nft_from_example_roster_contains_all_three_addresses_and_only_udp_7788() {
    let rendered = render_nft(&read(ROSTER));

    assert_eq!(
        rendered,
        read(NFT_EXAMPLE),
        "{NFT_EXAMPLE} is not what {NFT_TEMPLATE} renders from {ROSTER}"
    );
    for address in ["203.0.113.37", "198.51.100.12", "2001:db8:1::120"] {
        assert!(rendered.contains(address), "{address} is not in the set");
    }
    assert!(!rendered.contains('['), "an address kept its brackets");

    let rules: Vec<&str> = rendered
        .lines()
        .map(str::trim)
        .filter(|line| line.contains("dport"))
        .collect();
    assert!(!rules.is_empty(), "the ruleset matches no port at all");
    for rule in rules {
        assert!(
            rule.starts_with("udp dport 7788 "),
            "{rule:?} is not a UDP 7788 rule"
        );
    }
}

/// The shipped examples are what an operator copies to a host, so they have to be files the
/// sidecar accepts. Both parsers reject an unknown key, so a key the code renames fails here
/// rather than on the operator's first start.
#[test]
fn example_config_and_roster_load_with_the_real_parsers() {
    let config = Config::from_yaml(&read(CONFIG));
    let roster = Roster::from_yaml(&read(ROSTER));

    config.unwrap_or_else(|err| panic!("{CONFIG}: {err}"));
    let roster = roster.unwrap_or_else(|err| panic!("{ROSTER}: {err}"));
    assert_eq!(roster.hosts.len(), 3, "{ROSTER}");
}

/// D30: what an operator gets when they copy the example and change nothing. Kernel tuning off,
/// metrics on loopback, and neither of the two keys the panel removed, which a copy of an older
/// config would still carry and the parser would then reject.
#[test]
fn example_config_has_the_shipped_defaults() {
    let text = read(CONFIG);
    let config = Config::from_yaml(&text).unwrap_or_else(|err| panic!("{CONFIG}: {err}"));

    assert_eq!(config.metrics_listen.to_string(), "127.0.0.1:7789");
    assert_eq!(config.overlay.io_thread.pin_cpu, None);
    assert!(!config.overlay.io_thread.prefer_busy_poll);
    assert_eq!(config.overlay.io_thread.steering, Steering::Off);
    assert_eq!(
        config.bn.node_key_file,
        Path::new("/var/lib/fleet-overlay/node.key")
    );
    assert_eq!(config.log.level, LogLevel::Info);
    assert_eq!(config.log.format, LogFormat::Auto);
    for removed in ["auth:", "relay_selection"] {
        assert!(!text.contains(removed), "{CONFIG} still has {removed}");
    }
}
