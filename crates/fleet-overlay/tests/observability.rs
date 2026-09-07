//! The alert rules, the Grafana dashboard and the rollout guide. They are files an operator
//! loads into their own Prometheus, Grafana and Loki, so nothing here starts the sidecar: the
//! tests read the shipped files and hold them to the series the binary actually exports and to
//! a `promtool` that parses them.
//!
//! The metric names come from T-041's registry rather than from a list written out here, which
//! is the point: a renamed constant has to break a rule that names it, in this suite, instead of
//! quietly breaking an alert nobody is watching.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fleet_overlay::metrics::Metrics;
use prometheus::Registry;
use serde::Deserialize;

const ALERTS_DIR: &str = "deploy/prometheus";
const ALERTS_FILE: &str = "alerts.yml";
const DASHBOARD: &str = "deploy/grafana/fleet-overlay.json";
const COMPOSE: &str = "examples/compose/docker-compose.yml";
const ROLLOUT: &str = "docs/rollout.md";
const TROUBLESHOOTING: &str = "docs/troubleshooting.md";
const EVENTS: &str = "docs/events.md";

/// The image `promtool` comes out of where the host has no local one. Pinned to a tag rather
/// than a digest on purpose: the check is "does a current Prometheus accept these rules".
const PROMETHEUS_IMAGE: &str = "prom/prometheus:latest";

/// The process collector's series the rules and the dashboard read. The collector is Linux-only
/// in the `prometheus` crate, so the names are listed here and
/// [`process_names_are_the_ones_the_collector_exports`] holds the list to the real thing on the
/// platform that has one.
const PROCESS: &[&str] = &[
    "process_cpu_seconds_total",
    "process_open_fds",
    "process_resident_memory_bytes",
    "process_start_time_seconds",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(relative: &str) -> String {
    let path = workspace_root().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

/// Every series the sidecar exports: T-041's registry, plus the process collector's names.
fn exported_metrics() -> BTreeSet<String> {
    let registry = Registry::new();
    let metrics = Metrics::new(&registry).unwrap();
    metrics
        .registered_names()
        .chain(PROCESS.iter().copied())
        .map(str::to_owned)
        .collect()
}

/// How `promtool` can be reached on this host.
enum Promtool {
    /// Installed, on the `PATH`.
    Local,
    /// In `prom/prometheus`, with a container runtime that answers.
    Docker,
    /// Neither, so the check that needs it skips the way T-046's `systemd-analyze` test does.
    Missing,
}

fn runs(command: &mut Command) -> bool {
    command.output().is_ok_and(|output| output.status.success())
}

fn promtool() -> Promtool {
    if runs(Command::new("promtool").arg("--version")) {
        Promtool::Local
    } else if runs(Command::new("docker").args(["info", "--format", "{{.ServerVersion}}"])) {
        Promtool::Docker
    } else {
        Promtool::Missing
    }
}

/// `promtool check rules` over `file` in `dir`, or `None` where promtool cannot be reached at
/// all. The container form bind-mounts `dir`, so every caller passes a directory inside the
/// workspace rather than a temporary one the runtime may not share.
fn check_rules(dir: &Path, file: &str) -> Option<Output> {
    let output = match promtool() {
        Promtool::Local => Command::new("promtool")
            .args(["check", "rules"])
            .arg(dir.join(file))
            .output(),
        Promtool::Docker => Command::new("docker")
            .args(["run", "--rm", "-v"])
            .arg(format!("{}:/w", dir.display()))
            .args(["-w", "/w", "--entrypoint", "promtool", PROMETHEUS_IMAGE])
            .args(["check", "rules", file])
            .output(),
        Promtool::Missing => {
            eprintln!("skipped: neither promtool nor a working docker is on this host");
            return None;
        }
    };
    Some(output.unwrap_or_else(|err| panic!("promtool: {err}")))
}

fn assert_promtool_accepted(output: &Output) {
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Words that read like an identifier but never name a series. The ones that take a label list
/// are handled separately, because what follows them in brackets is label names.
const KEYWORDS: &[&str] = &[
    "and",
    "atan2",
    "bool",
    "by",
    "group_left",
    "group_right",
    "ignoring",
    "inf",
    "nan",
    "offset",
    "on",
    "or",
    "unless",
    "without",
];

/// The keywords whose parenthesised list holds label names rather than series.
const LABEL_LISTS: &[&str] = &[
    "by",
    "without",
    "on",
    "ignoring",
    "group_left",
    "group_right",
];

fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == ':'
}

/// Scans forward from the opening delimiter at `from` to just past its closing `close`. None of
/// these ever nest in a PromQL expression, so one pass is enough.
fn past(chars: &[char], from: usize, close: char) -> usize {
    let mut i = from + 1;
    while i < chars.len() && chars[i] != close {
        i += 1;
    }
    i + 1
}

/// The series a PromQL expression selects. Everything that is not one is skipped as it is read:
/// string literals, the label matchers in `{}`, the ranges in `[]`, the label lists after `by`
/// and its relatives, numbers with their unit or exponent, any identifier a `(` follows, which
/// is a function, and the operator keywords.
fn metric_names(expr: &str) -> BTreeSet<String> {
    let chars: Vec<char> = expr.chars().collect();
    let mut names = BTreeSet::new();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            quote @ ('"' | '\'' | '`') => i = past(&chars, i, quote),
            '{' => i = past(&chars, i, '}'),
            '[' => i = past(&chars, i, ']'),
            c if c.is_ascii_digit() => {
                while i < chars.len() && (is_name_char(chars[i]) || chars[i] == '.') {
                    i += 1;
                }
            }
            c if c.is_ascii_alphabetic() || c == '_' || c == ':' => {
                let start = i;
                while i < chars.len() && is_name_char(chars[i]) {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();

                let mut after = i;
                while after < chars.len() && chars[after].is_whitespace() {
                    after += 1;
                }
                let open = chars.get(after) == Some(&'(');
                // `sum(x)` and `sum by (instance) (x)` are both the aggregation, so a label
                // list where the argument would be says the word before it was one too.
                let next: String = chars[after..]
                    .iter()
                    .take_while(|c| is_name_char(**c))
                    .collect();
                let applied = open || LABEL_LISTS.contains(&next.as_str());

                if open && LABEL_LISTS.contains(&word.as_str()) {
                    i = past(&chars, after, ')');
                } else if !applied && !KEYWORDS.contains(&word.as_str()) {
                    names.insert(word);
                }
            }
            _ => i += 1,
        }
    }
    names
}

/// A Prometheus rule file, in the shape the alerts are written in: one group of alerting rules,
/// each with the annotations an operator reads when it fires.
#[derive(Deserialize)]
struct RuleFile {
    groups: Vec<Group>,
}

#[derive(Deserialize)]
struct Group {
    rules: Vec<Rule>,
}

#[derive(Deserialize)]
struct Rule {
    alert: String,
    expr: String,
    #[serde(rename = "for")]
    hold: String,
    annotations: Annotations,
}

#[derive(Deserialize)]
struct Annotations {
    summary: String,
    runbook: String,
}

fn alert_rules() -> Vec<Rule> {
    let path = format!("{ALERTS_DIR}/{ALERTS_FILE}");
    let file: RuleFile =
        serde_yaml_bw::from_str(&read(&path)).unwrap_or_else(|err| panic!("{path}: {err}"));
    file.groups
        .into_iter()
        .flat_map(|group| group.rules)
        .collect()
}

/// Check 1. The rules as Prometheus itself reads them, which is the only thing here that
/// catches a misspelled field, a duration it does not parse or an expression that does not
/// compile. Skipped where promtool cannot be reached; CI has it.
#[test]
fn promtool_check_rules_passes() {
    let dir = workspace_root().join(ALERTS_DIR);
    let Some(output) = check_rules(&dir, ALERTS_FILE) else {
        return;
    };

    assert_promtool_accepted(&output);
}

/// Check 2. §12's contract, from the other side: an alert that names a series the binary does
/// not export is an alert that never fires. The known set is read out of T-041's registry, so
/// renaming a constant fails here rather than in production.
#[test]
fn alert_rules_reference_only_metric_names_exported_by_the_binary() {
    let exported = exported_metrics();

    for rule in alert_rules() {
        let named = metric_names(&rule.expr);
        assert!(
            !named.is_empty(),
            "{}: no series read out of {:?}",
            rule.alert,
            rule.expr
        );

        let unknown: Vec<&String> = named
            .iter()
            .filter(|name| !exported.contains(*name))
            .collect();

        assert!(
            unknown.is_empty(),
            "{} names series the binary does not export: {unknown:?}",
            rule.alert
        );
    }
}

/// The ten alerts §12 and the design panel asked for, each holding for a window and pointing at
/// the section of the troubleshooting guide that says what to do about it.
#[test]
fn every_alert_holds_for_a_window_and_carries_a_summary_and_a_runbook() {
    let rules = alert_rules();

    let names: Vec<&str> = rules.iter().map(|rule| rule.alert.as_str()).collect();
    assert_eq!(
        names,
        [
            "OverlayPeersLow",
            "OverlayBnDisconnected",
            "OverlayNotTrustedByBn",
            "OverlayHandshakeFailures",
            "OverlayWinRateFalling",
            "OverlayFanoutSuppressed",
            "OverlayRosterReloadRejected",
            "OverlayMemoryHigh",
            "OverlaySidecarRestarting",
            "OverlayRepairRateRising",
        ]
    );

    for rule in &rules {
        assert!(
            rule.hold.ends_with('m'),
            "{}: for: {}",
            rule.alert,
            rule.hold
        );
        assert!(!rule.annotations.summary.is_empty(), "{}", rule.alert);
        assert!(!rule.annotations.runbook.is_empty(), "{}", rule.alert);
    }
}

/// The process collector is Linux-only in the `prometheus` crate, so this is the one check the
/// workspace's other platforms skip rather than fake. It is what keeps [`PROCESS`] honest.
#[cfg(target_os = "linux")]
#[test]
fn process_names_are_the_ones_the_collector_exports() {
    use prometheus::core::Collector;

    let registry = Registry::new();
    Metrics::new(&registry).unwrap();
    let gathered: BTreeSet<String> = registry
        .gather()
        .iter()
        .map(|family| family.name().to_owned())
        .collect();

    let missing: Vec<&&str> = PROCESS
        .iter()
        .filter(|name| !gathered.contains(**name))
        .collect();

    assert!(missing.is_empty(), "not on the scrape: {missing:?}");
}

/// Every query in the dashboard, as (datasource type, expression). Each target carries its own
/// datasource, which is how the Prometheus panels are told from the optional Loki ones.
fn dashboard_queries() -> Vec<(String, String)> {
    let dashboard: serde_json::Value =
        serde_json::from_str(&read(DASHBOARD)).unwrap_or_else(|err| panic!("{DASHBOARD}: {err}"));
    let mut queries = Vec::new();
    collect_queries(&dashboard, &mut queries);
    queries
}

fn collect_queries(value: &serde_json::Value, into: &mut Vec<(String, String)>) {
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                collect_queries(item, into);
            }
        }
        serde_json::Value::Object(fields) => {
            let expr = fields.get("expr").and_then(serde_json::Value::as_str);
            let kind = fields
                .get("datasource")
                .and_then(|source| source.get("type"))
                .and_then(serde_json::Value::as_str);
            if let (Some(expr), Some(kind)) = (expr, kind) {
                into.push((kind.to_owned(), expr.to_owned()));
            }
            for field in fields.values() {
                collect_queries(field, into);
            }
        }
        _ => {}
    }
}

/// Check 3. The same contract as the alert rules, over the panels: a dashboard that names a
/// series the binary does not export is a panel that stays empty and says nothing about why.
#[test]
fn dashboard_json_is_valid_and_references_only_known_metrics() {
    let exported = exported_metrics();
    let queries = dashboard_queries();

    let prometheus: Vec<&(String, String)> = queries
        .iter()
        .filter(|(kind, _)| kind == "prometheus")
        .collect();
    assert!(
        !prometheus.is_empty(),
        "{DASHBOARD} has no Prometheus panel"
    );

    for (_, expr) in prometheus {
        let named = metric_names(expr);
        assert!(!named.is_empty(), "no series read out of {expr:?}");

        let unknown: Vec<&String> = named
            .iter()
            .filter(|name| !exported.contains(*name))
            .collect();
        assert!(
            unknown.is_empty(),
            "{expr:?} names series the binary does not export: {unknown:?}"
        );
    }
}

/// The demo's Grafana provisions every dashboard under `examples/compose/dashboards` and its
/// Prometheus loads the rules mounted beside its config. Both files live in `deploy/`, where an
/// operator finds them; a second copy in the demo would be wrong the first time either changed,
/// and a symlink would point outside the directory the compose file mounts.
#[test]
fn the_compose_demo_mounts_the_shipped_dashboard_and_alert_rules() {
    let compose = read(COMPOSE);

    for mount in [
        "../../deploy/grafana/fleet-overlay.json:/var/lib/grafana/dashboards/fleet-overlay.json:ro",
        "../../deploy/prometheus/alerts.yml:/etc/prometheus/rules/fleet-overlay.yml:ro",
    ] {
        assert!(compose.contains(mount), "{COMPOSE} does not mount {mount}");
    }
}

/// The bodies of a Markdown file's ```language blocks, in order.
fn fenced_blocks(text: &str, language: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current: Option<Vec<&str>> = None;

    for line in text.lines() {
        match (&mut current, line.trim_end()) {
            (Some(lines), "```") => {
                blocks.push(lines.join("\n"));
                current = None;
            }
            (Some(lines), line) => lines.push(line),
            (None, fence) if fence == format!("```{language}") => current = Some(Vec::new()),
            (None, _) => {}
        }
    }
    blocks
}

/// Every LogQL query the project ships: the dashboard's optional panels, and the code blocks in
/// the rollout guide and in T-044's event reference.
fn logql_queries() -> Vec<String> {
    let mut queries: Vec<String> = dashboard_queries()
        .into_iter()
        .filter(|(kind, _)| kind == "loki")
        .map(|(_, expr)| expr)
        .collect();
    for doc in [ROLLOUT, EVENTS] {
        queries.extend(fenced_blocks(&read(doc), "logql"));
    }
    queries
}

/// A directory inside the workspace for the rule files promtool is handed, since the container
/// form of it bind-mounts whatever directory it is given and a temporary one may not be shared
/// with the runtime.
fn scratch() -> PathBuf {
    let dir = workspace_root().join("target/t052");
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Check 4. The queries an operator copies out of the rollout guide, wrapped one per recording
/// rule so `promtool` parses them the way Prometheus would. Skipped where promtool cannot be
/// reached, like check 1.
#[test]
fn rollout_doc_queries_are_syntactically_valid_promql() {
    let queries = fenced_blocks(&read(ROLLOUT), "promql");
    assert!(!queries.is_empty(), "{ROLLOUT} has no promql block");

    let mut rules = String::from("groups:\n  - name: rollout-doc\n    rules:\n");
    for (index, query) in queries.iter().enumerate() {
        let indented = query
            .lines()
            .map(|line| format!("          {line}"))
            .collect::<Vec<String>>()
            .join("\n");
        rules.push_str(&format!(
            "      - record: doc:query{index}\n        expr: |\n{indented}\n"
        ));
    }

    let dir = scratch();
    let file = "rollout-doc-queries.yml";
    std::fs::write(dir.join(file), &rules).unwrap();

    let Some(output) = check_rules(&dir, file) else {
        return;
    };
    assert_promtool_accepted(&output);
}

/// The same contract as checks 2 and 3, over the guide: a query in the documentation that names
/// a series the binary does not export sends an operator looking for a fault that is really a
/// typo in the doc.
#[test]
fn rollout_doc_queries_name_only_metrics_the_binary_exports() {
    let exported = exported_metrics();

    for query in fenced_blocks(&read(ROLLOUT), "promql") {
        let unknown: Vec<String> = metric_names(&query)
            .into_iter()
            .filter(|name| !exported.contains(name))
            .collect();

        assert!(
            unknown.is_empty(),
            "{ROLLOUT} names series the binary does not export: {unknown:?} in {query:?}"
        );
    }
}

/// Check 5. D32: there is one log stream with an `event` field, not a stream per event, so
/// every LogQL query selects the field rather than a file or a pipe.
#[test]
fn every_loki_query_selects_on_the_event_field() {
    let queries = logql_queries();
    assert!(queries.len() >= 3, "only {} LogQL queries", queries.len());

    for query in &queries {
        assert!(query.contains("| json"), "no `| json` in {query:?}");
        assert!(query.contains("event=\""), "no event filter in {query:?}");
        for stream in ["stdout", "stderr"] {
            assert!(!query.contains(stream), "{stream} named in {query:?}");
        }
    }
}

/// The heading an anchor points at, GitHub's way: lowercased, punctuation dropped, spaces
/// turned into dashes.
fn anchor(heading: &str) -> String {
    heading
        .trim()
        .to_lowercase()
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-')
        .map(|c| if c == ' ' { '-' } else { c })
        .collect()
}

/// An alert whose runbook link goes nowhere is an alert that fires at three in the morning and
/// says nothing useful. Every one of them has a section of its own in the troubleshooting guide.
#[test]
fn every_runbook_annotation_names_a_heading_in_the_troubleshooting_doc() {
    let headings: BTreeSet<String> = read(TROUBLESHOOTING)
        .lines()
        .filter_map(|line| line.strip_prefix("## "))
        .map(anchor)
        .collect();
    assert!(!headings.is_empty(), "{TROUBLESHOOTING} has no sections");

    for rule in alert_rules() {
        let (path, section) = rule
            .annotations
            .runbook
            .split_once('#')
            .unwrap_or_else(|| panic!("{}: runbook has no anchor", rule.alert));

        assert_eq!(path, TROUBLESHOOTING, "{}", rule.alert);
        assert!(
            headings.contains(section),
            "{}: no `## ` heading in {TROUBLESHOOTING} anchors to {section}",
            rule.alert
        );
    }
}
