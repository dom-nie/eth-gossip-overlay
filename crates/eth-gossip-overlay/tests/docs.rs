//! The operator documentation under `docs/`. An operator reads these files instead of the code,
//! so the checks here hold them to what the code actually does: the configuration reference is
//! generated from `Config`'s own doc comments, the Lighthouse drop-in in the prose is the file
//! the repository ships, and every link resolves.
//!
//! Regenerate the reference after changing `Config`:
//!
//! ```sh
//! UPDATE_DOCS=1 cargo test -p eth-gossip-overlay --test docs
//! ```

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;

use eth_gossip_overlay::app::SEND_LANES;
use eth_gossip_overlay::reload::RELOADABLE;
use overlay_core::budget::{self, MemoryBudget};
use overlay_core::config::Config;
use serde_yaml_bw as yaml;

const CONFIGURATION: &str = "docs/configuration.md";
const PERFORMANCE: &str = "docs/performance.md";
const LIGHTHOUSE: &str = "docs/lighthouse.md";
const CONFIG_SOURCE: &str = "crates/overlay-core/src/config.rs";
const BUDGET_SOURCE: &str = "crates/overlay-core/src/budget.rs";
const EXAMPLE_CONFIG: &str = "deploy/examples/config.yaml";
const DROP_IN: &str =
    "deploy/systemd/lighthouse-bn.service.d/10-eth-gossip-overlay-trusted-peer.conf";

/// The markers around the generated part of a document, the same shape the ticket backlog's own
/// generator uses, so the preamble a person writes and the table a program writes live in one
/// document.
fn begin(source: &str) -> String {
    format!("<!-- generated from {source}, do not edit by hand -->")
}
const END: &str = "<!-- end generated -->";

/// Holds the generated part of `document` to what `source` says it should be, and writes the
/// new text instead of failing under `UPDATE_DOCS=1`.
fn check_generated(document: &str, source: &str, body: &str) {
    let text = read(document);
    let begin = begin(source);
    let (head, rest) = text
        .split_once(&begin)
        .unwrap_or_else(|| panic!("{document} has no {begin}"));
    let (_, tail) = rest
        .split_once(END)
        .unwrap_or_else(|| panic!("{document} has no {END}"));
    let wanted = format!("{head}{begin}\n\n{body}\n{END}{tail}");

    if text == wanted {
        return;
    }
    if std::env::var_os("UPDATE_DOCS").is_some() {
        let path = workspace_root().join(document);
        std::fs::write(&path, wanted).unwrap_or_else(|err| panic!("{}: {err}", path.display()));
        return;
    }
    panic!(
        "{document} is not what {source} says; regenerate it with\n    \
         UPDATE_DOCS=1 cargo test -p eth-gossip-overlay --test docs"
    );
}

/// A document longer than this is one an operator stops reading. The count is the words outside
/// fenced code blocks: a command block is copied, not read.
const WORD_LIMIT: usize = 1500;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(relative: &str) -> String {
    let path = workspace_root().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("{}: {err}", path.display()))
}

/// Every `docs/*.md`, sorted, as repository-relative paths.
#[allow(clippy::unwrap_used)]
fn operator_documents() -> Vec<String> {
    let dir = workspace_root().join("docs");
    let mut found: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|err| panic!("{}: {err}", dir.display()))
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".md"))
        .map(|name| format!("docs/{name}"))
        .collect();
    found.sort();
    found
}

/// The words a person reads: everything outside a fenced code block.
fn prose_words(text: &str) -> usize {
    let mut fenced = false;
    let mut words = 0;
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
        } else if !fenced {
            words += line.split_whitespace().count();
        }
    }
    words
}

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

/// One `pub struct` or `pub enum` of the configuration model, as the source file spells it.
#[derive(Default)]
struct Item {
    fields: Vec<Field>,
    /// The serialized names of an enum's variants, empty for a struct.
    values: Vec<String>,
    /// Whether `#[serde(rename_all = "lowercase")]` spells those variants.
    lowercase: bool,
}

struct Field {
    /// The key as `config.yaml` spells it, which is the `#[serde(rename)]` where there is one.
    key: String,
    /// The type as written, `Option<…>` and all.
    ty: String,
    doc: String,
}

/// The doc comment on a line, or `None` where the line is not one.
fn doc_line(trimmed: &str) -> Option<&str> {
    match trimmed {
        "///" => Some(""),
        line => line.strip_prefix("/// "),
    }
}

/// The value of `attribute = "…"` in a `#[serde(…)]` line.
fn attribute<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    line.split_once(&format!("{name} = \""))
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(value, _)| value)
}

/// The configuration model as the source file declares it: every struct and enum reachable from
/// `Config`, with the doc comment on each field. Parsing the source rather than deriving from
/// the type is what puts the operator's reference and the programmer's comment in one place.
fn config_model() -> BTreeMap<String, Item> {
    let source = read(CONFIG_SOURCE);
    let mut items: BTreeMap<String, Item> = BTreeMap::new();
    let mut open: Option<(String, Item, bool)> = None;
    let mut docs: Vec<&str> = Vec::new();
    let mut rename: Option<&str> = None;
    let mut lowercase = false;

    for line in source.lines() {
        let trimmed = line.trim();
        if let Some(doc) = doc_line(trimmed) {
            docs.push(doc);
            continue;
        }
        if trimmed.starts_with("#[") {
            rename = attribute(trimmed, "rename").or(rename);
            lowercase |= attribute(trimmed, "rename_all") == Some("lowercase");
            continue;
        }

        let doc = docs.join(" ").trim().to_owned();
        if let Some(name) = line
            .strip_prefix("pub struct ")
            .and_then(|r| r.split(' ').next())
        {
            open = Some((name.to_owned(), Item::default(), false));
        } else if let Some(name) = line
            .strip_prefix("pub enum ")
            .and_then(|r| r.split(' ').next())
        {
            let item = Item {
                lowercase,
                ..Item::default()
            };
            open = Some((name.to_owned(), item, true));
        } else if line == "}" {
            if let Some((name, item, _)) = open.take() {
                items.insert(name, item);
            }
        } else if let Some((_, item, is_enum)) = open.as_mut() {
            if *is_enum {
                if let Some(variant) = trimmed.strip_suffix(',').filter(|v| !v.contains(' ')) {
                    let value = match item.lowercase {
                        true => variant.to_lowercase(),
                        false => variant.to_owned(),
                    };
                    item.values.push(value);
                }
            } else if let Some(field) = trimmed
                .strip_prefix("pub ")
                .and_then(|f| f.strip_suffix(','))
                && let Some((name, ty)) = field.split_once(": ")
            {
                item.fields.push(Field {
                    key: rename.unwrap_or(name).to_owned(),
                    ty: ty.to_owned(),
                    doc,
                });
            }
        }
        docs.clear();
        rename = None;
        lowercase = false;
    }
    items
}

/// One row of the reference.
struct Key {
    path: String,
    doc: String,
    /// What an enum-valued key accepts, empty for everything else.
    values: Vec<String>,
}

/// Every leaf key of `config.yaml`, in the order `Config` declares them, which is the order the
/// example file is written in.
fn keys(items: &BTreeMap<String, Item>, name: &str, prefix: &str, into: &mut Vec<Key>) {
    let item = items
        .get(name)
        .unwrap_or_else(|| panic!("{CONFIG_SOURCE} has no {name}"));
    for field in &item.fields {
        let path = format!("{prefix}{}", field.key);
        let inner = field
            .ty
            .strip_prefix("Option<")
            .and_then(|ty| ty.strip_suffix('>'))
            .unwrap_or(&field.ty);
        match items.get(inner) {
            Some(nested) if nested.values.is_empty() => {
                keys(items, inner, &format!("{path}."), into)
            }
            nested => into.push(Key {
                path,
                doc: field.doc.clone(),
                values: nested.map(|item| item.values.clone()).unwrap_or_default(),
            }),
        }
    }
}

/// The shipped example rendered as a lookup from dotted path to the scalar written there. It is
/// the defaults column: a separate test holds the file to `Config::default()`.
fn example_defaults() -> BTreeMap<String, String> {
    fn walk(value: &yaml::Value, prefix: &str, into: &mut BTreeMap<String, String>) {
        let yaml::Value::Mapping(mapping) = value else {
            return;
        };
        for (key, value) in mapping {
            let Some(key) = key.as_str() else { continue };
            let path = format!("{prefix}{key}");
            match value {
                yaml::Value::Mapping(_) => walk(value, &format!("{path}."), into),
                yaml::Value::Null(_) => {
                    into.insert(path, "none".to_owned());
                }
                yaml::Value::Bool(value, _) => {
                    into.insert(path, value.to_string());
                }
                yaml::Value::Number(value, _) => {
                    into.insert(path, value.to_string());
                }
                yaml::Value::String(value, _) => {
                    into.insert(path, value.clone());
                }
                other => panic!("{EXAMPLE_CONFIG}: {path} is {other:?}"),
            }
        }
    }

    let value: yaml::Value = yaml::from_str(&read(EXAMPLE_CONFIG))
        .unwrap_or_else(|err| panic!("{EXAMPLE_CONFIG}: {err}"));
    let mut defaults = BTreeMap::new();
    walk(&value, "", &mut defaults);
    defaults
}

/// The doc comment with the key it repeats taken off the front, since the key column says it.
fn without_the_key(doc: &str, path: &str) -> String {
    let key = path.rsplit('.').next().unwrap_or(path);
    doc.strip_prefix(&format!("`{key}`: "))
        .unwrap_or(doc)
        .to_owned()
}

/// The generated half of `docs/configuration.md`.
fn reference_table() -> String {
    let items = config_model();
    let mut rows = Vec::new();
    keys(&items, "Config", "", &mut rows);
    assert!(rows.len() > 20, "{CONFIG_SOURCE}: only {} keys", rows.len());

    let defaults = example_defaults();
    let mut table = String::from("| Key | Default | On change | What it is |\n|---|---|---|---|\n");
    for row in rows {
        let default = match defaults.get(&row.path) {
            Some(value) if value.is_empty() => "empty".to_owned(),
            Some(value) => format!("`{value}`"),
            None => "unset".to_owned(),
        };
        let reload = match RELOADABLE.contains(&row.path.as_str()) {
            true => "reload",
            false => "restart",
        };
        let mut doc = without_the_key(&row.doc, &row.path);
        if !row.values.is_empty() {
            let values: Vec<String> = row.values.iter().map(|v| format!("`{v}`")).collect();
            doc = format!("{doc} One of {}.", values.join(", "));
        }
        table.push_str(&format!(
            "| `{}` | {default} | {reload} | {doc} |\n",
            row.path
        ));
    }
    table
}

/// The roster the memory budget table is stated at: the fleet Architecture.md's §2 describes,
/// which is the example every other number in `docs/performance.md` is taken at.
const BUDGET_ROSTER: usize = 200;

/// A byte count the way the unit writes it, so the document and
/// `deploy/systemd/eth-gossip-overlay.service` spell the same ceiling the same way.
fn systemd_size(bytes: u64) -> String {
    let gib = 1024 * 1024 * 1024;
    match bytes {
        bytes if bytes.is_multiple_of(gib) => format!("{}G", bytes / gib),
        bytes => format!("{}M", bytes / (1024 * 1024)),
    }
}

/// The generated half of `docs/performance.md`: every bounded structure's worst case at the
/// Appendix A defaults, the sum, the headroom OPS-N4 asks for, and the ceiling it all has to
/// fit under.
fn budget_table() -> String {
    let budget = MemoryBudget::compute(
        &Config::default(),
        BUDGET_ROSTER,
        budget::MEMORY_MAX_DEFAULT,
        SEND_LANES,
    );
    let mib = |bytes: u64| format!("{:.1}", bytes as f64 / (1024.0 * 1024.0));

    let mut table = format!(
        "At the shipped defaults, a roster of {BUDGET_ROSTER} hosts and the unit's \
         `MemoryMax={}`, which gives every connection a receive window of {} MiB.\n\n\
         | Structure | Bytes | MiB |\n|---|---:|---:|\n",
        systemd_size(budget.limit),
        mib(budget.receive_window),
    );
    for (name, bytes) in &budget.rows {
        table.push_str(&format!("| `{name}` | {bytes} | {} |\n", mib(*bytes)));
    }
    table.push_str(&format!(
        "| **Sum of the bounds** | {} | {} |\n\
         | **Plus {}% headroom** | {} | {} |\n\
         | `MemoryMax` | {} | {} |\n",
        budget.bounded_bytes,
        mib(budget.bounded_bytes),
        budget::HEADROOM_PERCENT,
        budget.total_bytes,
        mib(budget.total_bytes),
        budget.limit,
        mib(budget.limit),
    ));
    table
}

/// Check 1. The reference is generated, so a key added to `Config` without a word about what it
/// does, or a default changed in the code and not in the document, fails here rather than
/// reaching an operator. `UPDATE_DOCS=1` writes the new table instead of failing.
#[test]
fn configuration_reference_matches_generated_output() {
    check_generated(CONFIGURATION, CONFIG_SOURCE, &reference_table());
}

/// The same for the memory budget (OPS-N4). An operator sizes `MemoryMax` off this table, and a
/// bound that moves in the code without moving here would have them size against a number the
/// process stopped holding to.
#[test]
fn memory_budget_table_matches_generated_output() {
    check_generated(PERFORMANCE, BUDGET_SOURCE, &budget_table());
}

/// Check 2. Every key an operator can copy out of the shipped example has a row of its own. The
/// example is the other end of the reference: generation cannot invent a key, but it can miss
/// one the example still carries.
#[test]
fn every_config_key_appears_in_the_reference() {
    let reference = read(CONFIGURATION);
    let missing: Vec<String> = example_defaults()
        .into_keys()
        .filter(|path| !reference.contains(&format!("| `{path}` |")))
        .collect();

    assert!(
        missing.is_empty(),
        "{CONFIGURATION} has no row for {missing:?}"
    );
}

/// The defaults column is read out of the example file, which only tells the truth while the
/// example is the defaults. D30 says it is; this is what keeps it that way.
#[test]
fn the_example_config_is_exactly_the_default_config() {
    let example = Config::from_yaml(&read(EXAMPLE_CONFIG))
        .unwrap_or_else(|err| panic!("{EXAMPLE_CONFIG}: {err}"));

    assert_eq!(example, Config::default(), "{EXAMPLE_CONFIG}");
}

/// Check 4. Every link in the operator documentation resolves. `--offline` leaves the internet
/// alone and checks the relative links, which are the ones a repository breaks by moving a
/// file. Skipped where `lychee` is not installed, like the promtool and systemd-analyze checks;
/// CI has it.
#[test]
fn link_check_passes() {
    let mut command = Command::new("lychee");
    command
        .current_dir(workspace_root())
        .args(["--offline", "--no-progress"])
        .args(operator_documents())
        .arg("README.md");

    let output = match command.output() {
        Ok(output) => output,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            eprintln!("skipped: lychee is not installed on this host");
            return;
        }
        Err(err) => panic!("lychee: {err}"),
    };

    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Check 6. The drop-in an operator copies out of the prose is the file the repository ships. A
/// paraphrase here would be a beacon node that never reads `lighthouse.env`.
#[test]
fn lighthouse_doc_drop_in_matches_the_shipped_file() {
    let shipped = read(DROP_IN);
    let blocks = fenced_blocks(&read(LIGHTHOUSE), "ini");

    assert!(
        blocks.iter().any(|block| block == shipped.trim_end()),
        "no ini block in {LIGHTHOUSE} is {DROP_IN} verbatim"
    );
}

/// Check 7 (R5.9). The `check-config` sample in both READMEs carries the lines the binary
/// prints for the three-host roster the sample shows, so the budget line cannot go stale the
/// way the old one had: no roster size could produce it. The ceiling is the built-in default,
/// which is what any shell without a cgroup limit of its own reads.
#[test]
fn readme_check_config_sample_matches_a_regenerated_line() {
    let budget = MemoryBudget::compute(
        &Config::default(),
        3,
        budget::MEMORY_MAX_DEFAULT,
        SEND_LANES,
    );
    let mib = |bytes: u64| bytes.div_ceil(1024 * 1024);
    let ceiling = format!(
        "memory ceiling: {} MiB (built-in default)",
        mib(budget.limit)
    );
    let total = format!(
        "memory budget: {} MiB ({} MiB in bounded structures plus {}% headroom)",
        mib(budget.total_bytes),
        mib(budget.bounded_bytes),
        budget::HEADROOM_PERCENT
    );

    for readme in ["README.md", "deploy/README.md"] {
        let text = read(readme);
        assert!(text.contains(&ceiling), "{readme} has no line {ceiling:?}");
        assert!(text.contains(&total), "{readme} has no line {total:?}");
    }
}

/// Split rather than grow. A runbook nobody finishes reading is a runbook that does not work at
/// three in the morning.
#[test]
fn no_operator_document_runs_over_fifteen_hundred_words() {
    let over: Vec<String> = operator_documents()
        .into_iter()
        .map(|doc| (prose_words(&read(&doc)), doc))
        .filter(|(words, _)| *words > WORD_LIMIT)
        .map(|(words, doc)| format!("{doc} ({words} words)"))
        .collect();

    assert!(over.is_empty(), "over {WORD_LIMIT} words: {over:?}");
}

/// A document nothing links to is a document nobody reads. The README is the index.
#[test]
fn the_readme_links_every_operator_document() {
    let readme = read("README.md");
    let unlinked: Vec<String> = operator_documents()
        .into_iter()
        .filter(|doc| !readme.contains(doc))
        .collect();

    assert!(unlinked.is_empty(), "README.md does not link {unlinked:?}");
}
