//! The repository files an outsider needs before they can adopt, contribute to or audit the
//! project. Checked from the workspace root, not the crate, because they live there.

use std::path::{Path, PathBuf};

use overlay_core::protocol::features;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn all_required_top_level_files_exist() {
    let root = workspace_root();
    let required = [
        "LICENSE",
        "README.md",
        "CONTRIBUTING.md",
        "CHANGELOG.md",
        "SECURITY.md",
        "CODE_OF_CONDUCT.md",
        "COMPATIBILITY.md",
        "deny.toml",
        ".github/PULL_REQUEST_TEMPLATE.md",
        ".github/ISSUE_TEMPLATE/bug_report.yml",
        ".github/ISSUE_TEMPLATE/feature_request.yml",
        ".github/workflows/ci.yml",
    ];

    let missing: Vec<&str> = required
        .iter()
        .copied()
        .filter(|name| !root.join(name).is_file())
        .collect();

    assert!(
        missing.is_empty(),
        "missing from the repository root: {missing:?}"
    );
}

fn checklist_items(text: &str) -> Vec<&str> {
    text.lines()
        .filter(|line| line.starts_with("- [ ]"))
        .collect()
}

/// The `- [ ]` lines under CONTRIBUTING.md's "Pull request checklist" heading, up to the next
/// heading; the file may grow other checklists later without widening this comparison.
fn contributing_checklist(text: &str) -> Vec<&str> {
    let section = text
        .split_once("## Pull request checklist")
        .map(|(_, rest)| rest)
        .unwrap_or_default();
    let section = section.split("\n## ").next().unwrap_or_default();
    checklist_items(section)
}

#[test]
fn pr_template_contains_baseline_dod_items() {
    let root = workspace_root();
    let contributing = std::fs::read_to_string(root.join("CONTRIBUTING.md")).unwrap();
    let template = std::fs::read_to_string(root.join(".github/PULL_REQUEST_TEMPLATE.md")).unwrap();

    let expected = contributing_checklist(&contributing);
    let actual = checklist_items(&template);

    assert!(
        !expected.is_empty(),
        "CONTRIBUTING.md has no pull request checklist"
    );
    assert_eq!(
        actual, expected,
        "the PR template's checklist drifted from CONTRIBUTING.md"
    );
}

fn rust_files(dir: &Path, into: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            rust_files(&path, into)?;
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            into.push(path);
        }
    }
    Ok(())
}

/// A `mutants::skip` with nothing saying why is the one thing the mutation-testing rule forbids:
/// the nightly run goes quiet and a reader cannot tell whether the mutant was equivalent or the
/// test was simply missing. The reason is a comment on the line above the attribute or on the
/// attribute's own line, and the same goes for the exclusion lists that skip what no attribute
/// can reach.
#[test]
fn every_mutants_skip_carries_a_reason() {
    let root = workspace_root();
    let mut sources = Vec::new();
    rust_files(&root.join("crates"), &mut sources).unwrap();
    assert!(!sources.is_empty(), "no Rust sources found under crates/");

    let mut bare = Vec::new();
    for path in &sources {
        let text = std::fs::read_to_string(path).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        for (index, line) in lines.iter().enumerate() {
            let is_attribute = line.contains("mutants::skip") && line.trim_start().starts_with('#');
            let has_reason = lines[..index]
                .last()
                .is_some_and(|above| above.trim_start().starts_with("//"))
                || line.contains("//");
            if is_attribute && !has_reason {
                bare.push(format!("{}:{}", path.display(), index + 1));
            }
        }
    }
    assert!(bare.is_empty(), "mutants::skip with no reason: {bare:?}");

    let config = std::fs::read_to_string(root.join(".cargo/mutants.toml")).unwrap();
    for key in ["exclude_re", "exclude_globs"] {
        let introduced_by_a_comment = config
            .split_once(key)
            .and_then(|(before, _)| before.lines().last().map(str::trim_start))
            .is_some_and(|above| above.starts_with('#'));
        assert!(
            !config.contains(key) || introduced_by_a_comment,
            "{key} in .cargo/mutants.toml has no comment saying why"
        );
    }
}

/// The `## [...]` sections of a changelog, as heading and body. The heading keeps its brackets,
/// which is what tells a version section from any other second-level heading the file grows.
fn changelog_sections(text: &str) -> Vec<(&str, &str)> {
    text.split("\n## ")
        .skip(1)
        .filter(|section| section.starts_with('['))
        .map(|section| section.split_once('\n').unwrap_or((section, "")))
        .collect()
}

/// `Protocol: major unchanged (1); features added: none`, or `major 1 → 2`, or a comma-separated
/// list of `NAME (bit N)` in place of `none`.
fn protocol_line_is_well_formed(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("Protocol: major ") else {
        return false;
    };
    let Some((major, features)) = rest.split_once("; features added: ") else {
        return false;
    };
    let major_reads = match major
        .strip_prefix("unchanged (")
        .and_then(|m| m.strip_suffix(')'))
    {
        Some(current) => current.parse::<u8>().is_ok(),
        None => major
            .split_once(" → ")
            .is_some_and(|(from, to)| from.parse::<u8>().is_ok() && to.parse::<u8>().is_ok()),
    };
    major_reads && (features == "none" || features.split(", ").all(names_a_feature_bit))
}

/// `STRIPING (bit 1)`, held against the protocol's own list of bits: a release note that names
/// a feature no build advertises is worse than one that names none.
fn names_a_feature_bit(item: &str) -> bool {
    let Some((name, position)) = item.split_once(" (bit ") else {
        return false;
    };
    let Some(Ok(position)) = position.strip_suffix(')').map(str::parse::<u32>) else {
        return false;
    };
    features::NAMES.iter().any(|(known, bit)| {
        *known == name.to_lowercase() && Some(*bit) == 1u64.checked_shl(position)
    })
}

/// D29: `Protocol:` is the one line that says whether a release splits the fleet into two
/// populations or rolls through it, so every section carries one in a shape a machine reads.
/// `Unreleased` carries one too, because it is the section a release is cut from.
#[test]
fn changelog_has_unreleased_section_and_every_release_section_has_a_protocol_line() {
    let text = std::fs::read_to_string(workspace_root().join("CHANGELOG.md")).unwrap();
    let sections = changelog_sections(&text);

    assert!(
        sections
            .iter()
            .any(|(heading, _)| *heading == "[Unreleased]"),
        "no Unreleased section in CHANGELOG.md"
    );

    let without: Vec<&str> = sections
        .iter()
        .filter(|(_, body)| !body.lines().any(protocol_line_is_well_formed))
        .map(|(heading, _)| *heading)
        .collect();
    assert!(
        without.is_empty(),
        "no well-formed `Protocol:` line under {without:?}"
    );
}
