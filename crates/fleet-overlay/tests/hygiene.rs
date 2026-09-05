//! The repository files an outsider needs before they can adopt, contribute to or audit the
//! project. Checked from the workspace root, not the crate, because they live there.

use std::path::{Path, PathBuf};

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
