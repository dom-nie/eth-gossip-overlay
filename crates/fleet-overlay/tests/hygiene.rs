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
