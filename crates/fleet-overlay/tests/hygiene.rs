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
