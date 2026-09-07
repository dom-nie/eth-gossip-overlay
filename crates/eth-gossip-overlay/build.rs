//! The two things `--version` says about a build that the source cannot: which commit it came
//! from and when it was made. Both are read here, because a released binary has no git checkout
//! to ask and no reason to trust the clock of the host it ends up on.
//!
//! `SOURCE_DATE_EPOCH` wins over the clock, so a reproducible build (T-048) says the same date
//! however often it is run.

use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// What either value becomes when there is nothing to read it from: a tarball build with no
/// `.git` beside it, or a machine without git installed.
const UNKNOWN: &str = "unknown";

fn main() {
    println!("cargo::rerun-if-env-changed=SOURCE_DATE_EPOCH");
    println!("cargo::rustc-env=ETH_GOSSIP_OVERLAY_GIT_SHA={}", git_sha());
    println!(
        "cargo::rustc-env=ETH_GOSSIP_OVERLAY_BUILD_EPOCH={}",
        build_epoch()
    );
}

fn git_sha() -> String {
    Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|sha| sha.trim().to_owned())
        .filter(|sha| !sha.is_empty())
        .unwrap_or_else(|| UNKNOWN.to_owned())
}

fn build_epoch() -> String {
    if let Ok(reproducible) = std::env::var("SOURCE_DATE_EPOCH")
        && reproducible.trim().parse::<i64>().is_ok()
    {
        return reproducible.trim().to_owned();
    }
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(since) => since.as_secs().to_string(),
        Err(_) => UNKNOWN.to_owned(),
    }
}
