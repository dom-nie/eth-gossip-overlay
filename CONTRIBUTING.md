# Contributing

## Tests first

Every change starts with a failing test. Commit the test on its own, watch it fail, then commit the code that makes it pass; a reviewer reads the two commits to see that the test drove the code. Each test checks one behaviour and is named after it: `entry_expires_after_ttl`, not `test_cache_2`. Anything that depends on the current time takes the `Clock` trait from `overlay-core` and is tested with `FakeClock`; async timers use `tokio::time::pause()`. There are no sleeps in the suite.

## Running the suite

```sh
cargo test --workspace                                     # everything; the first run also builds Lighthouse's crates as dev-dependencies
cargo test -p overlay-core                                 # the pure crate, seconds
cargo clippy --workspace --all-targets -- -D warnings      # what CI enforces
cargo fmt --all --check
cargo deny check licenses advisories bans sources          # dependency licences, advisories, duplicate versions, git sources
lychee --offline --no-progress --exclude-path target '**/*.md'   # internal links in the Markdown files
```

`cargo install cargo-deny lychee --locked` provides the last two. CI runs the same checks.

## Formatting and lints

Run `cargo fmt --all` before committing. Clippy runs with `-D warnings`, and three lints are on across the workspace: `missing_docs`, `clippy::unwrap_used` and `clippy::expect_used`. Tests may unwrap; non-test code that has to unwrap says in a comment why it cannot fail. Doc comments say what and why, not how, and never restate the code.

## Commits

The subject is a lowercase imperative summary under 72 characters. Changes from the backlog carry the ticket id as a prefix (`T-007: expire seen cache entries after ttl`); other changes name what they do. The body, when there is one, says what changed and why in plain language.

## Developer Certificate of Origin

Contributors certify the [Developer Certificate of Origin 1.1](https://developercertificate.org/) by adding `Signed-off-by: Name <email>` to each commit, which `git commit -s` does for you. There is no CLA.

## Bumping Lighthouse

`overlay-bn` compiles the `sigp/rust-libp2p` revision Lighthouse pins, so a Lighthouse release is a dependency bump plus a matrix run. In order:

1. In the root `Cargo.toml`, move the `tag` on `lighthouse_network` and `types` to the new release and copy the `sigp/rust-libp2p` `rev` in the `[patch]` table from Lighthouse's own root `Cargo.toml` at that tag. Then `cargo update -p lighthouse_network -p types -p libp2p`.
2. `cargo test -p overlay-bn drift` runs every drift test: the copied wire constants in `overlay_bn::gossip::wire`, `PINNED` against the tag, and the compatibility document against its generator. Fix whatever they flag; a moved constant is the point of the exercise.
3. `scripts/lighthouse-matrix.sh <version>` downloads the release, starts a beacon node and runs `crates/overlay-bn/tests/matrix.rs` against it. Once T-019 is merged, add `--ten-minutes`.
4. In `crates/overlay-bn/src/compat.rs`, update `PINNED`, `SUPPORTED` and `LAST_VERIFIED` together, regenerate the Lighthouse section of `COMPATIBILITY.md` with `UPDATE_COMPATIBILITY_MD=1 cargo test -p overlay-bn compatibility_md_matches_the_constant`, and add the version to the `version` list in `.github/workflows/lighthouse-matrix.yml`. The same test holds that list to `SUPPORTED`.
5. `cargo deny check licenses advisories bans sources`, then prune `deny.toml`'s advisory ignore list of anything the new tree no longer pulls in.

## Pull request checklist

The pull request template carries this list verbatim and a test keeps the two copies equal.

- [ ] Every test in the change's test plan exists, is named after the behaviour it checks, and passes with `cargo test --workspace`
- [ ] `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` are clean
- [ ] No `unwrap()`, `expect()` or `panic!` in non-test code unless a comment explains why it cannot fail
- [ ] Public items have a doc comment that says what and why, not how; no comment blocks restating the code
- [ ] New config keys are parsed in `overlay-core`'s `Config`, defaulted, validated, and documented in `docs/configuration.md` once the operator documentation exists
- [ ] New metrics are added to the metrics constants module and to the design document's metrics table
- [ ] Linux-only code is behind `cfg(target_os = "linux")` and the workspace still builds on macOS
- [ ] The `Unreleased` section of `CHANGELOG.md` is updated once the changelog exists
- [ ] Reviewed by someone who did not write it; the reviewer ticks this list
- [ ] For a change that implements a backlog ticket, the ticket's status is updated and the master file regenerated
