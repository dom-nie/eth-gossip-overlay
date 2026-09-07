What and why, in a sentence or two:

Ticket: T-NNN, or none

## Checklist

- [ ] Every test in the change's test plan exists, is named after the behaviour it checks, and passes with `cargo test --workspace`
- [ ] `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` are clean
- [ ] No `unwrap()`, `expect()` or `panic!` in non-test code unless a comment explains why it cannot fail
- [ ] Public items have a doc comment that says what and why, not how; no comment blocks restating the code
- [ ] New config keys are parsed in `overlay-core`'s `Config`, defaulted, validated, and documented in `docs/configuration.md` once the operator documentation exists
- [ ] New metrics are added to the metrics constants module and to the design document's metrics table
- [ ] Linux-only code is behind `cfg(target_os = "linux")` and the workspace still builds on macOS
- [ ] The `Unreleased` section of `CHANGELOG.md` says what this change gives an operator, or the pull request carries the `skip-changelog` label
- [ ] Reviewed by someone who did not write it; the reviewer ticks this list
- [ ] For a change that implements a backlog ticket, the ticket's status is updated and the master file regenerated
