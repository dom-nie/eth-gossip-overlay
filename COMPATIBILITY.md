# Compatibility

## Rust

The supported Rust is the latest stable minus two minor versions. `rust-toolchain.toml` pins the exact toolchain the project builds with, currently 1.98.1, and rustup installs it on the first `cargo` call. Nothing older than the pinned toolchain has been tested, so the crates carry no `rust-version` field; one arrives together with a CI job that builds on the oldest supported version.

## Lighthouse

Lighthouse v8.2.2, the tag the root `Cargo.toml` pins for `lighthouse_network`, `types` and the `sigp/rust-libp2p` fork. The tested version matrix and the startup check against a running beacon node arrive with the Lighthouse compatibility work (T-018).

## Platforms

Release binaries are built for Linux on x86_64 and aarch64. macOS builds the workspace and runs the test suite, for development only; Linux-only code sits behind `cfg(target_os = "linux")` and the sidecar is not supported on macOS in production.
