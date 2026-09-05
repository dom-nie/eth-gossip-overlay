# Fleet Gossip Overlay

A sidecar for [Lighthouse](https://github.com/sigp/lighthouse) beacon nodes. Drop `fleet-overlay` next to each node you run and the sidecars build a private QUIC overlay between your own machines, so blocks, blobs and columns your fleet already has reach your other nodes without a second trip through the public gossip mesh. `fleet-overlayctl` talks to a running sidecar over its admin socket.

The design document and the ticket backlog are maintained outside this repository. Work happens on one branch per ticket, test first: a failing test is committed, then the code that makes it pass, with commit subjects prefixed by the ticket id (`T-001: ...`).

## Build

Rust is pinned by `rust-toolchain.toml`; rustup picks it up on the first `cargo` call.

```sh
cargo build --release          # binaries in target/release/{fleet-overlay,fleet-overlayctl}
```

`overlay-bn` links `libp2p` from Lighthouse's fork (`sigp/rust-libp2p`) at the revision Lighthouse **v8.2.2** pins, through the `[patch]` table in the root `Cargo.toml`. Bumping Lighthouse means updating that tag, the rev next to it, and rerunning T-018's compatibility matrix.

## Test

```sh
cargo test --workspace                                     # everything; the first run also builds Lighthouse's crates as dev-dependencies
cargo test -p overlay-core                                 # the pure crate, seconds
cargo clippy --workspace --all-targets -- -D warnings      # what CI enforces
cargo fmt --all --check
```

## Layout

| Crate | What lives there |
|---|---|
| `crates/overlay-core` | pure logic: clock, backoff, and later routing, codecs, batching |
| `crates/overlay-transport` | QUIC between sidecars |
| `crates/overlay-bn` | the link to the local beacon node |
| `crates/fleet-overlay` | the two binaries and their wiring |
