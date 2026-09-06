# Fleet Gossip Overlay

[![CI](https://github.com/dom-nie/eth-bn-gossip-overlay/actions/workflows/ci.yml/badge.svg)](https://github.com/dom-nie/eth-bn-gossip-overlay/actions/workflows/ci.yml)

A sidecar for [Lighthouse](https://github.com/sigp/lighthouse) beacon nodes. Drop `fleet-overlay` next to each node you run and the sidecars build a private QUIC overlay between your own machines, so blocks, blobs and columns one of your nodes has already validated reach the others without a second trip through the public gossip mesh. `fleet-overlayctl` talks to a running sidecar over its admin socket.

It is for operators who run several Lighthouse beacon nodes they control, whether that is three hosts in one rack or a few hundred spread over regions. Only your own hosts join the overlay: admission is a key derived from a seed you generate once and copy to every host.

The overlay is an accelerator, never a dependency. Every beacon node keeps its own public peers, the sidecar holds no validator keys and creates no messages, and the receiving node validates everything that arrives through it as it would any other gossip. When the overlay is down, or a sidecar dies, the node carries on as if it had never had one; nothing gets worse.

The quickstart in docs/quickstart.md arrives with the operator documentation.

## Build

Rust is pinned by `rust-toolchain.toml`; rustup picks it up on the first `cargo` call.

```sh
cargo build --release          # binaries in target/release/{fleet-overlay,fleet-overlayctl}
```

`overlay-bn` links `libp2p` from Lighthouse's fork (`sigp/rust-libp2p`) at the revision Lighthouse **v8.2.2** pins, through the `[patch]` table in the root `Cargo.toml`. Bumping Lighthouse means updating that tag, the rev next to it, and rerunning T-018's compatibility matrix.

## Subcommands

`fleet-overlay gen-seed [--out PATH]` writes a new fleet seed: 32 bytes from the OS random number generator as 64 hex characters, mode 0600, default `/etc/fleet-overlay/seed`. It refuses to overwrite an existing file. Run it once per fleet and copy the file to every host over a secure channel; every host's overlay TLS key derives from it and its hostname.

`fleet-overlay peer-id [--config PATH]` prints the libp2p peer id of this host's node key (`bn.node_key_file`, created on first use). That is the id the sidecar hands Lighthouse through `/run/fleet-overlay/lighthouse.env` once T-045 lands, so it is how an operator reads the value ahead of time. It needs neither the seed nor the roster. The node key is per host and unrelated to the seed, so rotating the seed never changes the peer id.

`fleet-overlayctl` talks to a running sidecar over the admin socket in `admin_socket` (`/run/fleet-overlay/admin.sock` by default), which is mode 0660 and local only. `status` is the first thing to look at during a rolling upgrade: it prints the kill switch, the beacon node's version and whether it trusts the sidecar, and one row per live peer with its software version and the feature bits the pair negotiated. `roster reload` re-reads `config.yaml` and `roster.yaml` exactly as SIGHUP does, and applies whatever the files say. Exit codes are meant for configuration management: 0 the command took effect, 1 the sidecar refused it or the reload reported an error, 2 there was no socket to talk to.

```console
$ fleet-overlayctl --help
Talk to a running fleet-overlay sidecar over its local admin socket

Usage: fleet-overlayctl [OPTIONS] <COMMAND>

Commands:
  inject  Turn the inject kill switch on or off, or ask what it is
  status  Print what the sidecar is doing: the kill switch, the beacon node and every live peer
  roster  Print the roster the sidecar is using, or make it read the files again
  help    Print this message or the help of the given subcommand(s)

Options:
      --socket <SOCKET>  The sidecar's admin socket [default: /run/fleet-overlay/admin.sock]
      --json             Print the sidecar's answer as it came, one JSON object, for jq and scripts
  -h, --help             Print help
  -V, --version          Print version
```

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

## Contributing and policies

[CONTRIBUTING.md](CONTRIBUTING.md) explains the test-first workflow, the commit convention, the sign-off and the pull request checklist. The design document and the ticket backlog it refers to are maintained outside this repository. [SECURITY.md](SECURITY.md) says how to report a vulnerability privately and what the overlay's key pinning does and does not protect. [COMPATIBILITY.md](COMPATIBILITY.md) lists the supported Rust toolchain, Lighthouse version and platforms.
