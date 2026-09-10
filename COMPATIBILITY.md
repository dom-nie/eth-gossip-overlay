# Compatibility

## Rust

The supported Rust is the latest stable minus two minor versions. `rust-toolchain.toml` pins the exact toolchain the project builds with, currently 1.98.1, and rustup installs it on the first `cargo` call. Nothing older than the pinned toolchain has been tested, so the crates carry no `rust-version` field; one arrives together with a CI job that builds on the oldest supported version.

## Lighthouse

The text between the markers is generated from `overlay_bn::compat` by `UPDATE_COMPATIBILITY_MD=1 cargo test -p overlay-bn compatibility_md_matches_the_constant`; the same test fails when it is stale.

<!-- compat:begin -->
Supported: Lighthouse v8.2.2 only, last verified 2026-09-06. The range is exactly the versions the compatibility matrix has passed and grows only with a matrix run. The workspace is built against v8.2.2: the tag the root `Cargo.toml` pins for `lighthouse_network` and `types`, and the `sigp/rust-libp2p` revision that tag pins, through the `[patch]` table. A beacon node above the range is reported `untested` and one below it `unsupported`, on every connect, in the log and in `overlay_bn_compat{state}`; the sidecar keeps running either way.

The design leans on seven Lighthouse behaviours that no specification promises. Each has a named test, so a release that changes one fails the matrix by name instead of degrading the fleet quietly. Tests marked matrix need a real beacon node and run in the nightly matrix; the others run on every pull request against `FakeBn`.

| Assumption | Test |
|---|---|
| A trusted peer is admitted whenever the beacon node is under its inbound cap, is dialled by the beacon node through `--libp2p-addresses` at startup and through `add_peer` on demand under the outbound cap, and is never pruned once connected (MD-01) | under the cap and never pruned: `matrix_trusted_peer_is_admitted_under_the_inbound_cap_and_never_pruned` (matrix); the beacon node dialling a sidecar it has no inbound room for: `matrix_bn_dials_the_listening_sidecar_when_its_inbound_cap_is_full` (matrix); the startup flag: `matrix_bn_startup_flags_dial_the_listening_sidecar` (matrix) |
| A trusted peer is neither disconnected nor banned after one invalid message and after a period of duplicates only | `matrix_trusted_peer_survives_one_invalid_message_and_a_period_of_duplicates_only` (matrix) |
| The beacon node forwards a validated message to an explicit peer that is subscribed but not in its mesh | `bn_forwards_validated_message_to_a_subscribed_explicit_peer_outside_its_mesh` |
| The beacon node's `publish` reaches an explicit peer on a topic the beacon node is not subscribed to, and only if that peer is | `bn_publish_reaches_explicit_peer_on_a_topic_the_bn_is_not_subscribed_to_and_needs_the_sidecar_subscription` |
| The beacon node honours IDONTWANT from an explicit peer, and with partial messages compiled in still sends full messages to a peer that did not negotiate them | `bn_honours_idontwant_from_explicit_peer_and_sends_full_messages_without_partial_message_negotiation` |
| The beacon node's message id equals the sidecar's for the same topic and payload | `published_message_id_matches_fake_bn_for_random_payloads` |
| The event stream fires `block_gossip` inside gossip verification, after the proposer-signature and duplicate checks, and `data_column_sidecar` after KZG verification for a column from any of its four sources: gossip, partial-message merges, the execution layer's `getBlobs` and RPC by root (MD-06) | `matrix_event_stream_reports_accepted_blocks_and_verified_columns` (matrix), which pins that both events reach the custody tracker on a running node; which of the four sources a column came from is not in the payload and is not asserted |

The sidecar is a standard gossipsub peer. Other consensus clients' trusted-peer features are untested and nothing here claims to support them.
<!-- compat:end -->

## Platforms

Release binaries are built for Linux on x86_64 and aarch64. macOS builds the workspace and runs the test suite, for development only; Linux-only code sits behind `cfg(target_os = "linux")` and the sidecar is not supported on macOS in production.
