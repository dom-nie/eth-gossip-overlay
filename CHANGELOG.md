# Changelog

Everything worth telling an operator about, newest first. The format is [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the version numbers are [semantic](https://semver.org/spec/v2.0.0.html).

Every section also carries a `Protocol:` line, because the number that decides how an upgrade goes is not the one on the tarball. The protocol major travels in the overlay's ALPN and the minor and the feature bits in `HELLO`, so a release that only adds a feature bit pairs with every older host and can be rolled out in any order, and a major bump splits the fleet into two overlays until the last host is done. [docs/upgrading.md](docs/upgrading.md) is the procedure for both cases and [CONTRIBUTING.md](CONTRIBUTING.md) has the line's grammar.

## [Unreleased]

Protocol: major unchanged (1); features added: none

The first release, so all of it is new.

### Added

- `fleet-overlay`, a sidecar for a Lighthouse beacon node. It joins a QUIC mesh of the other sidecars you run and hands each beacon node the blocks, blobs and data columns another of your nodes has already validated, instead of leaving it to wait for the public gossip mesh. The beacon node keeps its public peers throughout and validates everything the sidecar injects, so a fleet with the overlay down is a fleet without the overlay.
- Admission by a key rather than a certificate. Every host derives its overlay TLS key from one fleet seed and its own hostname, so the roster is the whole membership list and there is nothing to issue or renew. `fleet-overlay gen-seed` writes the seed, and a second seed can be in force alongside it, which is what makes rotating one a rolling change rather than an outage.
- Version negotiation built for a fleet that is upgraded host by host: the protocol major in the ALPN, the minor, the feature bits and the frame limits in `HELLO`, and a pair that runs at the lower minor and the intersection of the bits.
- The beacon node link: the sidecar dials the node, registers itself as a trusted peer on every reconnect so the node dials back, mirrors whatever the node is subscribed to including every data-column topic per fork digest, injects under a rate limit and a kill switch, and answers the handful of req/resp methods a well-behaved peer has to answer.
- Lighthouse v8.2.2, with the version checked at every connect and reported in `overlay_bn_compat`, and a nightly matrix that runs the assumptions against a real beacon node. A Lighthouse identity is always a secp256k1 key, so the sidecar is built to verify one; it still signs with ed25519 itself.
- Deduplication in both directions from one seen cache, keyed by the consensus message id computed off the compressed payload, so nothing the local node has already seen is injected and nothing arriving twice is forwarded twice.
- A full mesh that repairs itself: one connection per pair, a reconnect with jittered backoff, a superseding handshake that tells a restarted peer from a moved one, and per-peer send queues bounded by bytes and by age so a slow peer costs its own lane and nothing else.
- Routing by subscription: a message goes only to the peers whose beacon node wants its topic, over 16-bit topic ids exchanged at connect and extended as the local subscriptions change.
- Prometheus metrics on `:7789`, one structured log stream on stdout, and an event log for large messages.
- `fleet-overlayctl`, over a local admin socket: `status` prints the kill switch, the beacon node and one row per live peer with the software version and the features that pair negotiated, `inject` flips the kill switch, and `roster reload` re-reads the files. `SIGHUP` does the same reload, without dropping a connection, and refuses an automatic one that would drop more than half the fleet.
- `fleet-overlay check-config`, which reads the same files a start reads and says who this host is and what it would hold, and `fleet-overlay peer-id`, which prints the id the beacon node has to trust before the sidecar has ever run.
- Deployment examples in `deploy/`: a systemd unit with readiness, a watchdog and the credential the seed arrives through, the sysctl drop-in, an nftables allowlist and the Ansible templates for the roster and the host name.
- A container image with the two binaries, a libc and a non-root user, and a compose demo in `examples/compose/` that runs three sidecars and three beacon nodes on one machine.
- Ten Prometheus alert rules and a Grafana dashboard in `deploy/`, and `docs/rollout.md`, which is how to get the sidecar onto a fleet without guessing whether it helped: a canary against a control group running the same code with injection off, the three numbers that decide it and the exact queries for them, and a rollback that is one command and needs no restart. Every alert links to a section of `docs/troubleshooting.md` saying what it means and what to look at first.
- Operator documentation in `docs/`, written for someone who runs beacon nodes and has never seen this project: a quickstart that goes from a downloaded binary to a message that arrived over the overlay, the beacon node's side of it, a configuration reference generated from the code so it cannot drift, the threat model and the seed-rotation procedure, and a runbook split between the alerts and the symptoms nothing alerts on.
- Tagged releases: Linux x86_64 and aarch64 tarballs with the binaries, the licence and `deploy/`, a `SHA256SUMS`, a provenance attestation, a published image, and release notes taken from this file.
