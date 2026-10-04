# syntax=docker/dockerfile:1

# The sidecar as an OCI image: the two binaries, a libc and a non-root user that owns the node
# key. Nothing else, because the binaries take every path from the config and the command line,
# and without NOTIFY_SOCKET the notify and watchdog calls are no-ops.
#
# Run it with --network host. QUIC through a port mapping adds a hop of latency and hides path
# MTU discovery from the endpoint; examples/compose/README.md has the detail.

FROM rust:1.99-bookworm AS builder

# The state directory the runtime stage takes as it is. It is made here because the runtime has
# no shell to make one there.
RUN install -d -m 750 /state

WORKDIR /src
COPY . .

# The registry, the git checkouts and the target directory are cached, because the workspace
# compiles libp2p from Lighthouse's fork and no one should pay for that twice. That puts
# target/ outside the layer, so the install has to happen in the same step.
#
# SOURCE_DATE_EPOCH comes from the commit rather than the clock, which is what build.rs reads
# and what lets two builds of one commit produce one binary.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/src/target \
    SOURCE_DATE_EPOCH="$(git log -1 --format=%ct 2> /dev/null || echo 0)" \
    cargo build --release --locked -p eth-gossip-overlay --bins \
    && install -m 755 target/release/eth-gossip-overlay target/release/eth-gossip-overlayctl /usr/local/bin/

# The same binaries with a shell around them, for the setup step in examples/compose that has to
# write a file and hand over a volume. Not the image an operator runs.
FROM debian:bookworm-slim AS toolbox
COPY --from=builder /usr/local/bin/eth-gossip-overlay /usr/local/bin/eth-gossip-overlayctl /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/eth-gossip-overlay"]

FROM gcr.io/distroless/cc-debian12:nonroot

LABEL org.opencontainers.image.source="https://github.com/dom-nie/eth-gossip-overlay" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.licenses="Apache-2.0"

# /var/lib/eth-gossip-overlay holds the node key, which is the peer id the beacon node trusts: give it
# a volume or every restart is a new identity. 65532 is the base image's nonroot user, a fixed
# uid so an operator can chown a host directory before the container ever starts.
COPY --from=builder --chown=65532:65532 /state /var/lib/eth-gossip-overlay
# /run/eth-gossip-overlay is where the shipped config binds the admin socket and where the env
# file for the beacon node is written. systemd makes it with RuntimeDirectory=; here nothing
# would, and the sidecar's start ends at that bind, so the image carries it with the same owner.
COPY --from=builder --chown=65532:65532 /state /run/eth-gossip-overlay
COPY --from=builder /usr/local/bin/eth-gossip-overlay /usr/local/bin/eth-gossip-overlayctl /usr/local/bin/

USER 65532:65532
EXPOSE 7788/udp 7789/tcp
ENTRYPOINT ["/usr/local/bin/eth-gossip-overlay"]
CMD ["run", "--config", "/etc/eth-gossip-overlay/config.yaml"]
