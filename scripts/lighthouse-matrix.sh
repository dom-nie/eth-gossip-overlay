#!/usr/bin/env bash
# Runs overlay-bn's matrix tests against a real Lighthouse release.
#
#   scripts/lighthouse-matrix.sh <version> [--ten-minutes]
#
# Downloads the release artefact for this host into ${LIGHTHOUSE_CACHE:-/tmp}/lighthouse-<version>
# (skipped when it is already there), builds fleet-overlay, starts a beacon node on sepolia with
# no discovery, no execution layer and the sidecar's peer id as its only trusted peer, and runs
# `cargo test -p overlay-bn --test matrix -- --ignored`. Sepolia because its genesis state is
# built into the binary; the node stays at genesis and syncs nothing, which is all the tests
# need. --ten-minutes (or MATRIX_TEN_MINUTES=1) turns on the ten-minute assertion T-019 owns.
#
# LIGHTHOUSE_TARGET_PEERS is the beacon node's --target-peers, 0 as the ticket has it. On
# v8.2.2 that admits no inbound connection at all, trusted or not (libp2p's connection limit
# is ceil(0.9 * target) and counts before it knows the peer), so the matrix fails by name on
# CL-N2 (1); at 1 the sidecar is admitted and the rest of the suite runs. See T-018's open
# questions.
set -euo pipefail

version=${1:?usage: $0 <version> [--ten-minutes]}
version=v${version#v}
if [[ ${2:-} == --ten-minutes ]]; then
  export MATRIX_TEN_MINUTES=1
fi

case "$(uname -sm)" in
  "Linux x86_64") triple=x86_64-unknown-linux-gnu ;;
  "Linux aarch64") triple=aarch64-unknown-linux-gnu ;;
  "Darwin arm64") triple=aarch64-apple-darwin ;;
  "Darwin x86_64") triple=x86_64-apple-darwin ;;
  *) echo "no Lighthouse release artefact for $(uname -sm)" >&2; exit 1 ;;
esac

cache=${LIGHTHOUSE_CACHE:-/tmp}/lighthouse-$version
if [[ ! -x $cache/lighthouse ]]; then
  mkdir -p "$cache"
  url=https://github.com/sigp/lighthouse/releases/download/$version/lighthouse-$version-$triple.tar.gz
  echo "downloading $url"
  curl -fsSL "$url" | tar xz -C "$cache"
fi
"$cache/lighthouse" --version | head -1

root=$(cd "$(dirname "$0")/.." && pwd)
cargo build --manifest-path "$root/Cargo.toml" -p fleet-overlay --bin fleet-overlay

work=$(mktemp -d)
bn_pid=
cleanup() {
  if [[ -n $bn_pid ]]; then
    kill "$bn_pid" 2>/dev/null || true
    wait "$bn_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

printf 'bn: { node_key_file: %s }\n' "$work/node.key" > "$work/config.yaml"
peer_id=$("$root/target/debug/fleet-overlay" peer-id --config "$work/config.yaml")
od -An -tx1 -N32 /dev/urandom | tr -d ' \n' > "$work/jwt.hex"

free_port() {
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}
p2p_port=$(free_port)
http_port=$(free_port)

"$cache/lighthouse" bn \
  --network sepolia \
  --datadir "$work/datadir" \
  --disable-discovery \
  --disable-upnp \
  --disable-quic \
  --disable-enr-auto-update \
  --listen-address 127.0.0.1 \
  --port "$p2p_port" \
  --http \
  --http-address 127.0.0.1 \
  --http-port "$http_port" \
  --target-peers "${LIGHTHOUSE_TARGET_PEERS:-0}" \
  --trusted-peers "$peer_id" \
  --execution-endpoint http://127.0.0.1:1 \
  --execution-jwt "$work/jwt.hex" \
  --allow-insecure-genesis-sync \
  --ignore-ws-check \
  > "$work/lighthouse.log" 2>&1 &
bn_pid=$!

for _ in $(seq 1 120); do
  if curl -fsS -m 2 "http://127.0.0.1:$http_port/eth/v1/node/version" > /dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$bn_pid" 2>/dev/null; then
    echo "lighthouse exited before its HTTP API came up:" >&2
    tail -20 "$work/lighthouse.log" >&2
    exit 1
  fi
  sleep 1
done
curl -fsS -m 2 "http://127.0.0.1:$http_port/eth/v1/node/version"; echo

export LIGHTHOUSE_HTTP=http://127.0.0.1:$http_port
export LIGHTHOUSE_P2P=/ip4/127.0.0.1/tcp/$p2p_port
export SIDECAR_NODE_KEY=$work/node.key
export LIGHTHOUSE_LOG=$work/lighthouse.log
status=0
# One test at a time: they share the node key, and the beacon node allows one connection per peer.
cargo test --manifest-path "$root/Cargo.toml" -p overlay-bn --test matrix -- --ignored --nocapture --test-threads=1 || status=$?
if [[ $status -ne 0 ]]; then
  echo "--- lighthouse log, last 40 lines ---" >&2
  tail -40 "$work/lighthouse.log" >&2
fi
exit $status
