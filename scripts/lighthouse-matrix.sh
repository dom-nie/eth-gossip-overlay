#!/usr/bin/env bash
# Runs overlay-bn's matrix tests against a real Lighthouse release.
#
#   scripts/lighthouse-matrix.sh <version> [--ten-minutes]
#
# Downloads the release artefact for this host into ${LIGHTHOUSE_CACHE:-/tmp}/lighthouse-<version>
# (skipped when it is already there), builds eth-gossip-overlay, starts a beacon node on sepolia with
# no discovery, no execution layer, the sidecar's peer id as its only trusted peer and the
# sidecar's listen address as a libp2p node to dial (both flags of MD-01's env file), and runs
# `cargo test -p overlay-bn --test matrix -- --ignored`. It then runs the eth-gossip-overlay binary
# against the same node and waits for the node to call it trusted, which is the only check here
# that covers what the shipped binary is built from rather than what a test build links.
# Sepolia because its genesis state is built into the binary; the node stays at genesis and
# syncs nothing, which is all the tests need. --ten-minutes (or MATRIX_TEN_MINUTES=1) turns on
# the ten-minute assertion T-019 owns.
#
# LIGHTHOUSE_TARGET_PEERS is the beacon node's --target-peers, 1 by default (MD-01): at 0
# v8.2.2 denies every inbound connection before it knows the peer, trusted or not, with
# `Exceeded { limit: 0, kind: EstablishedIncoming }`, because libp2p's connection limit is
# ceil(0.9 * target). At 1 the sidecar has the one slot. The test that needs that slot taken
# attaches its own dummy peer to fill it, so the other tests still connect the way they did.
#
# --libp2p-addresses is deprecated at v8.2.2 in favour of --boot-nodes, which cannot carry a
# local peer without replacing the network's boot ENRs. Passing it here is what tells us the
# day a Lighthouse release removes it: the beacon node refuses to start and the matrix fails.
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
cargo build --manifest-path "$root/Cargo.toml" -p eth-gossip-overlay --bin eth-gossip-overlay

work=$(mktemp -d)
bn_pid=
sidecar_pid=
cleanup() {
  if [[ -n $sidecar_pid ]]; then
    kill "$sidecar_pid" 2>/dev/null || true
    wait "$sidecar_pid" 2>/dev/null || true
  fi
  if [[ -n $bn_pid ]]; then
    kill "$bn_pid" 2>/dev/null || true
    wait "$bn_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT

printf 'bn: { node_key_file: %s }\n' "$work/node.key" > "$work/config.yaml"
peer_id=$("$root/target/debug/eth-gossip-overlay" peer-id --config "$work/config.yaml")
od -An -tx1 -N32 /dev/urandom | tr -d ' \n' > "$work/jwt.hex"

free_port() {
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}
p2p_port=$(free_port)
http_port=$(free_port)
listen_port=$(free_port)
sidecar_listen=/ip4/127.0.0.1/tcp/$listen_port

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
  --target-peers "${LIGHTHOUSE_TARGET_PEERS:-1}" \
  --trusted-peers "$peer_id" \
  --libp2p-addresses "$sidecar_listen/p2p/$peer_id" \
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
export SIDECAR_LISTEN=$sidecar_listen
# The beacon node's own file log, not its stdout: the file logger runs at debug level, where
# the peer manager records what it does with a peer (metadata refused, goodbye sent), while
# stdout is at info and never names a peer at all.
export LIGHTHOUSE_LOG=$work/datadir/beacon/logs/beacon.log
status=0
# One test at a time: they share the node key, and the beacon node allows one connection per peer.
cargo test --manifest-path "$root/Cargo.toml" -p overlay-bn --test matrix -- --ignored --nocapture --test-threads=1 || status=$?

# The one thing the tests above cannot check: the shipped binary. They link lighthouse_network,
# which turns libp2p's secp256k1 feature on for a test build, so they pass whether or not
# eth-gossip-overlay itself can decode a Lighthouse identity. This runs the binary an operator runs,
# against the same beacon node, and asks the beacon node whether it arrived. It comes last so it
# takes the peer slot only once the tests are done with it.
overlay_port=$(free_port)
metrics_port=$(free_port)
"$root/target/debug/eth-gossip-overlay" gen-seed --out "$work/seed" > /dev/null
cat > "$work/roster.yaml" <<ROSTER
hosts:
  - hostname: matrix
    region: eu
    site: matrix
    addr: "127.0.0.1:$overlay_port"
ROSTER
# listen_addr on an ephemeral port, so the only path to the beacon node is the sidecar's own
# dial. The tests own the other direction, and a fixed port here collides with the beacon node's
# dial to it under libp2p's TCP port reuse.
cat > "$work/sidecar.yaml" <<CONF
overlay:
  listen: "127.0.0.1:$overlay_port"
  roster_file: $work/roster.yaml
  fleet_seed_file: $work/seed
bn:
  identity_url: $LIGHTHOUSE_HTTP/eth/v1/node/identity
  events_url: $LIGHTHOUSE_HTTP/eth/v1/events?topics=block
  libp2p_addr: $LIGHTHOUSE_P2P
  node_key_file: $work/node.key
  listen_addr: /ip4/127.0.0.1/tcp/0
admin_socket: $work/admin.sock
metrics_listen: 127.0.0.1:$metrics_port
CONF
ETH_GOSSIP_OVERLAY_HOSTNAME=matrix "$root/target/debug/eth-gossip-overlay" run --config "$work/sidecar.yaml" \
  > "$work/sidecar.log" 2>&1 &
sidecar_pid=$!

trusted=0
for _ in $(seq 1 60); do
  if [[ $(curl -fsS -m 2 "http://127.0.0.1:$metrics_port/metrics" 2>/dev/null \
    | awk '$1 == "overlay_bn_trusted" {print $2}') == 1 ]]; then
    trusted=1
    break
  fi
  sleep 1
done
kill "$sidecar_pid" 2>/dev/null || true
wait "$sidecar_pid" 2>/dev/null || true
sidecar_pid=
if [[ $trusted == 1 ]]; then
  echo "the shipped binary paired with the beacon node, which lists it as trusted"
else
  cat >&2 <<'WHY'
the shipped eth-gossip-overlay binary never paired with the beacon node.
The tests above cannot see this: they link lighthouse_network, which turns libp2p's secp256k1
feature on for a test build, while the binary is built without it. A dial ending in `Invalid
public key` means the workspace Cargo.toml's libp2p is missing the secp256k1 feature.
WHY
  tail -20 "$work/sidecar.log" >&2
  status=1
fi

if [[ $status -ne 0 ]]; then
  echo "--- lighthouse log, last 40 lines ---" >&2
  tail -40 "$work/lighthouse.log" >&2
fi
exit $status
