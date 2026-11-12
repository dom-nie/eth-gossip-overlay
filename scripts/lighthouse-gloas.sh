#!/usr/bin/env bash
# The Gloas half of the Lighthouse matrix (T-121), run by `scripts/lighthouse-matrix.sh
# <version> --gloas`:
#
#   scripts/lighthouse-gloas.sh <lighthouse binary> <version>
#
# Brings up a devnet with Gloas active from genesis the way Lighthouse's own
# scripts/local_testnet does, with Kurtosis and ethereum-package: two Lighthouse beacon nodes
# with validators and an execution client each (both supernodes, so every column is on their
# subnets), spamoor sending blob transactions so every block carries blobs, and a third
# execution client whose kurtosis beacon node is stopped so that the downloaded release binary
# can run against it as the "far" node: no discovery, no boot nodes, so its only gossip peers
# are sidecars. The shipped eth-gossip-overlay runs on both nodes as a two-host roster, and
# a catch-up loop posts the far node the blocks and payload envelopes it lacks over the beacon
# API whenever it falls three slots behind: the shipped sidecar skips the first block after it
# starts (D42) and the far node has nobody to range-sync from. Then the five Gloas tests in
# crates/overlay-bn/tests/matrix.rs run with a harness as the far node's second peer.
#
# Local only. It needs Docker and Kurtosis, pulls the ethereum-package images, and a full run
# is about 40 minutes at MATRIX_SLOTS=64, which is more than the nightly matrix job's budget;
# the nightly stays on Sepolia at genesis. GLOAS_KEEP=1 leaves the enclave and the far node
# running after the tests, for a look around with `kurtosis enclave inspect eth-gossip-gloas`.
set -euo pipefail

lighthouse=${1:?usage: $0 <lighthouse binary> <version>}
version=${2:?usage: $0 <lighthouse binary> <version>}
enclave=eth-gossip-gloas
slot_seconds=6
root=$(cd "$(dirname "$0")/.." && pwd)
bin=$root/target/debug/eth-gossip-overlay
ctl=$root/target/debug/eth-gossip-overlayctl

for tool in docker kurtosis python3; do
  command -v "$tool" > /dev/null || { echo "$tool is needed for the Gloas devnet" >&2; exit 1; }
done

work=$(mktemp -d)
pids=()
cleanup() {
  for pid in "${pids[@]}"; do
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  done
  if [[ ${GLOAS_KEEP:-0} != 1 ]]; then
    kurtosis enclave rm -f "$enclave" > /dev/null 2>&1 || true
    rm -rf "$work"
  else
    echo "kept: enclave $enclave and $work"
  fi
}
trap cleanup EXIT

free_port() {
  python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])'
}
# Kurtosis prints its own notices before the answer, so only the last line is the port.
published() { kurtosis port print "$enclave" "$1" "$2" 2>/dev/null | tail -1; }
head_slot() {
  curl -fsS -m 3 "$1/eth/v1/beacon/headers/head" 2>/dev/null \
    | python3 -c 'import sys, json; print(json.load(sys.stdin)["data"]["header"]["message"]["slot"])' 2>/dev/null
}

# ---- the devnet ----------------------------------------------------------------------------
cat > "$work/params.yaml" <<PARAMS
participants:
  - cl_type: lighthouse
    cl_image: sigp/lighthouse:$version
    el_type: geth
    supernode: true
    cl_extra_params: ["--target-peers=8"]
  - cl_type: lighthouse
    cl_image: sigp/lighthouse:$version
    el_type: geth
    supernode: true
    cl_extra_params: ["--target-peers=8"]
  - cl_type: lighthouse
    cl_image: sigp/lighthouse:$version
    el_type: geth
    validator_count: 0
network_params:
  gloas_fork_epoch: 0
  seconds_per_slot: $slot_seconds
  genesis_delay: 60
  num_validator_keys_per_node: 64
additional_services:
  - spamoor
spamoor_params:
  spammers:
    - scenario: eoatx
      config:
        throughput: 20
    - scenario: blobs
      config:
        throughput: 4
global_log_level: info
PARAMS
kurtosis enclave rm -f "$enclave" > /dev/null 2>&1 || true
# The resource check reserves a core per service, which a laptop's Docker VM does not have.
kurtosis run --resource-check=false --enclave "$enclave" \
  github.com/ethpandaops/ethereum-package@main --args-file "$work/params.yaml"

near_http=$(published cl-1-lighthouse-geth http)
near_p2p=$(published cl-1-lighthouse-geth tcp-discovery)
near_metrics=$(published cl-1-lighthouse-geth metrics)
engine=$(published el-3-geth-lighthouse engine-rpc)
kurtosis service stop "$enclave" cl-3-lighthouse-geth > /dev/null
kurtosis files download "$enclave" el_cl_genesis_data "$work/testnet" > /dev/null
kurtosis files download "$enclave" jwt_file "$work/jwt" > /dev/null
cp "$work/testnet/deposit_contract_block.txt" "$work/testnet/deploy_block.txt"
curl -fsS "$near_http/eth/v1/config/spec" \
  | python3 -c 'import sys, json; d = json.load(sys.stdin)["data"]; print("spec:", {k: d[k] for k in ["PRESET_BASE", "SECONDS_PER_SLOT", "GLOAS_FORK_EPOCH", "FULU_FORK_EPOCH", "NUMBER_OF_COLUMNS"]})'

# ---- the far node: the downloaded release binary, isolated ---------------------------------
far_p2p_port=$(free_port)
far_http_port=$(free_port)
far_metrics_port=$(free_port)
"$lighthouse" bn \
  --testnet-dir "$work/testnet" \
  --datadir "$work/far" \
  --disable-discovery \
  --disable-upnp \
  --disable-quic \
  --disable-enr-auto-update \
  --listen-address 127.0.0.1 \
  --port "$far_p2p_port" \
  --http \
  --http-address 127.0.0.1 \
  --http-port "$far_http_port" \
  --metrics \
  --metrics-address 127.0.0.1 \
  --metrics-port "$far_metrics_port" \
  --target-peers 2 \
  --execution-endpoint "http://$engine" \
  --execution-jwt "$work/jwt/jwtsecret" \
  --allow-insecure-genesis-sync \
  --ignore-ws-check \
  > "$work/far.log" 2>&1 &
pids+=($!)
far_http=http://127.0.0.1:$far_http_port
for _ in $(seq 1 60); do
  curl -fsS -m 2 "$far_http/eth/v1/node/version" > /dev/null 2>&1 && break
  sleep 1
done
curl -fsS "$far_http/eth/v1/node/version"; echo

# ---- the catch-up loop ----------------------------------------------------------------------
# Lighthouse refuses an envelope for a block that commits to blobs unless the blobs and their
# cell proofs come with it, so both are rebuilt from the near node's column sidecars: the
# first 64 columns are the blob data cell by cell, and each column carries one proof per blob.
post_envelope() {
  python3 - "$near_http" "$far_http" "$1" <<'PY'
import json, sys, urllib.error, urllib.request
source, target, slot = sys.argv[1:4]
get = lambda url: json.loads(urllib.request.urlopen(url, timeout=30).read())
envelope = get(f"{source}/eth/v1/beacon/execution_payload_envelopes/{slot}")["data"]
columns = get(f"{source}/eth/v1/debug/beacon/data_column_sidecars/{slot}")["data"]
by_index = {int(c["index"]): c for c in columns}
blobs = len(columns[0]["column"]) if columns else 0
if blobs:
    body = {
        "signed_execution_payload_envelope": envelope,
        "kzg_proofs": [by_index[c]["kzg_proofs"][i] for i in range(blobs) for c in range(128)],
        "blobs": ["0x" + "".join(by_index[c]["column"][i][2:] for c in range(64)) for i in range(blobs)],
    }
else:
    body = envelope
request = urllib.request.Request(
    f"{target}/eth/v1/beacon/execution_payload_envelopes",
    data=json.dumps(body).encode(), method="POST",
    headers={"Content-Type": "application/json", "Eth-Consensus-Version": "gloas",
             "Eth-Blob-Data-Included": "true" if blobs else "false"})
try:
    with urllib.request.urlopen(request, timeout=60) as answer:
        print(answer.status, "envelope", slot, blobs, "blobs")
except urllib.error.HTTPError as err:
    print(err.code, "envelope", slot, err.read()[:120])
PY
}
post_block() {
  local body
  body=$(mktemp)
  if curl -fsS -m 5 -H 'Accept: application/octet-stream' -o "$body" "$near_http/eth/v2/beacon/blocks/$1" 2>/dev/null; then
    curl -sS -m 10 -o /dev/null -w "%{http_code} block $1\n" -X POST \
      -H 'Content-Type: application/octet-stream' -H 'Eth-Consensus-Version: gloas' \
      --data-binary "@$body" "$far_http/eth/v2/beacon/blocks"
  fi
  rm -f "$body"
}
catch_up() {
  while true; do
    local near far
    near=$(head_slot "$near_http"); far=$(head_slot "$far_http")
    if [[ -n $near && -n $far && $((near - far)) -ge 3 ]]; then
      echo "$(date +%T) far node at $far, near at $near"
      # The head's own envelope first: a child of a FULL parent is ParentUnknown without it.
      for s in $(seq "$far" "$near"); do
        [[ $s -gt $far ]] && post_block "$s"
        post_envelope "$s"
      done
    fi
    sleep 3
  done
}
catch_up > "$work/catch-up.log" 2>&1 &
pids+=($!)

# ---- the two shipped sidecars -----------------------------------------------------------------
near_overlay=$(free_port); far_overlay=$(free_port)
cat > "$work/roster.yaml" <<ROSTER
hosts:
  - hostname: near
    region: eu
    site: devnet
    addr: "127.0.0.1:$near_overlay"
  - hostname: far
    region: eu
    site: devnet
    addr: "127.0.0.1:$far_overlay"
ROSTER
"$bin" gen-seed --out "$work/seed" > /dev/null
# Unix socket paths are capped at about a hundred bytes, which mktemp's directory can exceed.
socket_dir=$(mktemp -d /tmp/eg-XXXXXX)
sidecar_config() { # $1 hostname, $2 overlay port, $3 beacon http, $4 beacon p2p, $5 metrics port
  cat > "$work/$1.yaml" <<CONF
overlay:
  listen: "127.0.0.1:$2"
  roster_file: $work/roster.yaml
  fleet_seed_file: $work/seed
bn:
  identity_url: $3/eth/v1/node/identity
  events_url: $3/eth/v1/events?topics=block,block_gossip,data_column_sidecar,execution_payload_gossip
  libp2p_addr: $4
  node_key_file: $work/$1.key
  listen_addr: /ip4/127.0.0.1/tcp/0
admin_socket: $socket_dir/$1.sock
metrics_listen: 127.0.0.1:$5
log:
  format: json
CONF
}
near_sidecar_metrics=$(free_port); far_sidecar_metrics=$(free_port)
sidecar_config near "$near_overlay" "$near_http" "/ip4/127.0.0.1/tcp/${near_p2p##*:}" "$near_sidecar_metrics"
sidecar_config far "$far_overlay" "$far_http" "/ip4/127.0.0.1/tcp/$far_p2p_port" "$far_sidecar_metrics"
ETH_GOSSIP_OVERLAY_HOSTNAME=near "$bin" run --config "$work/near.yaml" > "$work/near-sidecar.log" 2>&1 &
pids+=($!)
ETH_GOSSIP_OVERLAY_HOSTNAME=far "$bin" run --config "$work/far.yaml" > "$work/far-sidecar.log" 2>&1 &
pids+=($!)

for _ in $(seq 1 120); do
  if [[ $(curl -fsS -m 2 "http://127.0.0.1:$far_sidecar_metrics/metrics" 2>/dev/null \
    | awk '$1 == "overlay_peers_connected{region=\"eu\",site=\"devnet\"}" {print $2}') == 1 ]]; then
    break
  fi
  sleep 1
done
# In step: the far node within a slot of the near one, which the catch-up loop brings about.
for _ in $(seq 1 180); do
  near=$(head_slot "$near_http"); far=$(head_slot "$far_http")
  if [[ -n $near && -n $far && $((near - far)) -le 1 ]]; then break; fi
  sleep 2
done
echo "near node at slot $near, far node at slot $far"
curl -fsS -H 'Accept: application/json' "$near_http/eth/v2/beacon/blocks/head" \
  | python3 -c 'import sys, json; d = json.load(sys.stdin); print("head block fork:", d["version"], "slot", d["data"]["message"]["slot"])'

# ---- the tests -------------------------------------------------------------------------------
export MATRIX_GLOAS=1
export LIGHTHOUSE_HTTP=$near_http
export LIGHTHOUSE_P2P=/ip4/127.0.0.1/tcp/${near_p2p##*:}
export LIGHTHOUSE_METRICS=http://$near_metrics
export LIGHTHOUSE_FAR_HTTP=$far_http
export LIGHTHOUSE_FAR_P2P=/ip4/127.0.0.1/tcp/$far_p2p_port
export LIGHTHOUSE_FAR_METRICS=http://127.0.0.1:$far_metrics_port
export LIGHTHOUSE_PROPOSERS=0-63
export SIDECAR_NODE_KEY=$work/harness.key
export SIDECAR_FAR_LOG=$work/far-sidecar.log
export SIDECAR_FAR_ADMIN=$socket_dir/far.sock
export SIDECAR_CTL=$ctl
export MATRIX_SLOTS=${MATRIX_SLOTS:-64}
status=0
cargo test --manifest-path "$root/Cargo.toml" -p overlay-bn --test matrix -- --ignored --nocapture \
  --test-threads=1 --exact \
  matrix_every_gloas_kind_crosses_the_overlay \
  matrix_the_node_forwards_full_columns_to_its_explicit_peer_with_partials_on \
  matrix_execution_payload_gossip_fires_once_per_envelope_from_any_source \
  matrix_column_repair_is_quiet_on_a_healthy_gloas_chain \
  matrix_a_block_whose_parent_envelope_the_node_lacks || status=$?

if [[ $status -ne 0 ]]; then
  echo "--- far node log, last 40 lines ---" >&2
  tail -40 "$work/far.log" >&2
  echo "--- far sidecar log, last 20 lines ---" >&2
  tail -20 "$work/far-sidecar.log" >&2
fi
exit $status
