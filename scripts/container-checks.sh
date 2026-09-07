#!/usr/bin/env bash
# T-047's checks against a real container runtime.
#
#   scripts/container-checks.sh [--with-beacon-nodes]
#
# Builds the image if it is not already there, then runs the five checks a container needs a
# daemon to answer: check-config against the shipped example files, a non-root user, the size
# budget, a node key that outlives its container, and the compose demo reaching a full mesh.
#
# The mesh check starts the three sidecars alone. A sidecar builds its overlay whether or not
# its beacon node is up, so the check needs no testnet and runs on every pull request.
# --with-beacon-nodes starts the whole demo instead and also asserts overlay_bn_trusted, which
# needs a testnet and minutes of checkpoint sync, so that variant runs nightly.
#
# IMAGE            the tag to build and check, fleet-overlay:demo by default
# TOOLBOX          the Dockerfile's toolbox stage, which the compose demo's setup step needs
# MAX_IMAGE_BYTES  the size budget, 80 MB by default
# MESH_TIMEOUT     seconds the mesh has to form, 120 by default and 900 with beacon nodes
set -euo pipefail

IMAGE=${IMAGE:-fleet-overlay:demo}
TOOLBOX=${TOOLBOX:-fleet-overlay:toolbox}
MAX_IMAGE_BYTES=${MAX_IMAGE_BYTES:-80000000}

root=$(cd "$(dirname "$0")/.." && pwd)
demo=$root/examples/compose
with_beacon_nodes=0
if [ "${1-}" = "--with-beacon-nodes" ]; then
  with_beacon_nodes=1
fi
MESH_TIMEOUT=${MESH_TIMEOUT:-$([ "$with_beacon_nodes" = 1 ] && echo 900 || echo 120)}

# The three metrics endpoints docker-compose.yml publishes, one per sidecar.
ports=(7789 7790 7791)
failed=0

pass() { printf 'ok   %s\n' "$*"; }
fail() {
  printf 'FAIL %s\n' "$*"
  failed=1
}

volume() {
  docker volume create "fleet-overlay-check-$1-$$" > /dev/null
  echo "fleet-overlay-check-$1-$$"
}

compose() {
  FLEET_OVERLAY_IMAGE=$IMAGE FLEET_OVERLAY_TOOLBOX_IMAGE=$TOOLBOX \
    docker compose -f "$demo/docker-compose.yml" "$@"
}

cleanup() {
  docker volume ls -q --filter "name=fleet-overlay-check-.*-$$" | xargs -r docker volume rm -f > /dev/null 2>&1 || true
  compose down -v --remove-orphans > /dev/null 2>&1 || true
}
trap cleanup EXIT

docker image inspect "$IMAGE" > /dev/null 2>&1 || docker build -t "$IMAGE" "$root"
docker image inspect "$TOOLBOX" > /dev/null 2>&1 || docker build --target toolbox -t "$TOOLBOX" "$root"

# 1. The example files an operator copies to a host, read by the binary in the image. gen-seed
# writes the one file the examples do not ship, which is also how an operator makes it. The
# volume is made from the image's state directory, so it arrives owned by the user the image
# runs as; the second run mounts the same volume where the example config expects the seed.
etc=$(volume etc)
docker run --rm -v "$etc:/var/lib/fleet-overlay" "$IMAGE" gen-seed --out /var/lib/fleet-overlay/seed > /dev/null
if docker run --rm \
  -e FLEET_OVERLAY_HOSTNAME=bn-ams1-07 \
  -v "$etc:/etc/fleet-overlay" \
  -v "$root/deploy/examples/config.yaml:/etc/fleet-overlay/config.yaml:ro" \
  -v "$root/deploy/examples/roster.yaml:/etc/fleet-overlay/roster.yaml:ro" \
  "$IMAGE" check-config; then
  pass "image_runs_check_config_against_example_files_and_exits_0"
else
  fail "image_runs_check_config_against_example_files_and_exits_0"
fi

# 2. Nothing in the sidecar needs root, and an image that runs as root invites a deployment that
# keeps it. There is no `id` in the image to ask, so the answer comes from the one file the
# binary writes: the process created node.key, so the file's owner is the process's uid.
nonroot=$(volume nonroot)
docker run --rm \
  -v "$nonroot:/var/lib/fleet-overlay" \
  -v "$root/deploy/examples/config.yaml:/etc/fleet-overlay/config.yaml:ro" \
  "$IMAGE" peer-id > /dev/null
uid=$(docker run --rm -v "$nonroot:/state" --entrypoint stat "$TOOLBOX" -c %u /state/node.key)
if [ "$uid" != "0" ]; then
  pass "image_runs_as_non_root (uid $uid)"
else
  fail "image_runs_as_non_root (uid $uid)"
fi

# 3. A budget rather than a law: an image an operator pulls onto two hundred hosts should be
# the binary and a libc, not a distribution.
read -r size arch <<< "$(docker image inspect -f '{{.Size}} {{.Architecture}}' "$IMAGE")"
budget="$((size / 1000000)) MB of $((MAX_IMAGE_BYTES / 1000000)) MB, $arch"
if [ "$size" -lt "$MAX_IMAGE_BYTES" ]; then
  pass "image_size_is_under_80_mb ($budget)"
else
  fail "image_size_is_under_80_mb ($budget)"
fi

# 4. D01: the node key is the peer id the beacon node trusts, so a restart that loses it costs
# the sidecar that trust. The volume is what keeps it.
peer_id() {
  docker run --rm \
    -v "$1:/var/lib/fleet-overlay" \
    -v "$root/deploy/examples/config.yaml:/etc/fleet-overlay/config.yaml:ro" \
    "$IMAGE" peer-id
}
kept=$(volume key)
fresh=$(volume other-key)
first=$(peer_id "$kept")
again=$(peer_id "$kept")
other=$(peer_id "$fresh")
if [ "$first" = "$again" ] && [ "$first" != "$other" ]; then
  pass "node_key_persists_across_container_restarts ($first, fresh volume $other)"
else
  fail "node_key_persists_across_container_restarts ($first then $again, fresh volume $other)"
fi

# 5. Every sidecar sees the other two. With beacon nodes, each one also has to be trusted by
# the beacon node beside it.
#
# The value of a metric summed over its label sets, or nothing at all when the endpoint is not
# answering yet.
metric() {
  curl -fsS --max-time 2 "http://127.0.0.1:$1/metrics" 2> /dev/null \
    | awk -v m="$2" '$1 ~ "^"m"([{ ]|$)" {s += $NF} END {if (NR) print s + 0}' || true
}

meshed() {
  for port in "${ports[@]}"; do
    [ "$(metric "$port" overlay_peers_connected)" = "2" ] || return 1
    if [ "$with_beacon_nodes" = 1 ]; then
      [ "$(metric "$port" overlay_bn_trusted)" = "1" ] || return 1
    fi
  done
}

if [ "$with_beacon_nodes" = 1 ]; then
  compose up -d
  check=compose_demo_reaches_full_mesh_and_is_trusted_by_every_beacon_node
else
  compose up -d sc-1 sc-2 sc-3
  check=compose_demo_reaches_full_mesh_within_two_minutes
fi

started=$(date +%s)
formed=0
while true; do
  if meshed; then
    formed=1
    break
  fi
  if [ "$(($(date +%s) - started))" -ge "$MESH_TIMEOUT" ]; then
    compose logs --tail 40
    break
  fi
  sleep 2
done
elapsed=$(($(date +%s) - started))
if [ "$formed" = 1 ]; then
  pass "$check (${elapsed}s)"
else
  fail "$check (gave up after ${elapsed}s)"
fi

exit "$failed"
