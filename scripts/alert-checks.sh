#!/usr/bin/env bash
# T-052 check 6: the alert rules against a running fleet rather than against promtool.
#
#   scripts/alert-checks.sh [--with-beacon-nodes]
#
# Starts T-047's compose demo with the Prometheus that loads deploy/prometheus/alerts.yml, breaks
# something the rules are supposed to notice, and waits for the alert to go pending. Pending
# rather than firing, because every `for:` window in the file is minutes long and what is being
# checked is that the expression matches a real scrape, not that Prometheus can count.
#
#   OverlayPeersLow        stop one of the three sidecars; the other two are down to one peer of
#                          the two their roster lists.
#   OverlayNotTrustedByBn  start the beacon nodes without the trusted-peer flags the drop-in
#                          would give them. Needs a testnet and minutes of checkpoint sync, so it
#                          runs only with --with-beacon-nodes, which is the nightly job.
#
# IMAGE          the sidecar image, fleet-overlay:demo by default
# TOOLBOX        the Dockerfile's toolbox stage, which the demo's setup step needs
# ALERT_TIMEOUT  seconds an alert has to go pending, 120 by default
set -euo pipefail

IMAGE=${IMAGE:-fleet-overlay:demo}
TOOLBOX=${TOOLBOX:-fleet-overlay:toolbox}
ALERT_TIMEOUT=${ALERT_TIMEOUT:-120}
MESH_TIMEOUT=${MESH_TIMEOUT:-120}
TRUST_TIMEOUT=${TRUST_TIMEOUT:-900}

root=$(cd "$(dirname "$0")/.." && pwd)
demo=$root/examples/compose
with_beacon_nodes=0
if [ "${1-}" = "--with-beacon-nodes" ]; then
  with_beacon_nodes=1
fi

prometheus=http://127.0.0.1:9090
failed=0

pass() { printf 'ok   %s\n' "$*"; }
fail() {
  printf 'FAIL %s\n' "$*"
  failed=1
}

compose() {
  FLEET_OVERLAY_IMAGE=$IMAGE FLEET_OVERLAY_TOOLBOX_IMAGE=$TOOLBOX \
    docker compose -f "$demo/docker-compose.yml" "$@"
}

cleanup() { compose down -v --remove-orphans > /dev/null 2>&1 || true; }
trap cleanup EXIT

# 1 when `query` returns anything at all, 0 when it does not and while Prometheus is still
# starting. An aggregation drops the metric name, so what says the vector is not empty is the
# result array rather than any field inside it. `grep -c` prints its zero before it exits
# non-zero, which is what `|| true` keeps.
series() {
  curl -fsS --max-time 5 --get --data-urlencode "query=$1" "$prometheus/api/v1/query" 2>/dev/null \
    | grep -c '"result":\[{' || true
}

# Waits for `query` to return at least one series, or gives up after $2 seconds.
wait_for() {
  local query=$1 timeout=$2 started
  started=$(date +%s)
  while [ "$(series "$query")" = 0 ]; do
    if [ "$(($(date +%s) - started))" -ge "$timeout" ]; then
      return 1
    fi
    sleep 2
  done
  echo "$(($(date +%s) - started))"
}

pending() { echo "ALERTS{alertname=\"$1\",alertstate=\"pending\"}"; }

docker image inspect "$IMAGE" > /dev/null 2>&1 || docker build -t "$IMAGE" "$root"
docker image inspect "$TOOLBOX" > /dev/null 2>&1 || docker build --target toolbox -t "$TOOLBOX" "$root"

# 1. OverlayPeersLow. The three sidecars need no beacon node to build their mesh, so this half
# runs anywhere the demo does.
compose up -d sc-1 sc-2 sc-3 prometheus

if ! wait_for 'count(sum by (instance) (overlay_peers_connected) == 2) == 3' "$MESH_TIMEOUT" > /dev/null; then
  fail "the demo did not reach a full mesh in ${MESH_TIMEOUT}s"
  compose logs --tail 40
  exit "$failed"
fi

if [ "$(series "$(pending OverlayPeersLow)")" != 0 ]; then
  fail "OverlayPeersLow was already pending on a healthy mesh"
fi

compose stop sc-2 > /dev/null
if elapsed=$(wait_for "$(pending OverlayPeersLow)" "$ALERT_TIMEOUT"); then
  pass "alerts_fire_in_the_compose_demo: OverlayPeersLow pending ${elapsed}s after sc-2 stopped"
else
  fail "alerts_fire_in_the_compose_demo: OverlayPeersLow never went pending"
  compose logs --tail 20 prometheus
fi
compose start sc-2 > /dev/null

# 2. OverlayNotTrustedByBn. TRUST_SIDECAR=0 starts the beacon nodes without the two flags the
# systemd drop-in would hand them, which is the mistake this alert exists to catch.
if [ "$with_beacon_nodes" = 1 ]; then
  TRUST_SIDECAR=0 compose up -d bn-1 bn-2 bn-3

  if ! wait_for 'overlay_bn_trusted == 0' "$TRUST_TIMEOUT" > /dev/null; then
    fail "no beacon node reported the sidecar untrusted in ${TRUST_TIMEOUT}s"
  elif elapsed=$(wait_for "$(pending OverlayNotTrustedByBn)" "$ALERT_TIMEOUT"); then
    pass "alerts_fire_in_the_compose_demo: OverlayNotTrustedByBn pending after ${elapsed}s"
  else
    fail "alerts_fire_in_the_compose_demo: OverlayNotTrustedByBn never went pending"
  fi
fi

exit "$failed"
