# Local demo

Three sidecars and three Lighthouse beacon nodes on one machine, in two "regions", with
Prometheus scraping every sidecar and a Grafana in front of it. It is here so you can watch the
overlay carry a block between your own nodes without owning a fleet.

Each pair is one host: the beacon node joins its sidecar's network namespace, so the two talk
over `127.0.0.1` and the flags are the ones a systemd unit uses on bare metal. The sidecars see
each other over a private bridge network at the addresses in `roster.yaml`.

## What you need

Docker with the compose plugin, and room for three beacon nodes. That last part is the
expensive half: budget a core or two and a few gigabytes of memory for each beacon node, plus
disk for three datadirs. On a smaller machine, [start the overlay on its own](#the-overlay-on-its-own)
instead, which needs neither a testnet nor an execution client.

The beacon nodes start without an execution client, so they checkpoint sync and gossip but
leave every block optimistic. That is enough to watch messages cross the overlay. To give them
a real one, put its flags in `LIGHTHOUSE_EXTRA_ARGS`:

```sh
export LIGHTHOUSE_EXTRA_ARGS="--execution-endpoint http://host.docker.internal:8551 --execution-jwt /data/jwt.hex"
```

## Start

```sh
docker compose up -d
docker compose logs -f sc-1
```

The first run builds the image from the workspace, which takes a while. It then generates one
fleet seed and one node key per sidecar, and prints each sidecar's peer id into the shared
volume so the beacon nodes have their `--trusted-peers` value before they start.

| Address | What |
|---|---|
| `127.0.0.1:7789`, `:7790`, `:7791` | the three sidecars' metrics |
| `127.0.0.1:5052`, `:5053`, `:5054` | the three beacon nodes' HTTP APIs |
| `127.0.0.1:9090` | Prometheus |
| `127.0.0.1:3000` | Grafana, no login |

`metrics_listen` is `0.0.0.0:7789` here, because Prometheus scrapes from its own container. The
sidecar warns at startup that the endpoint is not on loopback, and that warning is correct: on
a real host it stays on `127.0.0.1` and only the local scraper reaches it.

Grafana loads every dashboard JSON in `dashboards/`, which is empty until the fleet dashboard
lands there.

## What to look at

Every sidecar connected to the other two:

```console
$ curl -s 127.0.0.1:7789/metrics | grep '^overlay_peers_connected'
overlay_peers_connected{region="eu",site="demo"} 1
overlay_peers_connected{region="us",site="demo"} 1
```

The beacon node beside it trusts it, which is what makes the sidecar an explicit peer rather
than an ordinary one:

```console
$ curl -s 127.0.0.1:7789/metrics | grep '^overlay_bn_trusted'
overlay_bn_trusted 1
```

Messages arriving over the overlay before the public mesh delivers them. The `source` label is
the whole point of the demo: a message counted under `overlay` is one this host got from a
sibling instead of from the internet.

```console
$ curl -s 127.0.0.1:7789/metrics | grep '^overlay_first_seen_total'
overlay_first_seen_total{class="large",source="bn"} 41
overlay_first_seen_total{class="large",source="overlay"} 17
```

One line per large message, with the id that joins it to the same message on the other two
hosts:

```sh
docker compose logs --no-log-prefix sc-1 | jq 'select(.event == "first_arrival")'
```

And what the sidecar itself says it is doing:

```sh
docker compose exec sc-1 fleet-overlayctl --socket /var/lib/fleet-overlay/admin.sock status
```

## The overlay on its own

The three sidecars form their mesh whether or not their beacon nodes are up, so the overlay half
of the demo runs on any machine, with no testnet and in seconds:

```sh
docker compose up -d sc-1 sc-2 sc-3
```

`scripts/container-checks.sh` in the repository root runs exactly this and asserts the mesh,
along with the other checks the image has to pass.

## Stop and clean up

```sh
docker compose down            # keeps the volumes, so a restart keeps the peer ids
docker compose down -v         # removes them too: new node keys, new seed, a fresh sync
docker image rm fleet-overlay:demo
```

Keeping the volumes is the interesting case. The node key is the peer id the beacon node was
told to trust, so it has to outlive the container; `docker compose down` and `up` again shows
the same peer id and the same trust.

Restart the pair rather than one of them. The beacon node lives in its sidecar's network
namespace, so `docker compose restart sc-1` leaves `bn-1` holding a namespace that has gone:

```sh
docker compose restart sc-1 bn-1
```

## Choosing a testnet

`NETWORK` and `CHECKPOINT_SYNC_URL` pick it, and the defaults are Hoodi:

```sh
NETWORK=hoodi CHECKPOINT_SYNC_URL=https://checkpoint-sync.hoodi.ethpandaops.io docker compose up -d
```

Pick whichever testnet is current and small. Lighthouse's `--network` list says what it knows
about, and the community checkpoint sync endpoints are at
<https://eth-clients.github.io/checkpoint-sync-endpoints/>. A large testnet works too and only
costs disk and sync time.

## Running the image outside the demo

Use `--network host`. The overlay is QUIC on UDP 7788 and the peers dial each other at the
addresses in the roster: a port mapping puts a NAT in front of that, which adds a hop of latency
and hides path MTU discovery from the endpoint. The demo uses a bridge network anyway, because
on one machine none of that matters.

```sh
docker build -t fleet-overlay ../..
docker run -d --name fleet-overlay --network host \
  -v /etc/fleet-overlay:/etc/fleet-overlay:ro \
  -v fleet-overlay-state:/var/lib/fleet-overlay \
  fleet-overlay
```

There is no published image to pull yet; the release pipeline is the ticket after this one.

The state volume is not optional. It holds the node key, and without it every restart is a new
peer id and the beacon node stops trusting the sidecar.

## Kubernetes

There are no manifests and no Helm chart here, and nothing in the design needs Kubernetes: the
sidecar is one process that reads two files and a seed. A chart or a set of manifests would be a
welcome contribution.
