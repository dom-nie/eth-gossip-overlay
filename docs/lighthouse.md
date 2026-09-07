# The beacon node's side

Two flags on the beacon node's command line and one drop-in. Nothing else about Lighthouse
changes, and nothing here can stop the beacon node starting.

## The drop-in

`/etc/systemd/system/<your-lighthouse-unit>.service.d/10-fleet-overlay-trusted-peer.conf`, the
file [`deploy/systemd/`](../deploy/README.md) ships:

```ini
# Order the beacon node after the sidecar, so the peer id the sidecar writes is on disk when
# the beacon node reads it, and read that file. Append $FLEET_OVERLAY_TRUSTED_PEER_ARGS,
# unquoted, to your own ExecStart= line.
#
# The dash keeps the file optional: with no sidecar the beacon node starts without a trusted
# peer, which is exactly a fleet without the overlay.
[Unit]
After=fleet-overlay.service

[Service]
EnvironmentFile=-/run/fleet-overlay/lighthouse.env
```

Then append `$FLEET_OVERLAY_TRUSTED_PEER_ARGS` to the end of your own `ExecStart=` line,
unquoted, so systemd splits it into the two flags it holds. That is the only edit to a file you
own.

The dash in `EnvironmentFile=-` is what makes this safe. If the sidecar has never run, or is
stopped, or failed, the file is missing, the variable is empty, the beacon node starts with no
trusted peer, and you have exactly the fleet you had before the overlay. There is no
`ExecStartPre=` and nothing here that can hold a beacon node down.

## What the two flags are

The sidecar writes the file before it binds anything, so the peer id is on disk by the time
`After=fleet-overlay.service` lets the beacon node read it:

```console
$ cat /run/fleet-overlay/lighthouse.env
FLEET_OVERLAY_TRUSTED_PEER_ARGS=--trusted-peers 12D3KooWJ6JBbaSGzLK7jZj7qtey7W9wc36Wq8qhkid7Rgpy854b --libp2p-addresses /ip4/127.0.0.1/tcp/7787/p2p/12D3KooWJ6JBbaSGzLK7jZj7qtey7W9wc36Wq8qhkid7Rgpy854b
```

`--trusted-peers` is what stops the beacon node scoring and pruning the sidecar like an ordinary
peer. `--libp2p-addresses` is what makes the beacon node dial it.

## Why the beacon node dials the sidecar

The sidecar dials the beacon node too, and on an idle node that is what connects first. On a
busy one it is not enough: libp2p checks the inbound connection limit before it knows which peer
is connecting, so being trusted cannot buy the sidecar an inbound slot on a node already at its
cap. Trust exempts a peer from pruning and scoring, not from admission. The beacon node's own
outbound dials run under a separate, larger limit, so the connection is made from the side that
has room.

Two things make that happen. `--libp2p-addresses` is dialled once inside Lighthouse's network
startup and never retried, so it covers the case systemd's ordering gives you: sidecar already
listening when the beacon node starts. Everything else is covered by the sidecar registering
itself through `POST /lighthouse/add_peer` on every reconnect, with an ENR signed by its node
key. Lighthouse adds that ENR to the trusted set and dials it at once, and again on every
heartbeat while it is disconnected, which is what recovers a sidecar restart against a beacon
node that is full.

`--libp2p-addresses` is marked deprecated at v8.2.2. The nightly compatibility matrix runs
against a real beacon node and would fail on the release that drops it; if that happens, the
registration alone still works and the env file loses its second flag. `bn.listen_addr` is the
address in it, `/ip4/127.0.0.1/tcp/7787` by default, and changing it needs a sidecar restart and
a beacon node restart, because it is on the beacon node's command line.

## The flags that were already yours

`--target-peers` stays where you had it, around 30 for a node that has to serve range sync and
by-root requests. The sidecar is one more peer and does not change what the number should be.
Running a handful of nodes per site much higher, at 100 or more, widens the fleet's public
ingress, and since the fleet's first arrival is the earliest of all its hosts, that is where the
overlay's benefit starts.

`--subscribe-all-subnets` is not required and is worth keeping if you had it. It holds every
attestation and sync committee subnet open, so the sidecar's subscription mirror covers all of
them and the fleet is a large share of every subnet's subscribers. Without it the sidecar
mirrors whatever the beacon node is actually subscribed to, which is smaller and changes every
epoch, and the overlay carries correspondingly less.

## Checking the beacon node's side of it

Three views of the same fact, in the order to try them:

```sh
sudo fleet-overlayctl status
curl -fsS 127.0.0.1:7789/metrics | grep '^overlay_bn_trusted'
curl -fsS 127.0.0.1:5052/lighthouse/peers | jq '.[] | select(.peer_info.is_trusted)'
```

The first is the sidecar's own account, the second is the same thing as a number the sidecar
re-checks on every connect, and the third is the beacon node's opinion, which is the one that
settles an argument. `overlay_bn_trusted` is absent rather than 0 on a beacon node whose
`/lighthouse/peers` endpoint is missing, and the sidecar logs that once.

`overlay_bn_trusted` at 0 for two minutes raises `OverlayNotTrustedByBn`;
[troubleshooting.md](troubleshooting.md#overlaynottrustedbybn) is what to do about it.
