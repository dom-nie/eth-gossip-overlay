# Quickstart

Two hosts, from a downloaded binary to a block that arrived over the overlay instead of the
public network. Everything here is per host except step 2, which is once for the fleet. Three
hosts or three hundred is the same walk.

Without two hosts to spare, [`examples/compose/`](../examples/compose/README.md) starts three
sidecars and three beacon nodes on one machine and the rest of this document still reads true.

## What you need

Two hosts already running Lighthouse, at a version [COMPATIBILITY.md](../COMPATIBILITY.md)
lists, that can reach each other on UDP 7788. Root on both. The sidecar needs no validator keys,
no execution client and no database of its own.

## 1. Install the binaries

```sh
tar xzf fleet-overlay-0.1.0-x86_64-unknown-linux-gnu.tar.gz
sudo install -m 755 fleet-overlay fleet-overlayctl /usr/local/bin/
fleet-overlay --version
```

[upgrading.md](upgrading.md) has the checksum and provenance commands, and what the second
`--version` line means for a fleet that is part way through a release.

## 2. One seed for the fleet

Once, anywhere, then copy the file to both hosts over a channel you trust:

```sh
fleet-overlay gen-seed --out ./seed
```

Every host's overlay TLS key is derived from this seed and its own hostname, which is how the
two sidecars recognise each other with no certificate authority anywhere. A host holding a
different seed is refused at the handshake. Keep a copy: losing it means rotating.

## 3. The files on each host

`roster.yaml` is the fleet and is identical on every host. Write one entry per host, with the
address that host's overlay is dialled at:

```yaml
hosts:
  - hostname: bn-ams1-07
    region: eu
    addr: "203.0.113.37:7788"
  - hostname: bn-nyc1-01
    region: us
    addr: "[2001:db8:1::120]:7788"
```

`config.yaml` is the same on every host too. Copy
[`deploy/examples/config.yaml`](../deploy/examples/config.yaml) and change nothing yet; the
defaults are what a bare-metal host wants, and [configuration.md](configuration.md) is there
when you want to change one.

```sh
sudo install -d -m 755 /etc/fleet-overlay
sudo install -m 600 seed /etc/fleet-overlay/seed
sudo install -m 644 config.yaml /etc/fleet-overlay/config.yaml
sudo install -m 644 roster.yaml /etc/fleet-overlay/roster.yaml
echo "FLEET_OVERLAY_HOSTNAME=$(hostname)" | sudo tee /etc/fleet-overlay/fleet-overlay.env
```

The hostname in that last file has to be the `hostname:` of this host's roster entry. It is the
one value the two files must agree on, and setting it from your inventory rather than from the
kernel is what keeps them agreeing.

## 4. Start the sidecar

Rehearse the start first. `check-config` reads the same files in the same order a start does and
prints who this host turned out to be:

```sh
sudo fleet-overlay check-config
```

If your roster names this host something other than `hostname` reports, put
`FLEET_OVERLAY_HOSTNAME=` in front of that command with the value the unit's environment file
carries; `check-config` reads the environment the same way a start does.

Then install the unit from [`deploy/systemd/`](../deploy/README.md) and start it:

```sh
sudo install -m 644 fleet-overlay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now fleet-overlay
```

On its first start the sidecar creates its libp2p node key, and before it binds anything it
writes `/run/fleet-overlay/lighthouse.env` with the peer id that key gives it. That file is how
the beacon node learns which peer to trust.

Do both hosts before going on. Two sidecars make a mesh; one makes nothing.

## 5. Tell Lighthouse about the sidecar

A drop-in orders the beacon node after the sidecar and reads that env file, and one edit to your
own `ExecStart=` line passes the flags on:

```sh
sudo install -d -m 755 /etc/systemd/system/lighthouse-bn.service.d
sudo install -m 644 10-fleet-overlay-trusted-peer.conf \
  /etc/systemd/system/lighthouse-bn.service.d/
```

Append `$FLEET_OVERLAY_TRUSTED_PEER_ARGS`, unquoted, to the end of the `ExecStart=` line in your
Lighthouse unit, then:

```sh
sudo systemctl daemon-reload
sudo systemctl restart lighthouse-bn
```

[lighthouse.md](lighthouse.md) is the whole of the beacon node's side: what the two flags do,
why the beacon node dials the sidecar rather than the other way round, and what to set
`--target-peers` to. The restart is needed once, because the flags are on the command line.

## Check it worked

The sidecar's own account of itself. `bn` should say `connected` and `trusted`, and every other
roster host should have a row:

```sh
sudo fleet-overlayctl status
```

```console
host    bn-ams1-07 (eu)
inject  on
bn      connected  Lighthouse/v8.2.2-1a2b3c4/x86_64-linux  trusted  203 subscriptions

hostname    region  site  rtt     up     queue_small  queue_large  version  features
bn-nyc1-01  us            81.4ms  3m22s  0f/0b        0f/0b        0.1.0    0x0
```

The same two facts as numbers, which are what you alert on later:

```sh
curl -fsS 127.0.0.1:7789/metrics | grep '^overlay_peers_connected'
curl -fsS 127.0.0.1:7789/metrics | grep '^overlay_bn_trusted 1'
```

Then the point of the whole thing. One line per large message the moment it first reaches this
host, and `"source":"overlay"` on a line means a sibling delivered it before the public network
did:

```sh
journalctl -u fleet-overlay -o cat | jq 'select(.event == "first_arrival")'
```

```console
{"timestamp":"2026-09-07T12:00:07.312905Z","level":"INFO","event":"first_arrival","msg_id":"9f3c…","class":"large","topic":"/eth2/6a95a1a9/beacon_block/ssz_snappy","node":"bn-ams1-07","region":"eu","site":"","first_arrival_ns":1757246407312905114,"source":"overlay","origin_peer":"bn-nyc1-01","target":"overlay::event"}
```

Blocks are one per slot, so give it a minute. The running total of who got there first is
`overlay_first_seen_total{source="overlay"}` against `{source="bn"}`, and that ratio is the
number [rollout.md](rollout.md) judges a canary on.

## Next

[troubleshooting.md](troubleshooting.md) if any of the three checks came back wrong.
[security.md](security.md) before this is more than two hosts: the overlay port is a trusted path
into every beacon node, and the allowlist and the seed are the fences around it.
[rollout.md](rollout.md) is how to take it to a fleet.
