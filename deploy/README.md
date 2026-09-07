# Deployment examples

Files to copy into your own configuration management, and the commands that install and check
them on one host. Nothing here is a deployment tool. What each file does and why is in the
operator documentation. Commands run from this directory, on the host.

## Files

| File | What it is | |
|---|---|---|
| `systemd/fleet-overlay.service` | the sidecar unit | required |
| `examples/config.yaml` | `/etc/fleet-overlay/config.yaml` | required |
| `examples/roster.yaml` | `/etc/fleet-overlay/roster.yaml` | required |
| `examples/roster.yaml.j2` | the roster from an Ansible inventory | example |
| `examples/fleet-overlay.env.j2` | `FLEET_OVERLAY_HOSTNAME` from an Ansible inventory | example |
| `systemd/lighthouse-bn.service.d/10-fleet-overlay-trusted-peer.conf` | the Lighthouse drop-in | recommended |
| `sysctl/90-fleet-overlay.conf` | socket buffers, `fq`, the RFS flow table | recommended |
| `nftables/fleet-overlay.nft.j2` | UDP 7788 allowlist from the roster | recommended |
| `nftables/fleet-overlay.nft.example` | the template rendered from `examples/roster.yaml` | example |
| `prometheus/alerts.yml` | the ten alert rules, for your own Prometheus | recommended |
| `grafana/fleet-overlay.json` | the dashboard, for your own Grafana | recommended |

The fleet seed at `/etc/fleet-overlay/seed` is required and is not in this directory: you
generate it once for the fleet.

## Placeholders

| Placeholder | What to put there |
|---|---|
| `<LIGHTHOUSE_UNIT>` | the name of your Lighthouse unit, without `.service`. The examples use `lighthouse-bn` |
| `<CPU_LIST>` | the cores reserved for the sidecar, such as `30-31`. Commented out in the unit |

## Install

Once for the fleet, on a machine that can reach every host:

```sh
fleet-overlay gen-seed --out ./seed
```

On every host, with `roster.yaml` rendered from your inventory:

```sh
sudo install -m 755 fleet-overlay fleet-overlayctl /usr/local/bin/
sudo install -d -m 755 /etc/fleet-overlay
sudo install -m 644 examples/config.yaml /etc/fleet-overlay/config.yaml
sudo install -m 644 roster.yaml /etc/fleet-overlay/roster.yaml
sudo install -m 600 seed /etc/fleet-overlay/seed
echo "FLEET_OVERLAY_HOSTNAME=$(hostname)" | sudo tee /etc/fleet-overlay/fleet-overlay.env

sudo install -m 644 systemd/fleet-overlay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now fleet-overlay
```

Encrypted seed instead of the plain file:

```sh
sudo systemd-creds encrypt --name=seed seed /etc/fleet-overlay/seed.cred
sudo rm /etc/fleet-overlay/seed
```

then in `/etc/systemd/system/fleet-overlay.service` replace

```ini
LoadCredential=seed:/etc/fleet-overlay/seed
```

with

```ini
LoadCredentialEncrypted=seed:/etc/fleet-overlay/seed.cred
```

Recommended, on every host:

```sh
sudo install -m 644 sysctl/90-fleet-overlay.conf /etc/sysctl.d/
sudo sysctl --system

# nftables/fleet-overlay.nft.j2 rendered from the same inventory as the roster
sudo nft -f fleet-overlay.nft

sudo install -d -m 755 /etc/systemd/system/<LIGHTHOUSE_UNIT>.service.d
sudo install -m 644 systemd/lighthouse-bn.service.d/10-fleet-overlay-trusted-peer.conf \
  /etc/systemd/system/<LIGHTHOUSE_UNIT>.service.d/
```

Then append `$FLEET_OVERLAY_TRUSTED_PEER_ARGS`, unquoted, to the end of the `ExecStart=` line in
your own Lighthouse unit, and restart it once:

```sh
sudo systemctl daemon-reload
sudo systemctl restart <LIGHTHOUSE_UNIT>
```

## Verify

```console
$ sudo systemctl status fleet-overlay
● fleet-overlay.service - Fleet gossip overlay sidecar
     Loaded: loaded (/etc/systemd/system/fleet-overlay.service; enabled; preset: enabled)
     Active: active (running) since Mon 2026-09-07 09:12:41 UTC; 3min 22s ago
   Main PID: 1841 (fleet-overlay)
      Tasks: 11 (limit: 76023)
     Memory: 41.2M (peak: 44.9M available: 470.8M)
     CGroup: /system.slice/fleet-overlay.service
             └─1841 /usr/local/bin/fleet-overlay run
```

```console
$ sudo journalctl -u fleet-overlay -o cat | jq .
{
  "timestamp": "2026-09-07T09:12:41.489217Z",
  "level": "INFO",
  "target": "eth_gossip_overlay::app",
  "message": "admin socket bound",
  "path": "/run/fleet-overlay/admin.sock"
}
```

```console
$ cat /run/fleet-overlay/lighthouse.env
FLEET_OVERLAY_TRUSTED_PEER_ARGS=--trusted-peers 12D3KooWJ6JBbaSGzLK7jZj7qtey7W9wc36Wq8qhkid7Rgpy854b --libp2p-addresses /ip4/127.0.0.1/tcp/7787/p2p/12D3KooWJ6JBbaSGzLK7jZj7qtey7W9wc36Wq8qhkid7Rgpy854b
```

```console
$ sudo fleet-overlayctl status
host    bn-ams1-07 (eu/ams1)
inject  on
bn      connected  Lighthouse/v8.2.2-1a2b3c4/x86_64-linux  trusted  203 subscriptions

hostname    region  site  rtt     up     queue_small  queue_large  version  features
bn-fra1-02  eu      fra1  4.1ms   3m22s  0f/0b        0f/0b        0.1.0    0x0
bn-nyc1-01  us      nyc1  81.4ms  3m22s  0f/0b        0f/0b        0.1.0    0x0
```

```console
$ curl -s 127.0.0.1:7789/metrics | grep -A2 '^# HELP overlay_bn_trusted'
# HELP overlay_bn_trusted 1 when the beacon node lists the sidecar as trusted.
# TYPE overlay_bn_trusted gauge
overlay_bn_trusted 1
```

```console
$ sudo fleet-overlay check-config
hostname: bn-ams1-07
region: eu
site: ams1
peer id: 12D3KooWJ6JBbaSGzLK7jZj7qtey7W9wc36Wq8qhkid7Rgpy854b
roster: 3 hosts
memory budget: 61 MiB (49 MiB in bounded structures plus 25% headroom)
```

## Reload

After pushing a new `config.yaml` or `roster.yaml`:

```console
$ sudo systemctl reload fleet-overlay
```

or, for the same thing with a report:

```console
$ sudo fleet-overlayctl roster reload
applied: roster
restart required: none
```

## Inject off, fleet-wide

```console
$ sudo fleet-overlayctl inject off
inject off
```

```sh
ansible beacon_nodes -b -a 'fleet-overlayctl inject off'
```

To keep it off across restarts, set `inject: false` in `config.yaml` and reload.

## Uninstall

```sh
sudo systemctl disable --now fleet-overlay
sudo rm /etc/systemd/system/fleet-overlay.service
sudo rm /etc/systemd/system/<LIGHTHOUSE_UNIT>.service.d/10-fleet-overlay-trusted-peer.conf
sudo rm /etc/sysctl.d/90-fleet-overlay.conf
sudo nft delete table inet fleet-overlay
sudo systemctl daemon-reload
sudo systemctl restart <LIGHTHOUSE_UNIT>
sudo rm -r /etc/fleet-overlay /var/lib/fleet-overlay
sudo rm /usr/local/bin/fleet-overlay /usr/local/bin/fleet-overlayctl
```

Remove `$FLEET_OVERLAY_TRUSTED_PEER_ARGS` from your Lighthouse `ExecStart=` before that restart.
