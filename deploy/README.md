# Deployment examples

Files to copy into your own configuration management, and the commands that install and check
them on one host. Nothing here is a deployment tool. What each file does and why is in the
operator documentation. Commands run from this directory, on the host.

## Files

| File | What it is | |
|---|---|---|
| `systemd/eth-gossip-overlay.service` | the sidecar unit | required |
| `examples/config.yaml` | `/etc/eth-gossip-overlay/config.yaml` | required |
| `examples/roster.yaml` | `/etc/eth-gossip-overlay/roster.yaml` | required |
| `examples/roster.yaml.j2` | the roster from an Ansible inventory | example |
| `examples/eth-gossip-overlay.env.j2` | `ETH_GOSSIP_OVERLAY_HOSTNAME` from an Ansible inventory | example |
| `systemd/lighthouse-bn.service.d/10-eth-gossip-overlay-trusted-peer.conf` | the Lighthouse drop-in | recommended |
| `sysctl/90-eth-gossip-overlay.conf` | socket buffers, `fq`, the RFS flow table | recommended |
| `nftables/eth-gossip-overlay.nft.j2` | UDP 7788 allowlist from the roster | recommended |
| `nftables/eth-gossip-overlay.nft.example` | the template rendered from `examples/roster.yaml` | example |
| `prometheus/alerts.yml` | the ten alert rules, for your own Prometheus | recommended |
| `grafana/eth-gossip-overlay.json` | the dashboard, for your own Grafana | recommended |

The fleet seed at `/etc/eth-gossip-overlay/seed` is required and is not in this directory: you
generate it once for the fleet.

## Placeholders

| Placeholder | What to put there |
|---|---|
| `<LIGHTHOUSE_UNIT>` | the name of your Lighthouse unit, without `.service`. The examples use `lighthouse-bn` |
| `<CPU_LIST>` | the cores reserved for the sidecar, such as `30-31`. Commented out in the unit |

## Install

Once for the fleet, on a machine that can reach every host:

```sh
eth-gossip-overlay gen-seed --out ./seed
```

On every host, with `roster.yaml` rendered from your inventory:

```sh
sudo install -m 755 eth-gossip-overlay eth-gossip-overlayctl /usr/local/bin/
sudo install -d -m 755 /etc/eth-gossip-overlay
sudo install -m 644 examples/config.yaml /etc/eth-gossip-overlay/config.yaml
sudo install -m 644 roster.yaml /etc/eth-gossip-overlay/roster.yaml
sudo install -m 600 seed /etc/eth-gossip-overlay/seed
echo "ETH_GOSSIP_OVERLAY_HOSTNAME=$(hostname)" | sudo tee /etc/eth-gossip-overlay/eth-gossip-overlay.env

sudo install -m 644 systemd/eth-gossip-overlay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now eth-gossip-overlay
```

Encrypted seed instead of the plain file:

```sh
sudo systemd-creds encrypt --name=seed seed /etc/eth-gossip-overlay/seed.cred
sudo rm /etc/eth-gossip-overlay/seed
```

then in `/etc/systemd/system/eth-gossip-overlay.service` replace

```ini
LoadCredential=seed:/etc/eth-gossip-overlay/seed
```

with

```ini
LoadCredentialEncrypted=seed:/etc/eth-gossip-overlay/seed.cred
```

Recommended, on every host:

```sh
sudo install -m 644 sysctl/90-eth-gossip-overlay.conf /etc/sysctl.d/
sudo sysctl --system

# nftables/eth-gossip-overlay.nft.j2 rendered from the same inventory as the roster
sudo nft -f eth-gossip-overlay.nft

sudo install -d -m 755 /etc/systemd/system/<LIGHTHOUSE_UNIT>.service.d
sudo install -m 644 systemd/lighthouse-bn.service.d/10-eth-gossip-overlay-trusted-peer.conf \
  /etc/systemd/system/<LIGHTHOUSE_UNIT>.service.d/
```

Then append `$ETH_GOSSIP_OVERLAY_TRUSTED_PEER_ARGS`, unquoted, to the end of the `ExecStart=` line in
your own Lighthouse unit, and restart it once:

```sh
sudo systemctl daemon-reload
sudo systemctl restart <LIGHTHOUSE_UNIT>
```

## Verify

```console
$ sudo systemctl status eth-gossip-overlay
● eth-gossip-overlay.service - Eth gossip overlay sidecar
     Loaded: loaded (/etc/systemd/system/eth-gossip-overlay.service; enabled; preset: enabled)
     Active: active (running) since Mon 2026-09-07 09:12:41 UTC; 3min 22s ago
   Main PID: 1841 (eth-gossip-overlay)
      Tasks: 11 (limit: 76023)
     Memory: 41.2M (peak: 44.9M available: 470.8M)
     CGroup: /system.slice/eth-gossip-overlay.service
             └─1841 /usr/local/bin/eth-gossip-overlay run
```

```console
$ sudo journalctl -u eth-gossip-overlay -o cat | jq .
{
  "timestamp": "2026-09-07T09:12:41.489217Z",
  "level": "INFO",
  "target": "eth_gossip_overlay::app",
  "message": "admin socket bound",
  "path": "/run/eth-gossip-overlay/admin.sock"
}
```

```console
$ cat /run/eth-gossip-overlay/lighthouse.env
ETH_GOSSIP_OVERLAY_TRUSTED_PEER_ARGS=--trusted-peers 12D3KooWJ6JBbaSGzLK7jZj7qtey7W9wc36Wq8qhkid7Rgpy854b --libp2p-addresses /ip4/127.0.0.1/tcp/7787/p2p/12D3KooWJ6JBbaSGzLK7jZj7qtey7W9wc36Wq8qhkid7Rgpy854b
```

```console
$ sudo eth-gossip-overlayctl status
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
$ sudo eth-gossip-overlay check-config
2026-09-16T12:56:22.065239Z  INFO overlay_core::budget: memory budget bounded_bytes=622494412 total_bytes=778118015 headroom_percent=25 memory_max=1073741824 roster=3 receive_window=236499046 rows=[("seen_cache", 12800000), ("recent_store", 27238400), ("publish_queue", 35651584), ("reassembler", 35651584), ("peer_send_lanes", 2711552), ("peer_topic_tables", 1310720), ("gossipsub", 34132480), ("by_root_cache", 0), ("quic_receive_windows", 472998092)]
hostname: bn-ams1-07
region: eu
site: ams1
peer id: 12D3KooWJ6JBbaSGzLK7jZj7qtey7W9wc36Wq8qhkid7Rgpy854b
roster: 3 hosts
memory ceiling: 1024 MiB (built-in default)
memory budget: 743 MiB (594 MiB in bounded structures plus 25% headroom)
```

The two memory lines are the ceiling `check-config` found and the budget derived against it. The
ceiling is the `memory.max` of the cgroup the command runs in, or of the nearest ancestor that
sets one; a shell session sets none, so from a shell the command warns and falls back to the
built-in default, which is the 1 GiB the unit sets. The sidecar's own start logs the same table
against the unit's `MemoryMax`. A budget over the ceiling is a `WARN` line in both places, and
the start goes ahead; [docs/performance.md](../docs/performance.md) says what to raise.

## Reload

After pushing a new `config.yaml` or `roster.yaml`:

```console
$ sudo systemctl reload eth-gossip-overlay
```

or, for the same thing with a report:

```console
$ sudo eth-gossip-overlayctl roster reload
applied: roster
restart required: none
```

## Inject off, fleet-wide

```console
$ sudo eth-gossip-overlayctl inject off
inject off
```

```sh
ansible beacon_nodes -b -a 'eth-gossip-overlayctl inject off'
```

To keep it off across restarts, set `inject: false` in `config.yaml` and reload.

## Uninstall

```sh
sudo systemctl disable --now eth-gossip-overlay
sudo rm /etc/systemd/system/eth-gossip-overlay.service
sudo rm /etc/systemd/system/<LIGHTHOUSE_UNIT>.service.d/10-eth-gossip-overlay-trusted-peer.conf
sudo rm /etc/sysctl.d/90-eth-gossip-overlay.conf
sudo nft delete table inet eth-gossip-overlay
sudo systemctl daemon-reload
sudo systemctl restart <LIGHTHOUSE_UNIT>
sudo rm -r /etc/eth-gossip-overlay /var/lib/eth-gossip-overlay
sudo rm /usr/local/bin/eth-gossip-overlay /usr/local/bin/eth-gossip-overlayctl
```

Remove `$ETH_GOSSIP_OVERLAY_TRUSTED_PEER_ARGS` from your Lighthouse `ExecStart=` before that restart.
