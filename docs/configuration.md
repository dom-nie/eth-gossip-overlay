# Configuration

One `config.yaml`, the same on every host, at `/etc/eth-gossip-overlay/config.yaml` unless
`--config` says otherwise. Every key has a default, so a file naming only what you change is
valid, and [`deploy/examples/config.yaml`](../deploy/examples/config.yaml) is that file with
every default written out. An unknown or misspelled key stops the start rather than being
ignored: run `eth-gossip-overlay check-config` after pushing a file and configuration management
finds out before systemd does.

## Reload or restart

`systemctl reload eth-gossip-overlay`, `SIGHUP` and `eth-gossip-overlayctl roster reload` re-read
`config.yaml` and `roster.yaml` without dropping a connection. The report says what took effect
and what did not:

```console
$ sudo eth-gossip-overlayctl roster reload
applied: inject, roster
restart required: overlay.listen
```

The table says which side each key is on. A `restart` key is read once at startup: a change to
it is listed on every report until the sidecar restarts. A key is applied only when its value
changed; one that failed to apply is retried on the next reload.

## Who this host is

The hostname is the identity everywhere: the roster key, the input to the overlay TLS key, the
connection tie-break. It is `gethostname()` unless `ETH_GOSSIP_OVERLAY_HOSTNAME` says otherwise;
set it from the inventory name so the two cannot drift.
`ETH_GOSSIP_OVERLAY_REGION` and `ETH_GOSSIP_OVERLAY_SITE` override the roster's answer for this host.

`roster.yaml` is the fleet, one entry per host, and is not part of `config.yaml`:

```yaml
hosts:
  - hostname: bn-ams1-07
    region: eu
    site: ams1                  # optional, a label for metrics and nothing else
    addr: "203.0.113.37:7788"   # where this host's overlay is dialled
```

Every host carries the same roster, and `region` is the fan-out's failure and latency domain.
Have your discovery tool write `roster.yaml`: the sidecar checks the file's modification time
every 10 seconds and reloads what changed, so membership needs no interface beyond the file.
Write to a temporary file in the same directory and rename it into place: a poll landing halfway
through a direct write reads a file that does not parse, keeps the roster it has, and picks up
the finished one next poll.

An automatic reload is refused if it would drop more than half the sidecar's hosts, since a
truncated file is likelier than half a fleet leaving at once. The refusal counts
`roster_reload_rejected_total`, which is alerted on; `eth-gossip-overlayctl roster reload`
applies the file anyway, which is how a genuine shrink is done.

## The seed, the node key and the logs

`overlay.fleet_seed_file` names the fleet seed, but `$CREDENTIALS_DIRECTORY/seed` wins whenever
systemd sets it, which is what the shipped unit's `LoadCredential=` does. Set
`overlay.fleet_seed_previous_file` only while a seed rotation is running;
[security.md](security.md) is the procedure.

`bn.node_key_file` holds this host's libp2p identity, created on first start with mode 0600. It
is the peer id the beacon node trusts and is not derived from the seed. Deleting it gives the
sidecar a new identity on the next start, so `lighthouse.env` changes and the beacon node has to
be restarted to read it; keep the file, and on a container the volume under it.

The `log` section sets the level and the format of the sidecar's one output stream, which carries
the events as well. [events.md](events.md) has the fields, the queries, and why
`tracing-journald` is an option rather than the default.

`bn.by_root_cache` trades memory for latency and is off. On, the sidecar answers the node's block
lookups from its store, saving a public round trip; columns are asked of custody peers only, which
the sidecar is not. Lighthouse picks the peer at random; `overlay_by_root_requests_total` says
whether it pays. Each slot costs 5.2 MiB of receive window ([performance.md](performance.md)).

## Every key

`On change` is `reload` for a key a running sidecar picks up and `restart` for one it reads only
at startup. Every key below ships in 0.1.0, the first release.

<!-- generated from crates/overlay-core/src/config.rs, do not edit by hand -->

| Key | Default | On change | What it is |
|---|---|---|---|
| `overlay.listen` | `[::]:7788` | restart | the address the QUIC endpoint binds. `[::]` listens dual-stack. |
| `overlay.roster_file` | `/etc/eth-gossip-overlay/roster.yaml` | restart | the fleet roster, re-read on SIGHUP and whenever the file changes. |
| `overlay.fleet_seed_file` | `/etc/eth-gossip-overlay/seed` | restart | the shared secret every overlay TLS key derives from. |
| `overlay.fleet_seed_previous_file` | unset | reload | the outgoing seed while a rotation is in progress, so peers still on it keep pairing. Absent or `null` otherwise. |
| `overlay.keepalive_ms` | `1000` | restart | the QUIC keepalive interval. Shorter than `idle_timeout_ms`, or every quiet connection would drop. |
| `overlay.idle_timeout_ms` | `5000` | restart | how long a silent connection lives before QUIC closes it. |
| `overlay.initial_window_bytes` | `4000000` | restart | the initial congestion window. A connection that carries one block every 12 s never leaves slow start with the RFC default. |
| `overlay.fanout.large.in_region` | `stripe` | restart | how a large message reaches the origin's own region. One of `stripe`, `direct`. |
| `overlay.fanout.large.cross_region` | `stripe` | restart | how it reaches each other region. One of `stripe`, `direct`, `relays`. |
| `overlay.fanout.large.stripe_min_recipients` | `16` | reload | with fewer subscribed recipients than this the message goes out whole; a stripe over a handful of hosts saves nothing. |
| `overlay.fanout.small.cross_region` | `relays` | reload | how it reaches each other region. One of `direct`, `relays`. |
| `overlay.fanout.small.relays_per_remote_region` | `3` | reload | how many hosts in a remote region receive a batch and re-fan it locally. |
| `overlay.fanout.small.relay_min_remote_hosts` | `12` | reload | a remote region with fewer live subscribed hosts than this is sent to directly; relaying would not save enough WAN traffic to pay for the extra hop. |
| `overlay.io_thread.pin_cpu` | `none` | restart | a reserved core to pin the overlay I/O thread to. `null` leaves it unpinned. |
| `overlay.io_thread.prefer_busy_poll` | `false` | restart | spin on the socket instead of waiting for interrupts. |
| `overlay.io_thread.busy_poll_usecs` | `100` | restart | how long each busy-poll spin lasts. |
| `overlay.io_thread.irq_suspend_timeout_ms` | `20` | restart | how long the NIC queue's interrupt stays masked while polling keeps finding packets. Needs `CAP_NET_ADMIN`; `0` asks for the busy polling without the suspension. |
| `overlay.io_thread.steering` | `off` | restart | how the overlay's packets are steered to the pinned core's NIC queue. One of `auto`, `ntuple`, `rfs`, `off`. |
| `bn.identity_url` | `http://127.0.0.1:5052/eth/v1/node/identity` | restart | the beacon API endpoint that reports the node's peer id. |
| `bn.events_url` | `http://127.0.0.1:5052/eth/v1/events?topics=block,block_gossip,data_column_sidecar` | restart | the beacon API event stream. |
| `bn.libp2p_addr` | `/ip4/127.0.0.1/tcp/9000` | restart | the multiaddr the sidecar dials to join the beacon node's gossipsub. |
| `bn.node_key_file` | `/var/lib/eth-gossip-overlay/node.key` | restart | the sidecar's own libp2p identity, per host, created on first start. |
| `bn.listen_addr` | `/ip4/127.0.0.1/tcp/7787` | restart | where the sidecar listens for the beacon node's own dial. Lighthouse caps inbound connections before it knows who is connecting, so a sidecar that only dialled would wait for peer churn on a busy node (MD-01). Restart-required: the beacon node is given this address in its command line. |
| `bn.publish_rate_limit.small_per_s` | `8000` | reload | small-class messages per second. |
| `bn.publish_rate_limit.large_per_s` | `300` | reload | large-class messages per second. |
| `bn.publish_rate_limit.bytes_per_s` | `33554432` | reload | payload bytes per second across both classes. |
| `bn.idontwant_on_publish` | `true` | restart | tell the beacon node IDONTWANT for a message as it is published. |
| `bn.by_root_cache.enabled` | `false` | reload | answer by-root lookups from the recent store. |
| `bn.by_root_cache.slots` | `16` | restart | slots of blocks and columns held while the cache is on. |
| `classes.small.batch_window_ms` | `10` | reload | how long a batch collects entries before it is flushed. |
| `classes.small.stale_after_ms` | `1000` | reload | a batch older than this is dropped rather than delivered late. |
| `classes.large.chunk_bytes` | `2048` | restart | the fixed chunk size. The Reed-Solomon shards need an even length; a multiple of 64 is the stricter rule the sidecar holds them to, so a chunk lands on a cache line and the SIMD paths run at their widest stride. |
| `classes.large.parity_ratio` | `0.1` | restart | parity chunks as a fraction of data chunks. |
| `classes.large.repair_deadline_ms` | `250` | reload | how long after the first chunk a receiver waits before asking peers for the missing ones. |
| `classes.large.column_repair` | `true` | reload | ask in-region peers for the custody columns the beacon node is still short of past the same deadline. Off, the node fetches them itself as it always has. |
| `inject` | `true` | reload | whether the sidecar publishes what it receives into the beacon node. `false` is the kill switch: the sidecar keeps observing and reporting but changes nothing. |
| `admin_socket` | `/run/eth-gossip-overlay/admin.sock` | restart | the Unix socket `eth-gossip-overlayctl` connects to. |
| `metrics_listen` | `127.0.0.1:7789` | restart | where the Prometheus scrape endpoint binds. |
| `log.level` | `info` | reload | the least severe level that is emitted. `RUST_LOG` overrides it. One of `trace`, `debug`, `info`, `warn`, `error`. |
| `log.format` | `auto` | reload | how the log stream is rendered. One of `auto`, `json`, `text`. |

<!-- end generated -->
