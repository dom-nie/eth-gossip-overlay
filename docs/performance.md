# Performance

Two numbers an operator needs before a rollout: what the large class costs in wall time, and
what the process holds when every bounded structure inside it is full. The first is measured,
the second is arithmetic over the code's own constants.

## Memory

`MemoryMax=1G` in the shipped unit is the ceiling this table is written against (OPS-N4). Every
row is a structure with a bound in code, so the sum is a worst case and not a measurement:
nothing in it grows with traffic, and a real fleet sits far below it. `by_root_cache` reads zero
because the optional cache it names ships off; the section below says what turning it on costs.

`quic_receive_windows` is the one row that is not a constant. It is whatever the other rows
leave under the ceiling, shared out over the roster and floored at the 1 MiB stream window
(DX-N3), so a larger fleet gives each peer a smaller window rather than pushing the total up.
Once the floor binds, it cannot shrink further and the sidecar warns at startup.

<!-- generated from crates/overlay-core/src/budget.rs, do not edit by hand -->

At the shipped defaults, a roster of 200 hosts and the unit's `MemoryMax=1G`, which gives every connection a receive window of 2.8 MiB.

| Structure | Bytes | MiB |
|---|---:|---:|
| `seen_cache` | 12800000 | 12.2 |
| `recent_store` | 27238400 | 26.0 |
| `publish_queue` | 35651584 | 34.0 |
| `reassembler` | 35651584 | 34.0 |
| `peer_send_lanes` | 128241664 | 122.3 |
| `gossipsub` | 34132480 | 32.6 |
| `by_root_cache` | 0 | 0.0 |
| `quic_receive_windows` | 582351212 | 555.4 |
| **Sum of the bounds** | 856066924 | 816.4 |
| **Plus 25% headroom** | 1070083655 | 1020.5 |
| `MemoryMax` | 1073741824 | 1024.0 |

<!-- end generated -->

The sum therefore sits on the usable line whatever the roster, until the floor binds: at these
defaults that is 478 hosts, and past it the total goes over. A row that grows for any other
reason brings that forward.

### The by-root cache

`bn.by_root_cache.enabled` widens the recent store so the sidecar answers its node's own block
and column lookups out of it. One slot above is a 200 KB block and 128 columns of 40 KB:

| Slots | Bytes | MiB | Row |
|---:|---:|---:|---|
| 5 | 27238400 | 26.0 | `recent_store`, held for repair whatever the cache does |
| 16 | 87162880 | 83.1 | the shipped `bn.by_root_cache.slots` |
| 11 | 59924480 | 57.1 | the difference, which is `by_root_cache` when it is on |

An ignored test in `crates/overlay-core/src/recent.rs` fills a sixteen-slot store with that
traffic and lands on the bound to the byte; the maps indexing it add about 300 bytes an entry.

The total does not move: at 200 hosts each connection's window goes from 2.79 MiB to 2.50 MiB,
and past 73 slots it is at the 1 MiB floor. Sixteen is the default because Lighthouse walks only
a few slots back for a missing parent; the 64 slots §5.8 sketched would fit, at a 321 MB row and
a 1.26 MiB window.

If you change `MemoryMax` yourself, `OverlayMemoryHigh` in `deploy/prometheus/alerts.yml` and
the two threshold lines on the dashboard's memory panel carry it as a literal and have to move
with it.

The sidecar logs this table at startup and again from `eth-gossip-overlay check-config`, at your
own roster size and against `/sys/fs/cgroup/memory.max` where there is one, so what a host
actually runs under is the number to read rather than this example.

## Throughput

Both benchmarks run a fleet of twenty whole sidecars on loopback, each with a beacon node of its
own, and time the publish that starts a message to the last beacon node that imports it. They
are ignored by default because they take minutes and measure the machine as much as the code.

```sh
cargo test --release -p eth-gossip-overlay --test stripe_throughput -- --ignored --nocapture
```

Each configuration publishes five times; the number quoted is the median of the five. Recorded
on an Apple M5 Pro, 18 cores, 64 GB, macOS 26.6.2, rustc 1.98.1, on 2026-09-08.

| Benchmark | Default | Tuned |
|---|---:|---:|
| 200 kB block, 20 nodes | 14.6 ms | 15.4 ms |
| 128 columns of 40 kB, 20 nodes | 268.7 ms | 280.3 ms |

"Default" is quinn's own 14,720-byte initial congestion window, which is what the overlay ran
with before it was tuned; "tuned" is the shipped `overlay.initial_window_bytes` of 4 MB. It is
the only tuned transport parameter an operator can move: the rest are constants or derived from
the roster, so there is nothing else to measure against.

### What the numbers do and do not say

The two columns are the same within the run-to-run spread: over six repeats the block benchmark
landed either side of the default by tenths of a millisecond, and the tuned column benchmark ran
between 275 ms and 351 ms against a default near 265 ms. Raising the initial congestion window
costs nothing on a block and can cost a little on a slot of columns.

That is what loopback should show. The window exists for a path with a round trip: a connection
carrying one block every 12 s never leaves slow start on a real link, and pays several round
trips per block for it. Loopback has none to amortise, so a 4 MB opening burst can only overrun
the receive path. The measurement worth having is a canary on real hosts
([rollout.md](rollout.md)); this pair is here to show that the tuning breaks nothing and that
the fleet still completes a slot's columns on every host in about a quarter of a second.

## The overlay I/O thread on a reserved core

Optional, Linux only, and off unless you set it. Nothing here is needed at the overlay's traffic
rates (Architecture.md §11.1); it is for operators who already reserve cores per service and
want the last of the jitter out of arrival times.

By default the QUIC endpoint shares the tokio runtime that runs the router, the batcher and the
beacon node link, so a block arriving from a sibling is read by whichever worker thread is free
— on a busy host, possibly behind a chunk being encoded or a message being handed to the beacon
node.

With a core named in `config.yaml`, the endpoint gets a single-threaded runtime of its own,
pinned to that core:

```yaml
overlay:
  io_thread:
    pin_cpu: 30
```

That runtime owns one epoll instance and nothing else runs on it, so a packet arriving is read
by a thread that was waiting for it. Frames reach the router through the same channels either
way.

### When it is worth setting

Set it when all three hold. The host is bare metal, not a container sharing cores with
neighbours you do not control. The sidecar's cgroup already has cores of its own,
`AllowedCPUs=30-31` next to the beacon node's `AllowedCPUs=0-29` in the §11 layout. And you are
measuring arrival times, so you can tell whether it changed anything.

Leave it unset otherwise: a pinned thread on a host whose cores are shared moves the contention
rather than removing it.

`pin_cpu` is read at startup only. Changing it needs a restart, not a `SIGHUP`.

### Checking that it took

`overlay_io_thread_pinned` is 1 when the endpoint is running on the core that was asked for, and
0 both when no core was named and when the kernel refused the one that was. A refusal is a
warning, not a failed start: a narrow cpuset should cost an operator the pinning and not the
overlay.

```console
$ curl -s 127.0.0.1:7789/metrics | grep io_thread
overlay_io_thread_pinned 1
```

The kernel's own answer is `psr`, the core a thread last ran on; `comm` is its name, which the
sidecar sets to `overlay-io`:

```console
$ ps -L -o pid,tid,psr,comm -p "$(pidof eth-gossip-overlay)"
    PID     TID PSR COMMAND
 118420  118420   3 eth-gossip-overl
 118420  118437  30 overlay-io
 118420  118438   7 tokio-runtime-wo
```

Sample it more than once. Every other thread moves between the cores its cgroup allows;
`overlay-io` is the one that does not.

## Busy polling with the queue's interrupt suspended

Needs kernel 6.13 or later for the `EPIOCSPARAMS` ioctl, `CAP_NET_ADMIN` for the second half,
and a `pin_cpu`, which `check-config` enforces.

```yaml
overlay:
  io_thread:
    pin_cpu: 30
    prefer_busy_poll: true
    busy_poll_usecs: 100
    irq_suspend_timeout_ms: 20
```

The I/O thread's epoll then spins on the queue for `busy_poll_usecs` before it sleeps, and the
queue's interrupt stays masked for `irq_suspend_timeout_ms` at a time while the spinning keeps
finding packets. Between bursts the timeout expires and the queue goes back to interrupts, so an
idle core is not burned.

Masking the interrupt is set over netdev netlink, which is what needs the capability:

```ini
# eth-gossip-overlay.service.d/busy-poll.conf
[Service]
AmbientCapabilities=CAP_NET_ADMIN
```

`irq_suspend_timeout_ms: 0` takes the busy polling alone and needs no capability.

### Checking that it took

`overlay_busy_poll_enabled` is 1 only when both halves are up. An older kernel, a missing
capability and a device with no NAPI queue each leave it at 0 and log which:

```console
$ curl -s 127.0.0.1:7789/metrics | grep busy_poll
overlay_busy_poll_enabled 1
```

The kernel's own answer is the interrupt count on the steered queue. Read it twice while blocks
are arriving:

```console
$ ethtool -S eth0 | grep -E 'rx_queue_3_(packets|irqs)'
```

Packets climbing with the interrupt count flat is the suspension working. Both climbing together
is busy polling on a queue that still interrupts — what a missing capability looks like.