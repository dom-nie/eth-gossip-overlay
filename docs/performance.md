# Performance

Two numbers an operator needs before a rollout: what the large class costs in wall time, and
what the process holds when every bounded structure inside it is full. The first is measured,
the second is arithmetic over the code's own constants.

## Memory

`MemoryMax=1G` in the shipped unit is the ceiling this table is written against (OPS-N4). Every
row is a structure with a bound in code, so the sum is a worst case and not a measurement:
nothing in it grows with traffic, and a real fleet sits far below it. One row reads zero because
the structure it names has not been built yet, `by_root_cache` (T-085); that ticket fills its own
row in.

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

Because the QUIC row is the remainder, the sum sits on the usable line whatever the roster, and
the floor is what eventually breaks that: the other rows grow with the fleet until there is less
than 1 MiB per connection to hand out, and past that point the total goes over. At these
defaults that happens at 478 hosts. A row that grows for any other reason brings it forward, so
a fleet well inside the limit today is not necessarily inside it after a bound moves.

The ceiling was 512M until MD-05, where this table first got computed and the 200-host example
did not fit; the largest roster that did was 181. Nothing had grown, and 512M had never been
justified anywhere the bounds it holds were, so the ceiling moved rather than the bounds. If you
change `MemoryMax` yourself, `OverlayMemoryHigh` in `deploy/prometheus/alerts.yml` and the two
threshold lines on the dashboard's memory panel carry it as a literal and have to move with it.

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
the only tuned transport parameter an operator can move. The stream limits, the stream window
and the 2 s read timeout are constants, and the connection receive window is derived from the
roster, so there is no configuration that turns them off to measure against.

### What the numbers do and do not say

The two columns are the same within the run-to-run spread. Over six repeats the block benchmark
landed either side of the default by a few tenths of a millisecond, and the tuned side of the
column benchmark ran between 275 ms and 351 ms against a default that stayed near 265 ms.
Raising the initial congestion window costs nothing on a 200 kB block and can cost a little on a
slot of columns.

That is what loopback should show. The window exists for a path with a round trip: a connection
carrying one block every 12 s never leaves slow start on a real link, and pays several round
trips per block for it. Loopback has no round trip to amortise, so a 4 MB opening burst can only
overrun the receive path and buy back retransmits. The measurement worth having is a canary on
real hosts ([rollout.md](rollout.md)), which is where the window has something to win; this pair is
here to show that the tuning does not break anything and that the fleet still completes a slot's
columns on every host in about a quarter of a second.

## The overlay I/O thread on a reserved core

Optional, Linux only, and off unless you set it. Nothing here is needed at the overlay's traffic
rates (Architecture.md §11.1); it is for operators who already reserve cores per service and
want the last of the jitter out of arrival times.

By default the QUIC endpoint shares the tokio runtime that runs the router, the batcher and the
beacon node link. A block arriving from a sibling is read by whichever worker thread is free,
which on a busy host means it can queue behind a chunk being encoded or a message being handed
to the beacon node.

With a core named in `config.yaml`, the endpoint gets a single-threaded runtime of its own,
pinned to that core:

```yaml
overlay:
  io_thread:
    pin_cpu: 30
```

That runtime owns one epoll instance and nothing else runs on it, so a packet arriving is read
by a thread that was waiting for it. The rest of the sidecar is unchanged: frames reach the
router through the same channels either way.

### When it is worth setting

Set it when all three hold. The host is bare metal, not a container sharing cores with
neighbours you do not control. The sidecar's cgroup already has cores of its own,
`AllowedCPUs=30-31` next to the beacon node's `AllowedCPUs=0-29` in the §11 layout. And you are
measuring arrival times, so you can tell whether it changed anything.

Leave it unset otherwise. An unset core costs nothing at all, and a pinned thread on a host
whose cores are shared moves the contention rather than removing it.

`pin_cpu` is read at startup only. Changing it needs a restart, not a `SIGHUP`.

### Checking that it took

`overlay_io_thread_pinned` is 1 when the endpoint is running on the core that was asked for, and
0 both when no core was named and when the kernel refused the one that was. The refusal is a
warning in the log, not a failed start: a cpuset narrower than the configuration expects should
cost an operator the pinning and not the overlay.

```console
$ curl -s 127.0.0.1:7789/metrics | grep io_thread
overlay_io_thread_pinned 1
```

The kernel's own answer is the thread's processor number. `psr` is the core a thread last ran
on and `comm` is its name, which the sidecar sets to `overlay-io`:

```console
$ ps -L -o pid,tid,psr,comm -p "$(pidof eth-gossip-overlay)"
    PID     TID PSR COMMAND
 118420  118420   3 eth-gossip-overl
 118420  118437  30 overlay-io
 118420  118438   7 tokio-runtime-wo
```

Sample it more than once. Every other thread moves between the cores its cgroup allows;
`overlay-io` is the one that does not.
