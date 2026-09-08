# Performance

Two numbers an operator needs before a rollout: what the large class costs in wall time, and
what the process holds when every bounded structure inside it is full. The first is measured,
the second is arithmetic over the code's own constants.

## Memory

`MemoryMax=1G` in the shipped unit is the ceiling this table is written against (OPS-N4). Every
row is a structure with a bound in code, so the sum is a worst case and not a measurement:
nothing in it grows with traffic, and a real fleet sits far below it. Two rows read zero because
the structure they name has not been built yet, `recent_store` (T-081) and `by_root_cache`
(T-085); each ticket fills its own row in.

`quic_receive_windows` is the one row that is not a constant. It is whatever the other rows
leave under the ceiling, shared out over the roster and floored at the 1 MiB stream window
(DX-N3), so a larger fleet gives each peer a smaller window rather than pushing the total up.
Once the floor binds, it cannot shrink further and the sidecar warns at startup.

<!-- generated from crates/overlay-core/src/budget.rs, do not edit by hand -->

At the shipped defaults, a roster of 200 hosts and the unit's `MemoryMax=1G`, which gives every connection a receive window of 2.9 MiB.

| Structure | Bytes | MiB |
|---|---:|---:|
| `seen_cache` | 12800000 | 12.2 |
| `recent_store` | 0 | 0.0 |
| `publish_queue` | 35651584 | 34.0 |
| `reassembler` | 35651584 | 34.0 |
| `peer_send_lanes` | 128241664 | 122.3 |
| `gossipsub` | 34132480 | 32.6 |
| `by_root_cache` | 0 | 0.0 |
| `quic_receive_windows` | 609453420 | 581.2 |
| **Sum of the bounds** | 855930732 | 816.3 |
| **Plus 25% headroom** | 1069913415 | 1020.3 |
| `MemoryMax` | 1073741824 | 1024.0 |

<!-- end generated -->

Because the QUIC row is the remainder, the sum sits on the usable line whatever the roster, and
the floor is what eventually breaks that: the other rows grow with the fleet until there is less
than 1 MiB per connection to hand out, and past that point the total goes over. At these
defaults that happens at 498 hosts. A row that grows for any other reason brings it forward, so
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
