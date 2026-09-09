# Events

The sidecar logs one line per large-class message the moment that message first reaches the
host, so a message can be followed across the fleet by its id. Fleet spread (first arrival to
last arrival for one block) and overlay win rate, the two numbers the canary is judged on
(Architecture.md §13), are queries over these lines.

An event is an ordinary `tracing` record: same subscriber, same stream, same format as every
other log line, told apart by its `event` field and its `overlay::event` target. There is no
second stream, no second file and nothing extra to configure. Under systemd everything the
process writes to stdout lands in the journal and is shipped from there, so a log shipper
already collecting the unit collects the events too.

The `log` section of `config.yaml` sets the level and the format:

```yaml
log:
  level: info      # trace, debug, info, warn, error
  format: auto     # auto, json, text
```

`auto` is JSON when stdout is not a terminal and text when it is, so a service writes JSON and
a person running the binary by hand reads text. `RUST_LOG` overrides the level and is the only
way to filter per target; while it is set, a reloaded `log.level` is ignored and the sidecar
logs that it was. Both keys reload on SIGHUP.

Queries below assume JSON. They select the unit's stream first; `{unit="eth-gossip-overlay.service"}`
is what journald's Loki shipper labels it, and any selector that reaches the sidecar's lines
works the same.

## `first_arrival`

One per large message per host: the block, blob and data-column topics. Small-class messages
travel batched and are not logged, and neither is a duplicate, so the count of these lines is
the count of distinct large messages the host saw.

| Field | Type | Meaning |
|---|---|---|
| `timestamp` | RFC 3339 string | When the line was written, from the subscriber |
| `level` | string | Always `INFO` |
| `target` | string | Always `overlay::event` |
| `event` | string | Always `first_arrival` |
| `msg_id` | 40 hex chars | The gossipsub message id, which joins this line to the same message on every other host |
| `class` | string | Always `large` |
| `topic` | string | The full gossipsub topic |
| `node` | string | The host's roster hostname |
| `region` | string | Its region |
| `site` | string | Its site label, empty when the roster gives none |
| `first_arrival_ns` | integer | Arrival, in nanoseconds since the Unix epoch, read at receipt from the beacon node or off the socket |
| `source` | string | `bn` if the local beacon node got there first, `overlay` if a fleet peer did |
| `origin_peer` | string | The peer that sent it. Present only when `source` is `overlay` |
| `slot` | integer | The slot the block or column belongs to. Present on `beacon_block` and `data_column_sidecar_*` lines |
| `block_root` | 64 hex chars | The block root, which for a column is the block the column belongs to. Present with `slot` |

Comparing `first_arrival_ns` across hosts is only as good as their clocks: run chrony with
hardware timestamping (Architecture.md §11), which holds the fleet inside a few microseconds.

`slot` and `block_root` come from the payload's own header, which the sidecar reads only for
these two topic kinds and only as far as the header, and only where it keeps the payload: as a
message arrives from the beacon node, and as one it reassembled from chunks comes back. A message
a sibling delivered whole is not kept and carries neither key, and neither does a line for any
other large topic or a line from a build without the `column-repair` feature. The keys are absent
rather than null. When the block root is here, it is what joins this line to the
[`import`](#import) event for the same block, in the same rendering on both.

### One line

```json
{"timestamp":"2026-09-07T12:00:07.312905Z","level":"INFO","event":"first_arrival","msg_id":"9f3c1d0a77b25e4418c6a2f0d51b3e8c7a409d62","class":"large","topic":"/eth2/6a95a1a9/beacon_block/ssz_snappy","node":"bn-ams1-07","region":"eu","site":"ams1","first_arrival_ns":1757246407312905114,"source":"overlay","origin_peer":"bn-fra1-02","slot":11814923,"block_root":"6f1c4d2b8a09e7f3541c0b6d92a8e35f70bd41c8a2e96d035b7f18c40de2a961","target":"overlay::event"}
```

### Fleet spread

How long a block takes to go from its first host to its last, per message, in milliseconds.
The p50 and p99 of this over a canary window are the first success criterion.

```logql
(
  max by (msg_id) (
    max_over_time({unit="eth-gossip-overlay.service"} | json | event="first_arrival" | topic=~".*beacon_block.*" | unwrap first_arrival_ns [5m])
  )
  -
  min by (msg_id) (
    min_over_time({unit="eth-gossip-overlay.service"} | json | event="first_arrival" | topic=~".*beacon_block.*" | unwrap first_arrival_ns [5m])
  )
) / 1e6
```

### Overlay win rate

The share of blocks that reached a host over the overlay before its own beacon node had them.
Above 50% is the second success criterion.

```logql
sum(count_over_time({unit="eth-gossip-overlay.service"} | json | event="first_arrival" | topic=~".*beacon_block.*" | source="overlay" [5m]))
/
sum(count_over_time({unit="eth-gossip-overlay.service"} | json | event="first_arrival" | topic=~".*beacon_block.*" [5m]))
```

Drop the `topic` filter in either query for every large message rather than blocks alone.

## `import`

One per block the beacon node imported, whether or not the block ever reached this host.

Arrival is not import. `newPayload` and column verification take 200 to 500 ms on a full block
(Architecture.md §2), and every 100 ms of that cancels 100 ms of whatever the overlay won. This
line is how you see how much of it your hosts are spending, and it is telemetry only: nothing in
the sidecar decides anything on it.

| Field | Type | Meaning |
|---|---|---|
| `timestamp` | RFC 3339 string | When the line was written, from the subscriber |
| `level` | string | Always `INFO` |
| `target` | string | Always `overlay::event` |
| `event` | string | Always `import` |
| `slot` | integer | The slot the block was proposed for |
| `block_root` | 64 hex chars | The block root, rendered as `first_arrival` renders it, which is what joins the two |
| `imported_ns` | integer | When the beacon node reported the import, in nanoseconds since the Unix epoch |
| `matched` | bool | Whether this host had a record of the block arriving |
| `first_arrival_ns` | integer | When the block first reached this host. Present only when `matched` is true |
| `lag_ms` | integer | Arrival to import, in milliseconds. Present only when `matched` is true |
| `source` | string | `bn` or `overlay`, whichever got the block here first. Present only when `matched` is true |
| `origin_peer` | string | The peer that sent it. Present only when `source` is `overlay` |

A `matched` of false is a block the beacon node imported that this host has no arrival for at
all, which is the overlay missing a block rather than nothing happening. Arrival records are
kept for eight slots of whatever `SECONDS_PER_SLOT` the beacon node reports, so a block imported
more than eight slots after it arrived also reads as unmatched, and so does one whose
`first_arrival` line carried no root: a build without the `column-repair` feature, or a block a
sibling delivered whole.

`lag_ms` is measured on the monotonic clock rather than by subtracting the two nanosecond
fields. Those two are wall readings, for comparing across hosts; a clock stepped between them
would put their difference anywhere.

### One line

The same block as the `first_arrival` line above, 315 ms later.

```json
{"timestamp":"2026-09-07T12:00:07.627905Z","level":"INFO","event":"import","slot":11814923,"block_root":"6f1c4d2b8a09e7f3541c0b6d92a8e35f70bd41c8a2e96d035b7f18c40de2a961","imported_ns":1757246407627905114,"matched":true,"first_arrival_ns":1757246407312905114,"lag_ms":315,"source":"overlay","origin_peer":"bn-fra1-02","target":"overlay::event"}
```

### Arrival to import

How long the beacon node spends on a block this host already had. It is the ceiling on what the
overlay can still win, so a p99 climbing towards a slot says the next bottleneck is the beacon
node and not the network.

```logql
quantile_over_time(0.99, {unit="eth-gossip-overlay.service"} | json | event="import" | matched="true" | unwrap lag_ms [5m])
```

Swap `0.99` for `0.5` for the median.

### Blocks the overlay missed

The share of imports this host had no arrival for. `overlay_import_events_total{matched="no"}`
is the same number as a counter, which is what the dashboard reads.

```logql
sum(count_over_time({unit="eth-gossip-overlay.service"} | json | event="import" | matched="false" [5m]))
/
sum(count_over_time({unit="eth-gossip-overlay.service"} | json | event="import" [5m]))
```

## journald fields

`tracing-journald` would send each field as a journal field of its own instead of packing JSON
into `MESSAGE`, which suits a fleet querying the journal directly. It is a welcome addition as
another `log.format` and is not the default: the shipped path is one JSON stream, because that
is what works the same under systemd, in a container and on a terminal.
