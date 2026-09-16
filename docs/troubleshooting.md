# Troubleshooting

One section per alert in [`deploy/prometheus/alerts.yml`](../deploy/prometheus/alerts.yml): what
the alert is telling you, and the first thing to look at. Each rule's `runbook` annotation points
at its section, so the link in the notification lands on the right paragraph.

[symptoms.md](symptoms.md) is the other half: what no rule fires on, because the healthy value
is a judgement call or because it only ever happens on a first install.

Three commands answer most of these. `eth-gossip-overlayctl status` says what the sidecar thinks is
true, `curl -s 127.0.0.1:7789/metrics` says what it is reporting, and
`journalctl -u eth-gossip-overlay -o cat | jq .` says what it did. Run them in that order.

## OverlayPeersLow

Fewer than 80% of the roster's other hosts have a live overlay connection, for five minutes. The
sidecar keeps dialling the missing ones with a jittered backoff, so this is about why those dials
are not landing.

Start with `eth-gossip-overlayctl status` on the host that alerted and on one of the hosts missing
from its list. If both sides agree they cannot see each other, suspect the path: UDP 7788 between
the two addresses, the nftables allowlist regenerated when the roster changed, and whether the
roster's address for that host is still the one it listens on. Dials that arrive and are refused
are admission rather than network, and `overlay_handshake_failures_total` has the reason in a
label. A whole region missing at once is usually one firewall change; a single host missing from
everyone's view is usually that host.

## OverlayBnDisconnected

The link to the local beacon node has been down for two minutes. Nothing crosses the overlay in
either direction while it lasts, so the host runs on public gossip alone. Its validators are not
at risk, but it gets none of the overlay's benefit.

Check the beacon node is up and its libp2p port is where `bn.libp2p_addr` says. The sidecar
reconnects on its own, so a restarted beacon node comes back without help. If the link still will
not form, the sidecar's log has the dial error, usually a beacon node listening somewhere other
than the configured address. A beacon node whose datadir was rebuilt has a new libp2p key and
takes one backoff cycle longer, which
[symptoms.md](symptoms.md#the-beacon-node-came-back-with-a-new-identity) explains.

## OverlayNotTrustedByBn

The beacon node is up and answering, and it does not list the sidecar as a trusted peer. An
untrusted sidecar is scored and pruned like any other peer, so under peer pressure the overlay
quietly stops delivering.

This is a drop-in problem, not a network one. The sidecar writes
`/run/eth-gossip-overlay/lighthouse.env` at startup and the beacon node reads it through the drop-in;
the two flags only take effect if `$ETH_GOSSIP_OVERLAY_TRUSTED_PEER_ARGS` is on the beacon node's own
`ExecStart=` line, unquoted, and the beacon node has been restarted since. Check that file exists,
that its peer id matches `eth-gossip-overlay peer-id`, and that the running beacon node's command line
carries both flags. A sidecar that lost its node key has a new peer id and the beacon node is
still trusting the old one, which looks the same from here.

## OverlayHandshakeFailures

Overlay handshakes have been failing at a steady rate for fifteen minutes. One or two failures
around a peer restart are normal and this alert sits through them; a rate that does not stop is a
disagreement about who is allowed in.

The `reason` label says which. `unknown_key` and `key_mismatch` mean the two ends derived
different TLS keys, which is a fleet seed that is not the same everywhere, or a host whose roster
entry does not carry the hostname its key was derived from. `hostname` means the key was right and
the name in `HELLO` was not. `version` means the two ends are on different protocol majors,
expected during a rolling upgrade until the last host is done; see [upgrading.md](upgrading.md).
`timeout` and `decode` point back at the path rather than at admission.

## OverlayWinRateFalling

Under half of the large messages this host saw arrived over the overlay before its own beacon node
had them. The overlay is running and not winning, which is what the canary measures, so treat
this as a measurement before treating it as a fault.

A host that is behind on peers wins less, so check `OverlayPeersLow` first. After that, either
this host's public gossip is unusually fast, the fleet's other hosts are not injecting
(`eth-gossip-overlayctl status` shows the kill switch), or the sidecar is dropping what it
receives before it can publish, which the guardrail panels show. A win rate that falls across the
whole fleet at once is worth reading as a change on the public network, not on your hosts.

## OverlayFanoutSuppressed

A peer sent more second-hop work than the roster size and the message sizes can account for, and
this host refused to re-fan it. The budget exists so one misbehaving sibling cannot make every
other host do its fan-out, and on a healthy fleet it is never reached.

The `peer` label names the sender and `kind` says which second hop was charged. Look at that peer:
a sidecar restarted into a loop, a host relaying for a region it should not be, or a roster the
two hosts disagree about. Sustained violation closes the connection with
`RateExceeded` and the peer reconnects with backoff, so a flapping peer in the live view alongside
this alert is the same story told twice.

## OverlayRosterReloadRejected

An automatic roster reload would have removed more than half of the current hosts, and the shrink
guard refused it. The sidecar kept the roster it already had, so nothing is broken right now.

Something wrote a truncated `roster.yaml`. Usually the discovery tool ran against an incomplete
inventory, or a templating step failed halfway and left a valid file with a short list. Compare
the file on disk with what you expect, fix the generator, and let the next automatic reload pick
it up. A genuine shrink of more than half is applied with a manual reload, which the guard
does not touch: `eth-gossip-overlayctl roster reload`.

## OverlayMemoryHigh

Resident memory has been over 80% of the unit's `MemoryMax` for ten minutes. At 100% the cgroup
kills the process and systemd restarts it, which costs the beacon node its trusted peer for a few
seconds.

`eth-gossip-overlay check-config` prints the budget the sidecar computed from the effective
config and roster size, the ceiling it read, and warns when the first is over the second: the
ceiling is too low for this fleet. If the budget is well under the ceiling and resident memory is
not, look at the peer send lanes and the publish queue in the dashboard: a slow peer holds a full
lane. The alert's threshold is a literal, so a `MemoryMax` raised in the unit has to be raised in
the rule.

## OverlaySidecarRestarting

The process started more than twice in the last hour. The unit restarts always and backs a crash
loop off to a minute, so a sidecar that keeps dying looks healthy in `systemctl status` between
restarts and this counter is what notices.

`journalctl -u eth-gossip-overlay` covers the restarts, with the reason usually in the last lines
before each one. Most are the watchdog firing because a core loop stopped making progress, or the
cgroup killing the process on memory, which `OverlayMemoryHigh` would have called first. A configuration or roster file that no longer parses stops the sidecar at
startup rather than looping it, and `eth-gossip-overlay check-config` says so in one line.

## OverlayRepairRateRising

This host is asking peers to resend what it did not receive. [rollout.md](rollout.md) says where
the threshold comes from. Split it two ways first:

```promql
sum by (instance, form, outcome) (rate(overlay_repair_requests_total[15m]))
```

`form="chunk"` is loss on the overlay path, not a fault in the sidecar: one host or one link
dropping chunks, or a region whose stripes miss `classes.large.repair_deadline_ms`.
`overlay_peer_queue_drops_total` beside it says whether the chunks were dropped before they were
sent.

`form="column"` is this beacon node short of custody columns past the same deadline, which is
rarer. Setting `classes.large.column_repair: false` and reloading turns it off; the node then
fetches its own columns.

`outcome` splits either form. `completed` is loss repair covered. `not_found` and `timeout` are
peers that could not answer. `gave_up` is no request sent: no candidate was live and advertising
the feature bit, expected during a rolling upgrade. `rate_limited` is counted by the answering
host: a peer asked faster than its bucket allows. Zero on an honest fleet.

`overlay_column_topic_mismatch_total` beside it reads zero on a healthy fleet; it counts a network
whose subnets do not name its columns.

## OverlayColumnIndexConflict

Two payloads claimed the same column, which an honest fleet never produces: a roster peer sent a
forged sidecar. This host keeps whichever came first and answers column repair with it; the
requester's beacon node rejects that, and nothing a host was served is served on, so each
requester loses one round trip.

The warn line names `held` and `refused`. Join `held` to its `first_arrival` line for
`origin_peer`, check `overlay_invalid_payload_total{peer}` on the same window, and take that peer
out of the roster.
