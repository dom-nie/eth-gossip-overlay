# Troubleshooting

One section per alert in [`deploy/prometheus/alerts.yml`](../deploy/prometheus/alerts.yml): what
the alert is telling you, and the first thing to look at. Each rule's `runbook` annotation points
at the section below it, so the link in the notification lands on the right paragraph.

[symptoms.md](symptoms.md) is the other half of the runbook: the things worth looking into that
no rule fires on, because the healthy value is a judgement call or because they only ever happen
on a first install.

Three commands answer most of these. `fleet-overlayctl status` says what the sidecar thinks is
true, `curl -s 127.0.0.1:7789/metrics` says what it is reporting, and
`journalctl -u fleet-overlay -o cat | jq .` says what it did. Run them in that order.

## OverlayPeersLow

Fewer than 80% of the roster's other hosts have a live overlay connection, for five minutes. The
sidecar keeps dialling the missing ones with a jittered backoff throughout, so this is about why
those dials are not landing rather than about the sidecar giving up.

Start with `fleet-overlayctl status` on the host that alerted and on one of the hosts missing
from its list. If both sides agree they cannot see each other, the path is the suspect: UDP 7788
between those two addresses, the nftables allowlist that was regenerated when the roster changed,
and whether the roster's address for that host is still the address it listens on. If the dials
are getting there and being refused, it is admission rather than the network, and
`overlay_handshake_failures_total` has the reason in a label. A whole region missing at once is
usually one firewall change; a single host missing from everyone's view is usually that host.

## OverlayBnDisconnected

The link to the local beacon node has been down for two minutes. Nothing crosses the overlay into
this node while it lasts, and nothing this node validates leaves over the overlay, so the host is
running on public gossip alone. Its validators are not at risk, but it is getting none of the
overlay's benefit.

Check the beacon node is up and its libp2p port is where `bn.libp2p_addr` says. The sidecar dials
it and reconnects on its own, so a beacon node that was restarted comes back without help. If the
beacon node is up and the link still will not form, read the sidecar's log: the dial error names
the cause, and the common one is a beacon node listening somewhere other than the configured
address. A beacon node whose datadir was rebuilt has a new libp2p key and takes one backoff cycle
longer, which [symptoms.md](symptoms.md#the-beacon-node-came-back-with-a-new-identity) explains.

## OverlayNotTrustedByBn

The beacon node is up and answering, and it does not list the sidecar as a trusted peer. An
untrusted sidecar is scored and pruned like any other peer, so it gets dropped under peer
pressure and the overlay quietly stops delivering.

This is a drop-in problem, not a network one. The sidecar writes
`/run/fleet-overlay/lighthouse.env` at startup and the beacon node reads it through the drop-in;
the two flags only take effect if `$FLEET_OVERLAY_TRUSTED_PEER_ARGS` is on the beacon node's own
`ExecStart=` line, unquoted, and the beacon node has been restarted since. Check that file exists,
that its peer id matches `fleet-overlay peer-id`, and that the running beacon node's command line
carries both flags. A sidecar that lost its node key has a new peer id and the beacon node is
still trusting the old one, which looks the same from here.

## OverlayHandshakeFailures

Overlay handshakes have been failing at a steady rate for fifteen minutes. One or two failures
around a peer restart are normal and this alert sits through them; a rate that does not stop is a
disagreement about who is allowed in.

The `reason` label says which. `unknown_key` and `key_mismatch` mean the two ends derived
different TLS keys, which is a fleet seed that is not the same everywhere, or a host whose roster
entry does not carry the hostname its key was derived from. `hostname` means the key was right and
the name in `HELLO` was not. `version` means the two ends are on different protocol majors, which
is expected during a rolling upgrade and stops when the last host is done, so check
[upgrading.md](upgrading.md) before treating it as a fault. `timeout` and `decode` point back at
the path rather than at admission.

## OverlayWinRateFalling

Under half of the large messages this host saw arrived over the overlay before its own beacon node
had them. The overlay is running and is not winning, which is the outcome the canary is measuring,
so treat this as a measurement before treating it as a fault.

A host that is behind on peers wins less, so check `OverlayPeersLow` first. After that, the honest
possibilities are that this host's public gossip is unusually fast, that the fleet's other hosts
are not injecting (`fleet-overlayctl status` shows the kill switch), or that the sidecar is
dropping what it receives before it can publish, which shows up in the guardrail panels rather
than here. A win rate that falls across the whole fleet at once is worth reading as a change on the
public network, not on your hosts.

## OverlayFanoutSuppressed

A peer sent more second-hop work than the roster size and the message sizes can account for, and
this host refused to re-fan it. The budget exists so one misbehaving sibling cannot make every
other host do its fan-out, and on a healthy fleet it is never reached.

The `peer` label names the sender and `kind` says which second hop was charged. Look at that peer:
a sidecar that has been restarted into a loop, a host that is relaying for a region it should not
be, or a roster the two hosts disagree about. Sustained violation closes the connection with
`RateExceeded` and the peer reconnects with backoff, so a flapping peer in the live view alongside
this alert is the same story told twice.

## OverlayRosterReloadRejected

An automatic roster reload would have removed more than half of the current hosts, and the shrink
guard refused it. The sidecar kept the roster it already had, so nothing is broken right now.

Something wrote a truncated `roster.yaml`. Usually the discovery tool ran against an incomplete
inventory, or a templating step failed halfway and left a valid file with a short list. Compare
the file on disk with what you expect, fix the generator, and let the next automatic reload pick
it up. A genuine fleet shrink of more than half is applied with a manual reload, which the guard
does not touch: `fleet-overlayctl roster reload`.

## OverlayMemoryHigh

Resident memory has been over 80% of the unit's `MemoryMax` for ten minutes. At 100% the cgroup
kills the process and systemd restarts it, which costs the beacon node its trusted peer for a few
seconds.

`fleet-overlay check-config` prints the memory budget the sidecar computed from the effective
config and roster size, which is what it expects to hold; comparing that number with the ceiling
says whether the ceiling is simply too low for this fleet. If the budget is well under the ceiling
and resident memory is not, look at the peer send lanes and the publish queue in the dashboard: a
slow peer holds a full lane. Note that the alert's threshold is a literal, so a `MemoryMax` you
raised in the unit has to be raised in the rule too.

## OverlaySidecarRestarting

The process started more than twice in the last hour. The unit restarts always and backs a crash
loop off to a minute, so a sidecar that keeps dying looks healthy in `systemctl status` between
restarts and this counter is what notices.

`journalctl -u fleet-overlay` covers the restarts and the reason is usually in the last lines
before each one. Two causes account for most of it: the watchdog firing because a core loop
stopped making progress, and the cgroup killing the process on memory, which `OverlayMemoryHigh`
would have called first. A configuration or roster file that no longer parses stops the sidecar at
startup rather than looping it, and `fleet-overlay check-config` says so in one line.

## OverlayRepairRateRising

This host is asking peers to resend chunks it did not receive, at a rate that is not incidental.
Repair is a v3 feature and the counter cannot move before it ships, so on a v1 or v2 fleet this
alert firing means something other than the sidecar is writing that series.

Once repair is in, a rising rate is loss on the overlay path rather than a fault in the sidecar:
one host or one link dropping chunks, or a region whose stripes do not arrive inside the deadline.
Read it next to `overlay_peer_queue_drops_total` on the sending side, which says whether the
chunks were dropped before they were ever sent.
