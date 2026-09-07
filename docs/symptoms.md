# Symptoms with no alert

Things that are worth looking into and that no rule in
[`deploy/prometheus/alerts.yml`](../deploy/prometheus/alerts.yml) fires on, either because the
healthy value is a judgement call or because they show up once, on a first install, and never
again. [troubleshooting.md](troubleshooting.md) is the other half: one section per alert.

The same three commands answer most of these. `eth-gossip-overlayctl status` says what the sidecar
thinks is true, `curl -s 127.0.0.1:7789/metrics` says what it is reporting, and
`journalctl -u eth-gossip-overlay -o cat | jq .` says what it did.

## Nothing has ever arrived over the overlay

`overlay_first_seen_total{source="overlay"}` is absent or zero and every `first_arrival` line
says `"source":"bn"`. The overlay is up and is not carrying anything, which on a first install
is usually one of three things rather than a fault.

Check that the peers are actually there (`overlay_peers_connected` against the roster size),
that the beacon nodes are synced, since a syncing node subscribes to nothing and there is
nothing to mirror, and that inject is on at the *other* hosts as well as this one:
`eth-gossip-overlayctl inject status` on each. After that, the honest possibility is that this host's public
gossip is simply beating the overlay, which is a measurement rather than a fault and is what
[rollout.md](rollout.md) is for. On a two-host fleet expect that often; on a hundred, rarely.

## `overlay_unknown_topic_id_total` is not zero

A peer sent a frame with a topic id this host has not been told about. Every sender interns its
topics and announces them before it uses them, so after start-up this counter should sit still
at whatever it reached in the first seconds.

The `peer` label names the sender. A value that keeps climbing means that peer is emitting ids
it never announced, which is a version disagreement or a bug rather than anything an operator
configured. Note the peer and the topic and report it; the frames themselves are dropped, so
nothing invalid reaches a beacon node. A small number right after a restart is the announcement
race and needs nothing.

## `overlay_publish_errors_total` is climbing

The sidecar had something for the beacon node and gossipsub would not take it. Read the `reason`
label before doing anything: `no_subscribers` is not an error. It means the message arrived in
the moment between a peer telling this host it wants a topic and the local beacon node
subscribing to it, and it goes away on its own.

Any other reason is the beacon node refusing a publish, and the log line beside the counter
carries what gossipsub said. Check the link is up at all (`overlay_bn_connected`), and check
`overlay_publish_queue_drops_total` next to it: a queue that is dropping means the sidecar is
handing over faster than the beacon node accepts, which is a slow or busy node rather than a
rejection.

## `overlay_rate_limited_total` is firing

The publish limits are a bug guard, not a throttle, and the shipped defaults sit far above any
rate real gossip produces. Reaching them means either a fleet much busier than the defaults
assume or something upstream duplicating messages.

The `class` label says which limit: `small` and `large` are per-second message counts,
and the byte ceiling is shared. Compare the rate the sidecar is receiving
(`overlay_messages_total{direction="in"}`) with what the class allows before raising anything;
the three keys are `bn.publish_rate_limit.*` and they reload, so a change takes effect with
`systemctl reload` and no restart.

## The beacon node came back with a new identity

The beacon node's libp2p key changed, usually because its datadir was rebuilt, and the sidecar's
log has one line about closing a connection from a peer that is not the beacon node. That is the
beacon node's own dial-back arriving under an identity the sidecar has not learned yet: the
sidecar fetched the old peer id from the beacon API and closes anything else, which is what
stops a stray localhost peer being mistaken for the beacon node.

Nothing to do. The sidecar re-reads the beacon node's peer id on every reconnect attempt, so it
learns the new one on its next backoff cycle, a few seconds later, and the link forms. If it
does not, the beacon node is not answering `bn.identity_url` and the problem is there.

Changing `bn.listen_addr`, the address the beacon node dials the sidecar at, needs a sidecar
restart and then a beacon node restart, because the address goes onto the beacon node's command
line through `lighthouse.env`.

## Socket buffers smaller than the sidecar asked for

At startup the sidecar logs `overlay endpoint bound` with `requested_bytes` beside the
`recv_buffer_bytes` and `send_buffer_bytes` the kernel actually gave it. An effective size well
under the request means the kernel capped it at `net.core.rmem_max` or `net.core.wmem_max`, and
almost always means the sysctl file never landed on this host.

```sh
sudo install -m 644 90-eth-gossip-overlay.conf /etc/sysctl.d/
sudo sysctl --system
sudo systemctl restart eth-gossip-overlay
```

The buffers are read at bind time, so the restart is what picks the new limits up. Linux reports
twice what it stored, so a value of exactly double the request is the kernel agreeing with you,
not overshooting.
