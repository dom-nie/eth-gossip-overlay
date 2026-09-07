# Upgrading

A new release is a new binary on each host. Whether the hosts can be done in any order, or have
to be marched through region by region, is the one thing a release tells you before you start:
the `Protocol:` line in its notes.

| The release's `Protocol:` line | What it means for a fleet mid-upgrade |
|---|---|
| `major unchanged (1); features added: none` | Every pair keeps working. Any order, no coordination. |
| `major unchanged (1); features added: STRIPING (bit 1)` | Every pair keeps working. Hosts that have the release use the new path with each other and the old one with everybody else. |
| `major 1 → 2` | Old and new never pair. The fleet is two separate overlays until the last host is done. |

The major travels in the overlay's ALPN and the minor and feature bits in `HELLO`, so a pair
runs at the lower minor and the intersection of the feature bits (Architecture §5.3). That is
what makes the first two rows uneventful and the third one a planned operation.

Whichever case you are in, the beacon nodes keep their public peers throughout. A fleet with no
overlay at all still imports everything it would have imported; the overlay is an accelerator.

## Before you start

Verify what you downloaded against the release's `SHA256SUMS`, and against the provenance
attestation if you want to know which workflow run built it:

```sh
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify eth-gossip-overlay-<version>-x86_64-unknown-linux-gnu.tar.gz \
  --repo dom-nie/eth-gossip-overlay
```

Then read the two lines the binary prints about itself. The second one is the same three numbers
the release notes are written from:

```console
$ ./eth-gossip-overlay --version
eth-gossip-overlay 0.1.0 9e5e500d46d6 2026-09-07
protocol 1.0 features=0x0
```

## A minor or feature-bit change

Nothing to plan. One host at a time, or all of them at once:

```sh
sudo install -m 755 eth-gossip-overlay eth-gossip-overlayctl /usr/local/bin/
sudo systemctl restart eth-gossip-overlay
```

The host reconnects to every peer as it comes back, old and new alike. What to watch, from any
host:

```console
$ eth-gossip-overlayctl status
hostname    region  site  rtt     up   queue_small  queue_large  version  features
bn-ams1-07  eu      ams1  1.2ms   3d   0f/0b        0f/0b        0.1.0    0x0
bn-ams1-08  eu      ams1  1.1ms   2m   0f/0b        0f/0b        0.2.0    0x0
```

The `version` column fills in with the new release as you work through the fleet. The `features`
column is the pair's negotiated intersection, so a bit a release adds shows up on a row only
once *both* ends of that pair have the release: it stays `0x0` on rows against hosts you have
not done yet and converges on the new value as the last of them is restarted. Watch
`overlay_peers_connected` too; on a feature-bit release it never moves.

## A major bump

Two sidecars on different majors do not pair: the ALPN does not match and the TLS handshake
fails, which is deliberate, because a pair that got past it would be exchanging frames neither
side could read. So the fleet spends the rollout as two overlays, each a full mesh inside
itself.

Upgrade a region at a time, finishing each region before starting the next. A region that is
entirely on one major keeps its own fan-out intact; what is missing is the traffic that would
have crossed between regions, and that is the part public gossip covers anyway.

While the skew lasts, expect on every host:

- `overlay_handshake_failures_total{reason="version"}` climbing, once per failed dial per peer
  on the other major. It stops climbing when the last host is done. It is the metric that tells
  you the rollout is not finished; alert on it being non-zero for longer than the rollout window,
  not on it being non-zero at all.
- `overlay_peers_connected` down to the size of this host's own population, and back to the
  whole roster at the end.
- `eth-gossip-overlayctl status` listing only the peers on this host's major.

Do not leave a fleet split across a major for longer than the rollout needs. Two half-size
overlays are not broken, but neither half is what you deployed.

## Rolling back

Reinstall the previous binary and restart:

```sh
sudo install -m 755 /path/to/previous/eth-gossip-overlay /usr/local/bin/eth-gossip-overlay
sudo systemctl restart eth-gossip-overlay
```

There is nothing to migrate. The sidecar keeps no persistent state of its own: the seen cache,
the topic tables and the live set are all rebuilt from what arrives after a start. The node key
in `bn.node_key_file` and the fleet seed are files an upgrade never touches, so the peer id the
beacon node trusts and the overlay TLS key are the same afterwards as before, and neither the
beacon node nor the other hosts have to be told anything.

Two things to know:

- If the release you are leaving added a configuration key and you started using it, the older
  binary will refuse the file: unknown keys are an error, not a warning. Run
  `eth-gossip-overlay check-config` with the older binary before you restart it, and take the new
  keys back out if it complains.
- Rolling back across a major bump is the major-bump procedure again, in the other direction,
  with the same two populations while it lasts.
