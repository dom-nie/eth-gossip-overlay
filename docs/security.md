# Security

The overlay port is a trusted path into every beacon node in the fleet. Whatever a sidecar
accepts there, its beacon node validates as ordinary gossip and forwards to its own public
peers. This document is about the fences around that port, the two secrets behind them, and what
an attacker gets if a fence fails.

Reporting a vulnerability in the sidecar itself is [SECURITY.md](../SECURITY.md).

## What is and is not at risk

The sidecar holds no validator keys, signs nothing and creates no messages. It relays messages
that already carry a BLS signature, and the receiving beacon node checks that signature as it
would for any peer. A modified message is rejected there. There is no slashing exposure anywhere
in this system and no path from a compromised sidecar to a signature.

What an attacker with a foothold on the overlay does get is CPU. Junk delivered to a sidecar is
published to its beacon node and validated before it is thrown away, and a message that fans out
reaches every host. That is the cost the fences are sized against, and it is bounded twice: by
the publish rate limits on the way into a beacon node, and by the per-peer fan-out budget that
stops one authenticated sibling making the whole fleet do its work. Repair answers sit outside
both, so each peer also gets a bucket on how often this host will answer one.

Confidentiality is not a goal. Everything on the overlay is public gossip, and QUIC's encryption
is there because QUIC requires TLS, not because the payloads are secret. Losing a beacon node is
no worse than it is today: every other beacon node validates what it receives.

## Three fences

An **nftables allowlist** on UDP 7788, generated from the same inventory as the roster, so
packets from anywhere but a fleet host are dropped before QUIC sees them. Regenerate it whenever
the roster changes; [`deploy/nftables/`](../deploy/README.md) has the template.

**Key pinning** underneath it. Every host derives every other host's overlay TLS key from the
fleet seed and that host's name, and the verifier accepts a connection only from a key in that
table. This is the fence that holds when a firewall rule is pushed wrong or a neighbour on the
same network is taken. There is no certificate authority and no expiry: the seed and the roster
are the whole of admission.

A **fan-out budget** per peer at the receiver, so a sibling that authenticated correctly and
then started shouting is delivered locally, not re-fanned, and is disconnected if it keeps at
it. `overlay_fanout_suppressed_total` is never non-zero on a healthy fleet, which is why any
value at all alerts.

## Watching the fence work

`overlay_handshake_failures_total{role, reason}` counts every refused handshake. `role` is
`dial` or `accept`. The reason says what was wrong:

| Reason | What it means |
|---|---|
| `unknown_key` | the key presented is not any roster host's key. A wrong seed, or a host that is not in this roster |
| `key_mismatch` | the dialled host answered with a key that is not the one its roster entry derives |
| `hostname` | the key was right and the name the peer claimed in `HELLO` was not the name that key belongs to |
| `version` | different protocol majors, which is a rolling upgrade in progress ([upgrading.md](upgrading.md)) and not an attack |
| `timeout`, `decode` | the handshake did not finish or did not parse. The path, not admission |

A steady rate of any of the first three is a real disagreement about who is allowed in.
[troubleshooting.md](troubleshooting.md#overlayhandshakefailures) has the walk.

## Holding the seed

The seed is the fleet's admission secret: anyone with it and the roster can compute every host's
key. Keep it out of the service's reach by handing it to the process as a systemd credential.
The shipped unit does this already:

```ini
LoadCredential=seed:/etc/eth-gossip-overlay/seed
DynamicUser=yes
StateDirectory=eth-gossip-overlay
```

`DynamicUser=yes` means no service account owns anything, and the seed is readable only through
`$CREDENTIALS_DIRECTORY`, which systemd mounts for this process alone. The sidecar prefers
`$CREDENTIALS_DIRECTORY/seed` over `overlay.fleet_seed_file` whenever it is there, so the
configured path is the fallback for people not running under systemd.

For a host where a plain file at rest is too much, encrypt it to the host's TPM or its machine
key and drop the plaintext:

```sh
sudo systemd-creds encrypt --name=seed seed /etc/eth-gossip-overlay/seed.cred
sudo rm /etc/eth-gossip-overlay/seed
```

then replace the line in the unit with
`LoadCredentialEncrypted=seed:/etc/eth-gossip-overlay/seed.cred`. Nothing else changes: the sidecar
reads the same place either way.

The node key in `bn.node_key_file` is a different secret with a much smaller blast radius. It is
per host, created on first start with mode 0600 inside `StateDirectory=`, and it is the identity
the local beacon node trusts. Somebody who steals it can pretend to be this host's sidecar to
this host's beacon node, which they could only reach from the host itself.

The roster is not secret but it is not public either: it names every host in the fleet and the
address each one answers on. Treat it the way you treat an inventory.

## Rotating the seed

No beacon node is touched by a rotation, and no beacon node restarts. The libp2p identity a
beacon node trusts is the node key, which the seed does not derive, so peer ids are unchanged
throughout.

The mesh stays full because every host spends the rotation accepting keys from both seeds. The
one thing to understand before starting is that `overlay.fleet_seed_file` is read once at
startup: a reload never changes the seed a running sidecar derives its own key from. That is why
the new seed goes in as the *previous*-seed file first, and why the order below is not the
obvious one.

`overlay.fleet_seed_previous_file` must be absent from `config.yaml` before you start. A reload
applies a key only when its value changes in the document, so a key that is already there does
nothing when the file behind it is rewritten.

**Step 1. Every host accepts both seeds.** Push the *new* seed to
`/etc/eth-gossip-overlay/seed.previous`, leaving `/etc/eth-gossip-overlay/seed` as the old one, and add the
key that names it:

```yaml
overlay:
  fleet_seed_previous_file: /etc/eth-gossip-overlay/seed.previous
```

Then reload everywhere and check the report says it applied:

```sh
sudo systemctl reload eth-gossip-overlay
```

Every running sidecar now derives its own key from the old seed and admits keys from either.
Nothing has moved yet, and the mesh is untouched.

**Step 2. Lay the files out for the restarts, and do not reload.** Push the new seed as
`/etc/eth-gossip-overlay/seed` and the old one as `/etc/eth-gossip-overlay/seed.previous`, swapping the two
files. Leave the config key exactly where it is.

This is the step to get right. A sidecar that is running keeps the pair it already loaded, both
seeds, and does not look at the files again. A sidecar that starts now reads the new seed as its
own and the old one as the one it also accepts, which is the same pair the other way round. Both
kinds of host talk to both kinds of host. Reloading here is the one thing that breaks it: it
would hand a host still running on the old seed the old seed as its previous one too, and it
would then refuse every host that had already restarted.

**Step 3. Restart the sidecars, one host at a time.**

```sh
sudo systemctl restart eth-gossip-overlay
```

Wait for the host to come back to a full peer count before doing the next one.
`overlay_peer_auth_via_previous_seed_total` climbs while the two populations are talking to each
other and stops when the last host is done, which is the signal that the walk is over. A host
that restarts on its own in the middle of this, or a crash loop, is harmless: the files on disk
are a working pair at every point in this procedure.

**Step 4. Retire the old seed.** Take `overlay.fleet_seed_previous_file` back out of
`config.yaml` and reload everywhere. Every host is now pinning the new seed alone, and
`overlay_peer_auth_via_previous_seed_total` stops moving for good. Only then delete
`/etc/eth-gossip-overlay/seed.previous`, and destroy the old seed wherever you kept it.
