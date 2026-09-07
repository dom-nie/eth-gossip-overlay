# Questions

## Why a sidecar and not a patch to Lighthouse?

An in-process module would be faster. It would drop the localhost hop, it would not have to wait
for the beacon node's validation echo before forwarding, and it could receive IDONTWANT from the
beacon node the way a mesh peer does. All three of the remaining inefficiencies are artifacts of
the process boundary.

The price is a Lighthouse fork, rebased on every release, forever. For a fleet of any size that
is a worse trade than a few milliseconds: the sidecar upgrades on its own schedule, a bad
release is a `systemctl restart` away from being reverted, and the beacon node runs the binary
its own maintainers shipped. If the fork ever stops being the expensive option, the design is
recorded and the decision can be taken again.

## Why not RLNC, like the hosted gateways?

Random linear network coding earns its cost on a large, lossy, multi-hop mesh of parties who do
not know each other: nodes can recode without coordinating, any coded chunk is as good as any
other, and duplicates are not wasted. This overlay is the opposite of that setting. Membership
is known, the paths are one or two hops between machines you own, the links are reliable, and
every peer is trusted.

So the benefits do not apply while the costs do: Gaussian elimination per message, a rank check
on the receive path, decoding before anything can be delivered, and patent exposure. Systematic
Reed-Solomon parity gives the loss resilience for nothing in the common case, because the data
chunks are the message and parity is only touched when something is missing.

## What happens if the sidecar dies?

The beacon node loses one explicit peer and carries on with its public ones. Nothing is queued,
nothing is lost, and no duty outcome is worse than it would be on a host that never had a
sidecar. systemd restarts it, and a wedged process that stops making progress is killed by the
watchdog after 30 seconds and restarted too.

The units are deliberately not bound to each other, so neither restart touches the other. The
overlay is an accelerator: every failure mode ends at "this host is now a fleet member without
the overlay", which is where everyone started.

## Does the sidecar hold any keys?

No validator keys, and it signs nothing. It has two secrets and neither can sign a message: the
fleet seed, which derives the TLS key that admits it to the overlay, and its libp2p node key,
which is the peer id the local beacon node trusts. Everything the sidecar relays already carries
the signature of whoever created it, and the beacon node on the far end checks that signature
before it accepts anything. [security.md](security.md) is the whole picture.

## What does rotating the seed do to my beacon nodes?

Nothing. No beacon node restarts and no peer id changes. The seed derives only the overlay TLS
key that sidecars use with each other; the identity a beacon node trusts is the node key, a
per-host file that is not derived from the seed and that a rotation never touches. The procedure
is a rolling restart of sidecars alone, in [security.md](security.md#rotating-the-seed).

## What does the overlay actually buy me?

Architecture.md §2 is the reasoning. This is the part of it an operator can measure, in the order
of how quickly each one answers. [rollout.md](rollout.md) is how to set up the comparison that
makes any of it readable.

**Wrong-head votes on other proposers' late blocks.** Timely head is 14 of the 64 attestation
reward weight and is lost whenever a block is not imported by four seconds. Blocks that reach any
fleet host in time now reach all of them in time, so head vote correctness is where the effect
shows up first. Read it from your validator monitor or from the attestation records on chain,
canary against control, over a day or two.

**Missed attestations from local peering trouble.** A host that loses its public peers still
receives blocks over the overlay, so a peering problem stops costing attestations. This shows up
as the disappearance of a failure mode rather than as a number going up, which means you need the
before: how many attestation misses in the last months traced back to peering.

**Own proposals under timing games.** A proposal now enters the public network from every host in
the fleet at once rather than from one node's mesh peers. What you can measure is the attestation
share your own blocks receive against the delay you published them at, block by block, and from
that the orphan curve. It needs weeks, because it is counted per proposal, and it is the input to
choosing a publish delay rather than a number that improves on its own.

**Sync committee participation.** Late-head misses get the same arrival improvement as
attestations and are paid in full rather than at 14 of 64. Expect little at period boundaries: a
fleet already running `--subscribe-all-subnets` is a large share of every sync subnet's
subscribers, so its messages already reach its own aggregators quickly.

**Not covered.** Import time after arrival is dominated by the execution layer's `newPayload` and
by column verification, and the overlay does not change it. It is measured, not improved: every
100 ms of import cancels 100 ms of the arrival gain on a late block.
