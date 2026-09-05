# Security policy

## Reporting a vulnerability

Report it privately through GitHub's vulnerability reporting for this repository: https://github.com/dom-nie/eth-bn-gossip-overlay/security/advisories/new. Never open a public issue for a security problem; people run this binary next to validators.

The maintainers acknowledge a report within 3 days and triage it within 7. A confirmed high-severity issue gets a fix or a mitigation within 30 days.

## Supported versions

There is no release yet. Until the first tag, `main` is the only supported version and fixes land there.

## Threat model

Every connection on the overlay port is a TLS handshake against a peer key derived from the fleet seed, so an outsider, or a neighbour on the same network, cannot join even when a firewall rule is wrong. Pinning says nothing about what a host that is already on the overlay sends: a compromised sidecar can inject junk into the beacon nodes, bounded by the per-node rate limit and the fleet-wide fan-out budget, and the cost is CPU. The sidecar holds no validator keys, creates no messages and cannot forge or alter one, because every message carries its BLS signature and the receiving beacon node validates it like any other gossip. The fleet seed is the one secret: whoever holds it can impersonate any host on the overlay until the seed is rotated on every host. The roster is internal because it lists every host's address and region, which is the fleet's topology.
