//! The spec constants the sidecar sizes itself by, as the beacon node reports them. Consumers
//! read a `watch` that starts at mainnet, so nothing waits on the beacon node; the BN link
//! replaces the value on every connect.
