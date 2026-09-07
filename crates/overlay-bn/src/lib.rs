//! The link between a sidecar and its local beacon node.

pub mod bn_http;
pub mod compat;
#[cfg(test)]
mod conformance;
pub mod gossip;
pub mod inbound;
pub mod link;
pub mod mirror;
pub mod node_key;
pub mod publish;
pub mod rpc;
pub mod spec;
// A fixture reports itself broken by panicking, which is what its unwraps are.
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(any(test, feature = "test-util"))]
pub mod testutil;

#[cfg(test)]
mod tests {
    #[test]
    fn crate_compiles() {}
}
