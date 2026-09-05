//! The link between a sidecar and its local beacon node.

pub mod bn_http;
pub mod gossip;
pub mod inbound;
pub mod link;
pub mod mirror;
pub mod node_key;
pub mod publish;
pub mod spec;
#[cfg(test)]
mod testutil;

#[cfg(test)]
mod tests {
    #[test]
    fn crate_compiles() {}
}
