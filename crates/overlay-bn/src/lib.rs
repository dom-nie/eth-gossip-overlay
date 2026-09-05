//! The link between a sidecar and its local beacon node.

pub mod bn_http;
pub mod node_key;
pub mod spec;

#[cfg(test)]
mod tests {
    #[test]
    fn crate_compiles() {}
}
