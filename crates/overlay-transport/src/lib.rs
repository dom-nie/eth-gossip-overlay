//! QUIC transport between sidecars.

pub mod endpoint;
pub mod manager;
pub mod tls;

/// A live overlay on loopback, for this crate's tests and for the crates that drive one of
/// their own. Behind a feature because it is test-only code that other crates' tests link.
// A harness reports a broken fixture by panicking, which is what its unwraps are.
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(any(test, feature = "test-util"))]
pub mod testutil;

#[cfg(test)]
mod tests {
    #[test]
    fn crate_compiles() {}
}
