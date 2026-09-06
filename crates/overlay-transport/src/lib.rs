//! QUIC transport between sidecars.

pub mod endpoint;
pub mod hello;
pub mod manager;
pub mod subs;
pub mod tls;

// A harness reports a broken fixture by panicking, which is what its unwraps are.
#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(any(test, feature = "test-util"))]
pub mod testutil;

#[cfg(test)]
mod testlog;

#[cfg(test)]
mod tests {
    #[test]
    fn crate_compiles() {}
}
