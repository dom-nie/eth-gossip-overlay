//! QUIC transport between sidecars.

pub mod batching;
pub mod busy_poll;
pub mod endpoint;
pub mod fanout;
pub mod hello;
pub mod io_thread;
pub mod manager;
pub mod receive;
pub mod repair;
pub mod router;
pub mod sender;
pub mod steering;
pub mod subs;
pub mod timestamping;
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
