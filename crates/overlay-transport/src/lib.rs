//! QUIC transport between sidecars.

pub mod endpoint;
pub mod manager;
pub mod tls;

#[cfg(test)]
mod tests {
    #[test]
    fn crate_compiles() {}
}
