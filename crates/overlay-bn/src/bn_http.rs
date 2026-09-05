//! One-shot calls to the local beacon node's HTTP API: its peer id before every dial, and on
//! every connect its version, whether it lists the sidecar as trusted, and the spec constants
//! the sidecar sizes itself by. One attempt per call and a short timeout; the BN link retries
//! with backoff, so a beacon node that is down or still starting costs a clear error and
//! nothing else here.

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use libp2p::identity::{Keypair, ed25519};
    use serde_json::json;
    use url::Url;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    fn client(server: &MockServer) -> BnClient {
        client_at(&format!("{}/eth/v1/node/identity", server.uri()))
    }

    fn client_at(identity_url: &str) -> BnClient {
        BnClient::new(Url::parse(identity_url).unwrap(), Duration::from_secs(2))
    }

    /// A peer id that is valid and stable across runs, without a literal to keep in sync.
    fn peer_id(seed: u8) -> PeerId {
        let secret = ed25519::SecretKey::try_from_bytes([seed; 32]).unwrap();
        Keypair::from(ed25519::Keypair::from(secret))
            .public()
            .to_peer_id()
    }

    async fn serve(server: &MockServer, at: &str, body: serde_json::Value) {
        Mock::given(method("GET"))
            .and(path(at))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn returns_peer_id_from_well_formed_response() {
        let server = MockServer::start().await;
        let own = peer_id(1);
        serve(
            &server,
            "/eth/v1/node/identity",
            json!({"data": {
                "peer_id": own.to_string(),
                "enr": "enr:-Ku4QHqVeJ8PPICcWk1vSn_XcSkjOkNiTg6Fmii5j6vUQgvzMc9L1goFnLKgXqBJspJjIsbFXUn4",
                "p2p_addresses": ["/ip4/127.0.0.1/tcp/9000"],
                "discovery_addresses": ["/ip4/127.0.0.1/udp/9000"],
                "metadata": {"seq_number": "1", "attnets": "0x0000000000000000"}
            }}),
        )
        .await;

        let got = client(&server).peer_id().await.unwrap();

        assert_eq!(got, own);
    }
}
