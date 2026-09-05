//! One-shot calls to the local beacon node's HTTP API: its peer id before every dial, and on
//! every connect its version, whether it lists the sidecar as trusted, and the spec constants
//! the sidecar sizes itself by. One attempt per call and a short timeout; the BN link retries
//! with backoff, so a beacon node that is down or still starting costs a clear error and
//! nothing else here.
//!
//! Checked against Lighthouse v8.2.2: `/eth/v1/node/identity` wraps its payload as
//! `{"data": ...}` (`GenericResponse` in `common/eth2/src/types.rs`), where `IdentityData`
//! carries `peer_id` as a string.

use std::time::Duration;

use libp2p::PeerId;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use url::Url;

const IDENTITY: &str = "/eth/v1/node/identity";

/// The client. One connection pool shared by every call, built once at startup.
#[derive(Clone, Debug)]
pub struct BnClient {
    http: reqwest::Client,
    identity: Url,
}

/// Why a call to the beacon node failed. Every message names the endpoint, because the four
/// calls fail for different reasons and the BN link logs them from one place.
#[derive(Debug, thiserror::Error)]
pub enum BnHttpError {
    /// No HTTP response came back: the BN is down, still starting or not where the config says.
    #[error("GET {endpoint}: {}", root_cause(.source))]
    Connect {
        /// The path that was requested.
        endpoint: &'static str,
        /// What the HTTP client said.
        source: reqwest::Error,
    },
    /// No complete response within the client's timeout. On localhost that is a beacon node
    /// that is wedged, not one that is slow.
    #[error("GET {endpoint}: {}", root_cause(.source))]
    Timeout {
        /// The path that was requested.
        endpoint: &'static str,
        /// What the HTTP client said.
        source: reqwest::Error,
    },
    /// The BN answered outside 2xx. A 404 on `/lighthouse/peers` means a BN that is not
    /// Lighthouse or has the endpoint off, which the caller reports differently from an
    /// empty peer list.
    #[error("beacon node answered HTTP {0}")]
    Status(u16),
    /// The body was not the JSON the sidecar expects.
    #[error("GET {endpoint}: {}", root_cause(.source))]
    Body {
        /// The path that was requested.
        endpoint: &'static str,
        /// What the HTTP client said.
        source: reqwest::Error,
    },
    /// The identity's `peer_id` is not a peer id.
    #[error("GET {IDENTITY}: {0:?} is not a peer id")]
    InvalidPeerId(String),
}

/// The innermost error, which is the one an operator can act on: reqwest's own text only says
/// "error sending request".
fn root_cause(err: &reqwest::Error) -> String {
    let mut cause: &dyn std::error::Error = err;
    while let Some(next) = cause.source() {
        cause = next;
    }
    cause.to_string()
}

fn map(err: reqwest::Error, endpoint: &'static str) -> BnHttpError {
    if err.is_timeout() {
        BnHttpError::Timeout {
            endpoint,
            source: err,
        }
    } else if err.is_decode() {
        BnHttpError::Body {
            endpoint,
            source: err,
        }
    } else {
        BnHttpError::Connect {
            endpoint,
            source: err,
        }
    }
}

/// The `{"data": ...}` envelope the standard beacon API puts around every payload.
#[derive(Deserialize)]
struct Data<T> {
    data: T,
}

#[derive(Deserialize)]
struct Identity {
    peer_id: String,
}

impl BnClient {
    /// Builds the client for the beacon node at `identity_url`. Every call shares the same
    /// `timeout`, which bounds the whole request; on localhost a few seconds is generous.
    #[expect(
        clippy::expect_used,
        reason = "with no TLS backend compiled in, a client can only fail to build on proxy \
                  setup, and none is configured"
    )]
    pub fn new(identity_url: Url, timeout: Duration) -> Self {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .expect("plain HTTP client");
        Self {
            http,
            identity: identity_url,
        }
    }

    /// The beacon node's current peer id, read fresh because the operator may have
    /// regenerated its key since the last dial.
    pub async fn peer_id(&self) -> Result<PeerId, BnHttpError> {
        let Data {
            data: Identity { peer_id },
        } = self.get(&self.identity, IDENTITY).await?;
        peer_id
            .parse()
            .map_err(|_| BnHttpError::InvalidPeerId(peer_id))
    }

    async fn get<T: DeserializeOwned>(
        &self,
        url: &Url,
        endpoint: &'static str,
    ) -> Result<T, BnHttpError> {
        let response = self
            .http
            .get(url.clone())
            .send()
            .await
            .map_err(|err| map(err, endpoint))?;
        let status = response.status();
        if !status.is_success() {
            return Err(BnHttpError::Status(status.as_u16()));
        }
        response.json().await.map_err(|err| map(err, endpoint))
    }
}

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

    #[tokio::test]
    async fn ignores_unknown_fields() {
        let server = MockServer::start().await;
        let own = peer_id(1);
        serve(
            &server,
            "/eth/v1/node/identity",
            json!({
                "data": {"peer_id": own.to_string(), "added_in_a_later_release": {"x": [1, 2]}},
                "execution_optimistic": false
            }),
        )
        .await;

        let got = client(&server).peer_id().await.unwrap();

        assert_eq!(got, own);
    }

    #[tokio::test]
    async fn non_200_is_status_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/identity"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let err = client(&server).peer_id().await.unwrap_err();

        assert!(matches!(err, BnHttpError::Status(503)), "{err:?}");
    }

    #[tokio::test]
    async fn malformed_json_is_body_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/identity"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{\"data\": {\"peer_id\""))
            .mount(&server)
            .await;

        let err = client(&server).peer_id().await.unwrap_err();

        assert!(matches!(err, BnHttpError::Body { .. }), "{err:?}");
        assert!(err.to_string().contains("/eth/v1/node/identity"), "{err}");
    }

    #[tokio::test]
    async fn invalid_peer_id_string_is_invalid_peer_id_error() {
        let server = MockServer::start().await;
        serve(
            &server,
            "/eth/v1/node/identity",
            json!({"data": {"peer_id": "not-a-peer-id"}}),
        )
        .await;

        let err = client(&server).peer_id().await.unwrap_err();

        assert!(
            matches!(&err, BnHttpError::InvalidPeerId(text) if text == "not-a-peer-id"),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn connection_refused_is_connect_error() {
        let port = {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        };

        let err = client_at(&format!("http://127.0.0.1:{port}/eth/v1/node/identity"))
            .peer_id()
            .await
            .unwrap_err();

        assert!(matches!(err, BnHttpError::Connect { .. }), "{err:?}");
        assert!(err.to_string().contains("/eth/v1/node/identity"), "{err}");
    }

    #[tokio::test]
    async fn slow_server_times_out() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/identity"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(5)))
            .mount(&server)
            .await;
        let identity_url = format!("{}/eth/v1/node/identity", server.uri());
        let client = BnClient::new(
            Url::parse(&identity_url).unwrap(),
            Duration::from_millis(100),
        );
        let started = std::time::Instant::now();

        let err = client.peer_id().await.unwrap_err();

        assert!(matches!(err, BnHttpError::Timeout { .. }), "{err:?}");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn version_returns_the_data_version_string() {
        let server = MockServer::start().await;
        serve(
            &server,
            "/eth/v1/node/version",
            json!({"data": {"version": "Lighthouse/v8.2.2-e423a66/x86_64-linux"}}),
        )
        .await;

        let got = client(&server).version().await.unwrap();

        assert_eq!(got, "Lighthouse/v8.2.2-e423a66/x86_64-linux");
    }
}
