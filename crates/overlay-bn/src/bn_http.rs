//! One-shot calls to the local beacon node's HTTP API: its peer id before every dial, the
//! sidecar's ENR handed over with it, and on every connect the beacon node's version, whether
//! it lists the sidecar as trusted, and the spec constants the sidecar sizes itself by. One
//! attempt per call and a short timeout; the BN link retries with backoff, so a beacon node
//! that is down or still starting costs a clear error and nothing else here.
//!
//! Checked against Lighthouse v8.2.2: `/eth/v1/node/identity` and `/eth/v1/node/version` wrap
//! their payload as `{"data": ...}` (`GenericResponse` in `common/eth2/src/types.rs`), where
//! `IdentityData` carries `peer_id` as a string and `VersionData` carries `version` as the
//! string `version_with_platform()` builds in the `node/version` handler of
//! `beacon_node/http_api/src/lib.rs`. `/lighthouse/peers` is not wrapped: its handler in the
//! same file returns a bare array of `peer::Peer { peer_id, peer_info }`
//! (`beacon_node/http_api/src/peer.rs`), and `is_trusted` is a plain `bool` field of
//! `PeerInfo` in `beacon_node/lighthouse_network/src/peer_manager/peerdb/peer_info.rs`.
//! `/eth/v1/config/spec` wraps a `ConfigAndPreset`
//! (`consensus/types/src/core/config_and_preset.rs`): `UPPERCASE` keys with numbers as
//! quoted decimal strings, plus `BLOB_SCHEDULE`, which is an array. A map of strings would
//! choke on that array, which is why the snapshot is a struct that names its keys and
//! ignores the rest. `POST /lighthouse/add_peer` takes `api_types::AdminPeer`, one `enr`
//! string, and answers an empty 200.

use std::time::Duration;

use libp2p::PeerId;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::spec::{SpecSnapshot, SpecWire};

const IDENTITY: &str = "/eth/v1/node/identity";
const VERSION: &str = "/eth/v1/node/version";
const PEERS: &str = "/lighthouse/peers";
const SPEC: &str = "/eth/v1/config/spec";
const ADD_PEER: &str = "/lighthouse/add_peer";

/// The client. One connection pool shared by every call, built once at startup.
#[derive(Clone, Debug)]
pub struct BnClient {
    http: reqwest::Client,
    identity: Url,
    version: Url,
    peers: Url,
    spec: Url,
    add_peer: Url,
}

/// What the beacon node knows about one of its peers, cut down to what the sidecar acts on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
pub struct PeerInfo {
    /// Whether the peer is in the BN's `--trusted-peers`; how the sidecar learns that the
    /// operator's flag took effect.
    pub is_trusted: bool,
}

/// Why a call to the beacon node failed. Every message names the endpoint, because the four
/// calls fail for different reasons and the BN link logs them from one place.
#[derive(Debug, thiserror::Error)]
pub enum BnHttpError {
    /// No HTTP response came back: the BN is down, still starting or not where the config says.
    #[error("{endpoint}: {}", root_cause(.source))]
    Connect {
        /// The path that was requested.
        endpoint: &'static str,
        /// What the HTTP client said.
        source: reqwest::Error,
    },
    /// No complete response within the client's timeout. On localhost that is a beacon node
    /// that is wedged, not one that is slow.
    #[error("{endpoint}: {}", root_cause(.source))]
    Timeout {
        /// The path that was requested.
        endpoint: &'static str,
        /// What the HTTP client said.
        source: reqwest::Error,
    },
    /// The BN answered outside 2xx. A 404 on `/lighthouse/peers` or `/lighthouse/add_peer`
    /// means a BN that is not Lighthouse or has the endpoint off, which the caller reports
    /// differently from an empty peer list or a registration the BN rejected.
    #[error("beacon node answered HTTP {0}")]
    Status(u16),
    /// The body was not the JSON the sidecar expects.
    #[error("{endpoint}: {}", root_cause(.source))]
    Body {
        /// The path that was requested.
        endpoint: &'static str,
        /// What the HTTP client said.
        source: reqwest::Error,
    },
    /// The identity's `peer_id` is not a peer id.
    #[error("{IDENTITY}: {0:?} is not a peer id")]
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

/// `api_types::AdminPeer`, the body `POST /lighthouse/add_peer` takes.
#[derive(Serialize)]
struct AdminPeer<'a> {
    enr: &'a str,
}

#[derive(Deserialize)]
struct Identity {
    peer_id: String,
}

#[derive(Deserialize)]
struct Version {
    version: String,
}

#[derive(Deserialize)]
struct Peer {
    peer_id: String,
    peer_info: PeerInfo,
}

/// The identity URL with its path swapped: the other endpoints share its scheme, host and
/// port, so there is one `bn.identity_url` key and no origin to keep in sync with it.
fn sibling(identity: &Url, path: &str) -> Url {
    let mut url = identity.clone();
    url.set_path(path);
    url
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
            version: sibling(&identity_url, VERSION),
            peers: sibling(&identity_url, PEERS),
            spec: sibling(&identity_url, SPEC),
            add_peer: sibling(&identity_url, ADD_PEER),
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

    /// The beacon node's version string, verbatim. T-018 decides what it means.
    pub async fn version(&self) -> Result<String, BnHttpError> {
        let Data {
            data: Version { version },
        } = self.get(&self.version, VERSION).await?;
        Ok(version)
    }

    /// What the beacon node reports about the sidecar itself, or `None` when it does not list
    /// `own` at all. Other rows are matched by text and never parsed.
    pub async fn peer_info(&self, own: &PeerId) -> Result<Option<PeerInfo>, BnHttpError> {
        let own = own.to_string();
        let peers: Vec<Peer> = self.get(&self.peers, PEERS).await?;
        Ok(peers
            .into_iter()
            .find(|peer| peer.peer_id == own)
            .map(|peer| peer.peer_info))
    }

    /// Hands the beacon node `enr` so its peer manager trusts that peer id and dials it, at
    /// once and on every heartbeat while it is disconnected. This is what gets the sidecar in
    /// when the beacon node's inbound cap is full (MD-01).
    pub async fn add_peer(&self, enr: &str) -> Result<(), BnHttpError> {
        let response = self
            .http
            .post(self.add_peer.clone())
            .json(&AdminPeer { enr })
            .send()
            .await
            .map_err(|err| map(err, ADD_PEER))?;
        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            Err(BnHttpError::Status(status.as_u16()))
        }
    }

    /// The spec constants as the beacon node runs them.
    pub async fn spec(&self) -> Result<SpecSnapshot, BnHttpError> {
        let Data { data } = self.get::<Data<SpecWire>>(&self.spec, SPEC).await?;
        Ok(data.into())
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
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;
    use crate::spec::SpecSnapshot;

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

    fn peer_row(id: &PeerId, is_trusted: bool) -> serde_json::Value {
        json!({
            "peer_id": id.to_string(),
            "peer_info": {
                "score": {"score": 0.0},
                "client": {"kind": "Lighthouse", "version": "v8.2.2"},
                "connection_status": {"status": "connected", "connections_in": 1},
                "is_trusted": is_trusted,
                "sync_status": "Synced"
            }
        })
    }

    #[tokio::test]
    async fn peer_info_finds_own_peer_id_and_reads_is_trusted() {
        let (own, other) = (peer_id(1), peer_id(2));
        for trusted in [true, false] {
            let server = MockServer::start().await;
            serve(
                &server,
                "/lighthouse/peers",
                json!([peer_row(&other, !trusted), peer_row(&own, trusted)]),
            )
            .await;

            let got = client(&server).peer_info(&own).await.unwrap();

            assert_eq!(
                got,
                Some(PeerInfo {
                    is_trusted: trusted
                })
            );
        }
    }

    #[tokio::test]
    async fn peer_info_is_none_when_own_peer_id_not_listed() {
        let (own, other) = (peer_id(1), peer_id(2));
        let server = MockServer::start().await;
        serve(
            &server,
            "/lighthouse/peers",
            json!([peer_row(&other, true)]),
        )
        .await;

        let got = client(&server).peer_info(&own).await.unwrap();

        assert_eq!(got, None);
    }

    #[tokio::test]
    async fn peer_info_404_is_status_error_not_none() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/lighthouse/peers"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let err = client(&server).peer_info(&peer_id(1)).await.unwrap_err();

        assert!(matches!(err, BnHttpError::Status(404)), "{err:?}");
    }

    /// Every key the sidecar reads, with values a mainnet BN would never send, among the
    /// clutter a real spec carries: a hundred keys nobody reads and v8's `BLOB_SCHEDULE`, the
    /// one value that is not a string.
    fn spec_data() -> serde_json::Value {
        let mut data = json!({
            "DATA_COLUMN_SIDECAR_SUBNET_COUNT": "64",
            "NUMBER_OF_COLUMNS": "64",
            "NUMBER_OF_CUSTODY_GROUPS": "32",
            "CUSTODY_REQUIREMENT": "2",
            "MAX_PAYLOAD_SIZE": "1048576",
            "SECONDS_PER_SLOT": "6",
            "SLOTS_PER_EPOCH": "8",
            "BLOB_SCHEDULE": [{"EPOCH": "412608", "MAX_BLOBS_PER_BLOCK": "15"}]
        });
        for n in 0..100 {
            data[format!("UNRELATED_{n}")] = json!(n.to_string());
        }
        data
    }

    const MOCKED: SpecSnapshot = SpecSnapshot {
        data_column_sidecar_subnet_count: 64,
        number_of_columns: 64,
        number_of_custody_groups: 32,
        custody_requirement: 2,
        max_payload_size: 1_048_576,
        seconds_per_slot: 6,
        slots_per_epoch: 8,
    };

    #[tokio::test]
    async fn spec_parses_decimal_strings_into_snapshot() {
        let server = MockServer::start().await;
        serve(&server, "/eth/v1/config/spec", json!({"data": spec_data()})).await;

        let got = client(&server).spec().await.unwrap();

        assert_eq!(got, MOCKED);
    }

    #[tokio::test]
    async fn spec_missing_key_keeps_compiled_default() {
        let server = MockServer::start().await;
        let mut data = spec_data();
        data.as_object_mut()
            .unwrap()
            .remove("NUMBER_OF_CUSTODY_GROUPS");
        serve(&server, "/eth/v1/config/spec", json!({"data": data})).await;

        let got = client(&server).spec().await.unwrap();

        assert_eq!(
            got,
            SpecSnapshot {
                number_of_custody_groups: crate::spec::MAINNET.number_of_custody_groups,
                ..MOCKED
            }
        );
    }

    #[tokio::test]
    async fn spec_non_numeric_value_is_body_error() {
        let server = MockServer::start().await;
        let mut data = spec_data();
        data["SECONDS_PER_SLOT"] = json!("twelve");
        serve(&server, "/eth/v1/config/spec", json!({"data": data})).await;

        let err = client(&server).spec().await.unwrap_err();

        assert!(matches!(err, BnHttpError::Body { .. }), "{err:?}");
        assert!(err.to_string().contains("twelve"), "{err}");
    }

    /// Lighthouse's handler (`beacon_node/http_api/src/lib.rs`, POST lighthouse/add_peer)
    /// takes `api_types::AdminPeer`, a single `enr` string, and answers 404 on a beacon node
    /// that is not Lighthouse or has the endpoint off.
    #[tokio::test]
    async fn add_peer_posts_the_enr_and_maps_404_to_status() {
        let text =
            "enr:-Ku4QHqVeJ8PPICcWk1vSn_XcSkjOkNiTg6Fmii5j6vUQgvzMc9L1goFnLKgXqBJspJjIsbFXUn4";
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/lighthouse/add_peer"))
            .and(body_json(json!({"enr": text})))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let gone = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/lighthouse/add_peer"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&gone)
            .await;

        client(&server).add_peer(text).await.unwrap();
        let err = client(&gone).add_peer(text).await.unwrap_err();

        server.verify().await;
        assert!(matches!(err, BnHttpError::Status(404)), "{err:?}");
    }

    #[tokio::test]
    async fn all_endpoints_use_the_identity_urls_origin() {
        let server = MockServer::start().await;
        let own = peer_id(1);
        for (at, body) in [
            (
                "/eth/v1/node/identity",
                json!({"data": {"peer_id": own.to_string()}}),
            ),
            (
                "/eth/v1/node/version",
                json!({"data": {"version": "Lighthouse/v8.2.2"}}),
            ),
            ("/lighthouse/peers", json!([peer_row(&own, true)])),
            ("/eth/v1/config/spec", json!({"data": spec_data()})),
        ] {
            Mock::given(method("GET"))
                .and(path(at))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .expect(1)
                .mount(&server)
                .await;
        }
        let client = client_at(&format!("{}/eth/v1/node/identity", server.uri()));

        client.peer_id().await.unwrap();
        client.version().await.unwrap();
        client.peer_info(&own).await.unwrap();
        client.spec().await.unwrap();

        server.verify().await;
    }
}
