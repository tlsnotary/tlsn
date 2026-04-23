//! WASM type definitions with TypeScript bindings.

use std::{collections::HashMap, ops::Range};

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tsify_next::Tsify;

/// HTTP request body.
#[derive(Debug, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
#[serde(untagged)]
#[non_exhaustive]
pub enum Body {
    /// JSON body.
    Json(JsonValue),
}

/// HTTP method.
#[derive(Debug, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
pub enum Method {
    /// HTTP GET method.
    GET,
    /// HTTP POST method.
    POST,
    /// HTTP PUT method.
    PUT,
    /// HTTP DELETE method.
    DELETE,
}

/// HTTP request.
#[derive(Debug, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct HttpRequest {
    /// Request URI.
    pub uri: String,
    /// HTTP method.
    pub method: Method,
    /// Request headers.
    pub headers: HashMap<String, Vec<u8>>,
    /// Optional request body.
    pub body: Option<Body>,
}

/// HTTP response.
#[derive(Debug, Tsify, Serialize)]
#[tsify(into_wasm_abi)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers.
    pub headers: Vec<(String, Vec<u8>)>,
}

/// TLS version.
#[derive(Debug, Tsify, Serialize)]
#[tsify(into_wasm_abi)]
pub enum TlsVersion {
    /// TLS 1.2.
    V1_2,
    /// TLS 1.3.
    V1_3,
}

/// Transcript length information.
#[derive(Debug, Tsify, Serialize)]
#[tsify(into_wasm_abi)]
pub struct TranscriptLength {
    /// Bytes sent.
    pub sent: usize,
    /// Bytes received.
    pub recv: usize,
}

/// Connection information.
#[derive(Debug, Tsify, Serialize)]
#[tsify(into_wasm_abi)]
pub struct ConnectionInfo {
    /// Unix timestamp of the connection.
    pub time: u64,
    /// TLS version used.
    pub version: TlsVersion,
    /// Transcript length information.
    pub transcript_length: TranscriptLength,
}

/// Full transcript of sent and received data.
#[derive(Debug, Tsify, Serialize)]
#[tsify(into_wasm_abi)]
pub struct Transcript {
    /// Data sent to the server.
    pub sent: Vec<u8>,
    /// Data received from the server.
    pub recv: Vec<u8>,
}

/// Partial transcript with authenticated ranges.
#[derive(Debug, Tsify, Serialize)]
#[tsify(into_wasm_abi)]
pub struct PartialTranscript {
    /// Data sent to the server.
    pub sent: Vec<u8>,
    /// Authenticated ranges of sent data.
    pub sent_authed: Vec<Range<usize>>,
    /// Data received from the server.
    pub recv: Vec<u8>,
    /// Authenticated ranges of received data.
    pub recv_authed: Vec<Range<usize>>,
}

/// Ranges of data to commit.
#[derive(Debug, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct Commit {
    /// Ranges of sent data to commit.
    pub sent: Vec<Range<usize>>,
    /// Ranges of received data to commit.
    pub recv: Vec<Range<usize>>,
}

/// Ranges of data to reveal.
#[derive(Debug, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct Reveal {
    /// Ranges of sent data to reveal.
    pub sent: Vec<Range<usize>>,
    /// Ranges of received data to reveal.
    pub recv: Vec<Range<usize>>,
    /// Whether to reveal the server identity.
    pub server_identity: bool,
}

/// Output from the verifier.
#[derive(Debug, Tsify, Serialize)]
#[tsify(into_wasm_abi)]
pub struct VerifierOutput {
    /// Server name (if revealed).
    pub server_name: Option<String>,
    /// Connection information.
    pub connection_info: ConnectionInfo,
    /// Partial transcript (if revealed).
    pub transcript: Option<PartialTranscript>,
}

/// Network setting for protocol optimization.
#[derive(Debug, Clone, Copy, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
pub enum NetworkSetting {
    /// Prefers a bandwidth-heavy protocol.
    Bandwidth,
    /// Prefers a latency-heavy protocol.
    Latency,
}

impl From<NetworkSetting> for tlsn::config::tls_commit::mpc::NetworkSetting {
    fn from(value: NetworkSetting) -> Self {
        match value {
            NetworkSetting::Bandwidth => Self::Bandwidth,
            NetworkSetting::Latency => Self::Latency,
        }
    }
}
