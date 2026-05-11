//! Shared types for the SDK.

use std::{collections::HashMap, ops::Range};

use http_body_util::Full;
use hyper::body::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::error::{Result, SdkError};

/// HTTP request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum Body {
    /// JSON body.
    Json(JsonValue),
    /// Raw bytes body.
    Raw(Vec<u8>),
}

/// HTTP method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

impl From<Method> for hyper::Method {
    fn from(value: Method) -> Self {
        match value {
            Method::GET => hyper::Method::GET,
            Method::POST => hyper::Method::POST,
            Method::PUT => hyper::Method::PUT,
            Method::DELETE => hyper::Method::DELETE,
        }
    }
}

/// HTTP request.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl HttpRequest {
    /// Creates a new HTTP request.
    pub fn new(method: Method, uri: impl Into<String>) -> Self {
        Self {
            uri: uri.into(),
            method,
            headers: HashMap::new(),
            body: None,
        }
    }

    /// Creates a new GET request.
    pub fn get(uri: impl Into<String>) -> Self {
        Self::new(Method::GET, uri)
    }

    /// Creates a new POST request.
    pub fn post(uri: impl Into<String>) -> Self {
        Self::new(Method::POST, uri)
    }

    /// Adds a header to the request.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<Vec<u8>>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    /// Sets the request body.
    pub fn body(mut self, body: Body) -> Self {
        self.body = Some(body);
        self
    }

    /// Sets a JSON body.
    pub fn json(self, value: impl Serialize) -> Result<Self> {
        let value = serde_json::to_value(value)
            .map_err(|e| SdkError::http(format!("failed to serialize JSON body: {e}")))?;
        Ok(self.body(Body::Json(value)))
    }
}

impl TryFrom<HttpRequest> for hyper::Request<Full<Bytes>> {
    type Error = SdkError;

    fn try_from(value: HttpRequest) -> Result<Self> {
        let mut builder = hyper::Request::builder();
        builder = builder.uri(value.uri).method(value.method);
        for (name, value) in value.headers {
            builder = builder.header(name, value);
        }

        if let Some(body) = value.body {
            let body = match body {
                // If the JSON value is a plain string, use its contents directly
                // to avoid double-serialization (wrapping in extra quotes).
                Body::Json(serde_json::Value::String(s)) => Full::new(Bytes::from(s)),
                // For other JSON values, serialize to bytes (infallible).
                Body::Json(value) => Full::new(Bytes::from(
                    serde_json::to_vec(&value).expect("Value serialization is infallible"),
                )),
                Body::Raw(bytes) => Full::new(Bytes::from(bytes)),
            };
            builder.body(body).map_err(SdkError::from)
        } else {
            builder
                .body(Full::new(Bytes::new()))
                .map_err(SdkError::from)
        }
    }
}

/// HTTP response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response headers.
    pub headers: Vec<(String, Vec<u8>)>,
    /// Response body (if available).
    pub body: Option<Vec<u8>>,
}

/// TLS version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsVersion {
    /// TLS 1.2.
    V1_2,
    /// TLS 1.3.
    V1_3,
}

impl From<tlsn::connection::TlsVersion> for TlsVersion {
    fn from(value: tlsn::connection::TlsVersion) -> Self {
        match value {
            tlsn::connection::TlsVersion::V1_2 => Self::V1_2,
            tlsn::connection::TlsVersion::V1_3 => Self::V1_3,
        }
    }
}

/// Transcript length information.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TranscriptLength {
    /// Bytes sent.
    pub sent: usize,
    /// Bytes received.
    pub recv: usize,
}

impl From<tlsn::connection::TranscriptLength> for TranscriptLength {
    fn from(value: tlsn::connection::TranscriptLength) -> Self {
        Self {
            sent: value.sent as usize,
            recv: value.received as usize,
        }
    }
}

/// Connection information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    /// Unix timestamp of the connection.
    pub time: u64,
    /// TLS version used.
    pub version: TlsVersion,
    /// Transcript length information.
    pub transcript_length: TranscriptLength,
}

impl From<tlsn::connection::ConnectionInfo> for ConnectionInfo {
    fn from(value: tlsn::connection::ConnectionInfo) -> Self {
        Self {
            time: value.time,
            version: value.version.into(),
            transcript_length: value.transcript_length.into(),
        }
    }
}

/// Full transcript of sent and received data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transcript {
    /// Data sent to the server.
    pub sent: Vec<u8>,
    /// Data received from the server.
    pub recv: Vec<u8>,
}

impl From<&tlsn::transcript::Transcript> for Transcript {
    fn from(value: &tlsn::transcript::Transcript) -> Self {
        Self {
            sent: value.sent().to_vec(),
            recv: value.received().to_vec(),
        }
    }
}

/// Partial transcript with authenticated ranges.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl From<tlsn::transcript::PartialTranscript> for PartialTranscript {
    fn from(value: tlsn::transcript::PartialTranscript) -> Self {
        Self {
            sent: value.sent_unsafe().to_vec(),
            sent_authed: value.sent_authed().iter().collect(),
            recv: value.received_unsafe().to_vec(),
            recv_authed: value.received_authed().iter().collect(),
        }
    }
}

/// A byte range paired with a hash algorithm for commitment.
///
/// Uses flat `start`/`end` fields so the JS wire format matches the wasm
/// crate's `CommitRange` without conversion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitRange {
    /// Start of the byte range (inclusive).
    pub start: usize,
    /// End of the byte range (exclusive).
    pub end: usize,
    /// Hash algorithm to use for this range.
    pub algorithm: HashAlgorithm,
}

impl CommitRange {
    /// Returns the byte range as a [`Range<usize>`].
    pub fn range(&self) -> Range<usize> {
        self.start..self.end
    }
}

/// Ranges of data to hash-commit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Commit {
    /// Ranges of sent data to commit, each with its own algorithm.
    pub sent: Vec<CommitRange>,
    /// Ranges of received data to commit, each with its own algorithm.
    pub recv: Vec<CommitRange>,
}

/// Ranges of data to reveal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reveal {
    /// Ranges of sent data to reveal.
    pub sent: Vec<Range<usize>>,
    /// Ranges of received data to reveal.
    pub recv: Vec<Range<usize>>,
    /// Whether to reveal the server identity.
    pub server_identity: bool,
}

impl Reveal {
    /// Creates a new Reveal with empty ranges.
    pub fn new() -> Self {
        Self {
            sent: Vec::new(),
            recv: Vec::new(),
            server_identity: false,
        }
    }

    /// Adds a range of sent data to reveal.
    pub fn sent(mut self, range: Range<usize>) -> Self {
        self.sent.push(range);
        self
    }

    /// Adds a range of received data to reveal.
    pub fn recv(mut self, range: Range<usize>) -> Self {
        self.recv.push(range);
        self
    }

    /// Sets whether to reveal the server identity.
    pub fn server_identity(mut self, reveal: bool) -> Self {
        self.server_identity = reveal;
        self
    }
}

impl Default for Reveal {
    fn default() -> Self {
        Self::new()
    }
}

/// Handler direction: sent (request) or received (response) data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HandlerType {
    /// Sent data (HTTP request).
    Sent,
    /// Received data (HTTP response).
    Recv,
}

/// Which part of the HTTP message a handler targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HandlerPart {
    /// The entire start line (request line or status line).
    StartLine,
    /// The HTTP protocol/version portion of the start line.
    Protocol,
    /// The HTTP method (GET, POST, etc.) — requests only.
    Method,
    /// The request target (path) — requests only.
    RequestTarget,
    /// The status code — responses only.
    StatusCode,
    /// HTTP headers.
    Headers,
    /// The message body.
    Body,
    /// The entire message.
    All,
}

/// Hash algorithm for hash-commitment actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HashAlgorithm {
    /// BLAKE3 hash algorithm.
    Blake3,
    /// SHA-256 hash algorithm.
    Sha256,
    /// Keccak-256 hash algorithm.
    Keccak256,
}

impl From<HashAlgorithm> for tlsn_core::hash::HashAlgId {
    fn from(alg: HashAlgorithm) -> Self {
        match alg {
            HashAlgorithm::Blake3 => tlsn_core::hash::HashAlgId::BLAKE3,
            HashAlgorithm::Sha256 => tlsn_core::hash::HashAlgId::SHA256,
            HashAlgorithm::Keccak256 => tlsn_core::hash::HashAlgId::KECCAK256,
        }
    }
}

/// Opening for a single hash-committed range.
///
/// Pairs the commitment hash digest with the blinder used to produce it, so
/// the holder can later prove `H(plaintext || blinder) == hash` to a third
/// party without re-running the MPC-TLS protocol. The committed range and
/// algorithm come from the input [`CommitRange`] at the same index.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashOpening {
    /// The commitment hash digest.
    pub hash: Vec<u8>,
    /// The blinder (16 bytes) used to compute the commitment.
    pub blinder: Vec<u8>,
}

/// Output of [`SdkProver::reveal`].
///
/// Mirrors the shape of the input [`Commit`]: `sent[i]` opens `commit.sent[i]`
/// and likewise for `recv`. Both vectors are empty when no commit was
/// supplied.
///
/// [`SdkProver::reveal`]: crate::prover::SdkProver::reveal
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RevealOutput {
    /// Openings for `commit.sent`, in input order.
    pub sent: Vec<HashOpening>,
    /// Openings for `commit.recv`, in input order.
    pub recv: Vec<HashOpening>,
}

/// What action to take with the matched ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "UPPERCASE")]
pub enum HandlerAction {
    /// Reveal the data in plaintext.
    Reveal,
    /// Hash-commit to the data (blinded, never revealed as plaintext).
    Hash {
        /// Hash algorithm.
        algorithm: HashAlgorithm,
    },
}

/// Optional parameters for a handler.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HandlerParams {
    /// Header name to target (for `Headers` part).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// If true, hide the header/JSON key (reveal only the value).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hide_key: Option<bool>,
    /// If true, hide the header/JSON value (reveal only the key).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hide_value: Option<bool>,
    /// Content type: `"json"` for JSON body, `"regex"` for regex matching.
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// JSON dot-notation path (for `Body` part with `type: "json"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Regex pattern (for `All` part with `type: "regex"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regex: Option<String>,
    /// Regex flags (for `All` part with `type: "regex"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<String>,
}

/// A handler that specifies what data to extract from an HTTP transcript.
///
/// Handlers are used by plugins to control selective disclosure in TLS proofs.
/// Each handler targets a specific part of the HTTP message and specifies
/// whether to reveal or hash-commit the data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Handler {
    /// Direction: sent (request) or received (response).
    #[serde(rename = "type")]
    pub handler_type: HandlerType,
    /// Which part of the HTTP message to target.
    pub part: HandlerPart,
    /// What action to take (reveal plaintext or hash-commit). Serialized as a
    /// nested object with a `kind` discriminant so that action-specific fields
    /// (e.g. `algorithm` for hash) are namespaced under `action` rather than
    /// scattered across the handler.
    pub action: HandlerAction,
    /// Optional parameters for fine-grained control.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<HandlerParams>,
}

/// Output from the verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierOutput {
    /// Server name (if revealed).
    pub server_name: Option<String>,
    /// Connection information.
    pub connection_info: ConnectionInfo,
    /// Partial transcript (if revealed).
    pub transcript: Option<PartialTranscript>,
}
