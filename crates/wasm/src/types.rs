use std::{collections::HashMap, ops::Range};

use http_body_util::Full;
use hyper::body::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tsify_next::Tsify;
use wasm_bindgen::prelude::*;

#[derive(Debug, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
#[serde(untagged)]
#[non_exhaustive]
pub enum Body {
    Json(JsonValue),
}

#[derive(Debug, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
pub enum Method {
    GET,
    POST,
    PUT,
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

#[derive(Debug, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct HttpRequest {
    pub uri: String,
    pub method: Method,
    pub headers: HashMap<String, Vec<u8>>,
    pub body: Option<Body>,
}

impl TryFrom<HttpRequest> for hyper::Request<Full<Bytes>> {
    type Error = JsError;

    fn try_from(value: HttpRequest) -> Result<Self, Self::Error> {
        let mut builder = hyper::Request::builder();
        builder = builder.uri(value.uri).method(value.method);
        for (name, value) in value.headers {
            builder = builder.header(name, value);
        }

        if let Some(body) = value.body {
            let body = match body {
                Body::Json(value) => Full::new(Bytes::from(serde_json::to_vec(&value).unwrap())),
            };
            builder.body(body).map_err(Into::into)
        } else {
            builder.body(Full::new(Bytes::new())).map_err(Into::into)
        }
    }
}

#[derive(Debug, Tsify, Serialize)]
#[tsify(into_wasm_abi)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, Vec<u8>)>,
}

#[derive(Debug, Tsify, Serialize)]
#[tsify(into_wasm_abi)]
pub enum TlsVersion {
    V1_2,
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

#[derive(Debug, Tsify, Serialize)]
#[tsify(into_wasm_abi)]
pub struct TranscriptLength {
    pub sent: usize,
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

#[derive(Debug, Tsify, Serialize)]
#[tsify(into_wasm_abi)]
pub struct ConnectionInfo {
    time: u64,
    version: TlsVersion,
    transcript_length: TranscriptLength,
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

#[derive(Debug, Tsify, Serialize)]
#[tsify(into_wasm_abi)]
pub struct Transcript {
    pub sent: Vec<u8>,
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

#[derive(Debug, Tsify, Serialize)]
#[tsify(into_wasm_abi)]
pub struct PartialTranscript {
    pub sent: Vec<u8>,
    pub sent_authed: Vec<Range<usize>>,
    pub recv: Vec<u8>,
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

#[derive(Debug, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct Commit {
    pub sent: Vec<Range<usize>>,
    pub recv: Vec<Range<usize>>,
}

#[derive(Debug, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct Reveal {
    pub sent: Vec<Range<usize>>,
    pub recv: Vec<Range<usize>>,
    pub server_identity: bool,
}

#[derive(Debug, Tsify, Serialize)]
#[tsify(into_wasm_abi)]
pub struct VerifierOutput {
    pub server_name: Option<String>,
    pub connection_info: ConnectionInfo,
    pub transcript: Option<PartialTranscript>,
}

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
