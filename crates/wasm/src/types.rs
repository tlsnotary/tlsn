use std::{collections::HashMap, ops::Range};

use http_body_util::Full;
use hyper::body::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tlsn_core::CryptoProvider;
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

impl From<tlsn_core::connection::TlsVersion> for TlsVersion {
    fn from(value: tlsn_core::connection::TlsVersion) -> Self {
        match value {
            tlsn_core::connection::TlsVersion::V1_2 => Self::V1_2,
            tlsn_core::connection::TlsVersion::V1_3 => Self::V1_3,
        }
    }
}

#[derive(Debug, Tsify, Serialize)]
#[tsify(into_wasm_abi)]
pub struct TranscriptLength {
    pub sent: usize,
    pub recv: usize,
}

impl From<tlsn_core::connection::TranscriptLength> for TranscriptLength {
    fn from(value: tlsn_core::connection::TranscriptLength) -> Self {
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

impl From<tlsn_core::connection::ConnectionInfo> for ConnectionInfo {
    fn from(value: tlsn_core::connection::ConnectionInfo) -> Self {
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

impl From<&tlsn_core::transcript::Transcript> for Transcript {
    fn from(value: &tlsn_core::transcript::Transcript) -> Self {
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

impl From<tlsn_core::transcript::PartialTranscript> for PartialTranscript {
    fn from(value: tlsn_core::transcript::PartialTranscript) -> Self {
        Self {
            sent: value.sent_unsafe().to_vec(),
            sent_authed: value.sent_authed().iter_ranges().collect(),
            recv: value.received_unsafe().to_vec(),
            recv_authed: value.received_authed().iter_ranges().collect(),
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
}

#[derive(Debug, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
pub enum KeyType {
    P256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen]
#[serde(transparent)]
pub struct Attestation(pub(crate) tlsn_core::attestation::Attestation);

#[wasm_bindgen]
impl Attestation {
    pub fn verifying_key(&self) -> VerifyingKey {
        self.0.body.verifying_key().into()
    }

    /// Serializes to a byte array.
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Attestation should be serializable")
    }

    /// Deserializes from a byte array.
    pub fn deserialize(bytes: Vec<u8>) -> Result<Attestation, JsError> {
        Ok(bincode::deserialize(&bytes)?)
    }
}

impl From<tlsn_core::attestation::Attestation> for Attestation {
    fn from(value: tlsn_core::attestation::Attestation) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen]
#[serde(transparent)]
pub struct Secrets(pub(crate) tlsn_core::Secrets);

#[wasm_bindgen]
impl Secrets {
    /// Returns the transcript.
    pub fn transcript(&self) -> Transcript {
        self.0.transcript().into()
    }

    /// Serializes to a byte array.
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Secrets should be serializable")
    }

    /// Deserializes from a byte array.
    pub fn deserialize(bytes: Vec<u8>) -> Result<Secrets, JsError> {
        Ok(bincode::deserialize(&bytes)?)
    }
}

impl From<tlsn_core::Secrets> for Secrets {
    fn from(value: tlsn_core::Secrets) -> Self {
        Self(value)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[wasm_bindgen]
#[serde(transparent)]
pub struct Presentation(tlsn_core::presentation::Presentation);

#[wasm_bindgen]
impl Presentation {
    /// Returns the verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key().into()
    }

    /// Verifies the presentation.
    pub fn verify(&self) -> Result<PresentationOutput, JsError> {
        let provider = CryptoProvider::default();

        self.0
            .clone()
            .verify(&provider)
            .map(PresentationOutput::from)
            .map_err(JsError::from)
    }

    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).expect("Presentation should be serializable")
    }

    pub fn deserialize(bytes: Vec<u8>) -> Result<Presentation, JsError> {
        Ok(bincode::deserialize(&bytes)?)
    }
}

impl From<tlsn_core::presentation::Presentation> for Presentation {
    fn from(value: tlsn_core::presentation::Presentation) -> Self {
        Self(value)
    }
}

#[derive(Debug, Tsify, Serialize)]
#[tsify(into_wasm_abi)]
pub struct PresentationOutput {
    pub attestation: Attestation,
    pub server_name: Option<String>,
    pub connection_info: ConnectionInfo,
    pub transcript: Option<PartialTranscript>,
}

impl From<tlsn_core::presentation::PresentationOutput> for PresentationOutput {
    fn from(value: tlsn_core::presentation::PresentationOutput) -> Self {
        Self {
            attestation: value.attestation.into(),
            server_name: value.server_name.map(|name| name.as_str().to_string()),
            connection_info: value.connection_info.into(),
            transcript: value.transcript.map(PartialTranscript::from),
        }
    }
}

#[derive(Debug, Serialize)]
#[wasm_bindgen(getter_with_clone)]
pub struct NotarizationOutput {
    pub attestation: Attestation,
    pub secrets: Secrets,
}

#[derive(Debug, Tsify, Serialize)]
#[tsify(into_wasm_abi)]
pub struct VerifierOutput {
    pub server_name: String,
    pub connection_info: ConnectionInfo,
    pub transcript: PartialTranscript,
}

#[derive(Debug, Tsify, Serialize)]
#[tsify(into_wasm_abi)]
pub struct VerifyingKey {
    pub alg: u8,
    pub data: Vec<u8>,
}

impl From<&tlsn_core::signing::VerifyingKey> for VerifyingKey {
    fn from(value: &tlsn_core::signing::VerifyingKey) -> Self {
        Self {
            alg: value.alg.as_u8(),
            data: value.data.clone(),
        }
    }
}
