use std::{collections::HashMap, ops::Range};

use http_body_util::Full;
use hyper::body::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use tlsn_core::commitment::CommitmentKind;
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
            builder = builder.header(name, value.to_vec());
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
pub struct Transcript {
    pub sent: Vec<u8>,
    pub recv: Vec<u8>,
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

#[derive(Debug, Serialize, Deserialize)]
#[wasm_bindgen]
#[serde(transparent)]
pub struct NotarizedSession(tlsn_core::NotarizedSession);

#[wasm_bindgen]
impl NotarizedSession {
    /// Builds a new proof.
    pub fn proof(&self, reveal: Reveal) -> Result<TlsProof, JsError> {
        let mut builder = self.0.data().build_substrings_proof();

        for range in reveal.sent.iter() {
            builder.reveal_sent(range, CommitmentKind::Blake3)?;
        }

        for range in reveal.recv.iter() {
            builder.reveal_recv(range, CommitmentKind::Blake3)?;
        }

        let substring_proof = builder.build()?;

        Ok(TlsProof(tlsn_core::proof::TlsProof {
            session: self.0.session_proof(),
            substrings: substring_proof,
        }))
    }

    /// Returns the transcript.
    pub fn transcript(&self) -> Transcript {
        Transcript {
            sent: self.0.data().sent_transcript().data().to_vec(),
            recv: self.0.data().recv_transcript().data().to_vec(),
        }
    }

    /// Serializes to a byte array.
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).expect("NotarizedSession is serializable")
    }

    /// Deserializes from a byte array.
    pub fn deserialize(bytes: Vec<u8>) -> Result<NotarizedSession, JsError> {
        Ok(bincode::deserialize(&bytes)?)
    }
}

impl From<tlsn_core::NotarizedSession> for NotarizedSession {
    fn from(value: tlsn_core::NotarizedSession) -> Self {
        Self(value)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[wasm_bindgen]
#[serde(transparent)]
pub struct TlsProof(tlsn_core::proof::TlsProof);

#[wasm_bindgen]
impl TlsProof {
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).expect("TlsProof is serializable")
    }

    pub fn deserialize(bytes: Vec<u8>) -> Result<TlsProof, JsError> {
        Ok(bincode::deserialize(&bytes)?)
    }
}

#[derive(Debug, Tsify, Serialize)]
#[tsify(into_wasm_abi)]
pub struct VerifierData {
    pub server_dns: String,
    pub sent: Vec<u8>,
    pub sent_auth_ranges: Vec<Range<usize>>,
    pub received: Vec<u8>,
    pub received_auth_ranges: Vec<Range<usize>>,
}
