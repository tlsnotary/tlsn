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
    pub body: String,
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
pub struct SignedSession(tlsn_core::msg::SignedSession);

#[wasm_bindgen]
impl SignedSession {
    /// Serializes to a byte array.
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(self).expect("NotarizedSession is serializable")
    }

    /// Deserializes from a byte array.
    pub fn deserialize(bytes: Vec<u8>) -> Result<SignedSession, JsError> {
        Ok(bincode::deserialize(&bytes)?)
    }
}

impl From<tlsn_core::msg::SignedSession> for SignedSession {
    fn from(value: tlsn_core::msg::SignedSession) -> Self {
        Self(value)
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
