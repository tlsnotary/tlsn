use std::collections::HashMap;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use wasm_bindgen::JsError;

#[derive(Serialize, Deserialize)]
pub struct ProverConfig {
    id: String,
    server_dns: String,
    max_sent_data: Option<usize>,
    max_received_data: Option<usize>,
}

impl From<ProverConfig> for tlsn_prover::tls::ProverConfig {
    fn from(value: ProverConfig) -> Self {
        let mut builder = tlsn_prover::tls::ProverConfig::builder();
        builder.id(value.id);
        builder.server_dns(value.server_dns);

        if let Some(value) = value.max_sent_data {
            builder.max_sent_data(value);
        }

        if let Some(value) = value.max_received_data {
            builder.max_recv_data(value);
        }

        builder.build().unwrap()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum Body {
    Json(JsonValue),
}

#[derive(Serialize, Deserialize)]
#[serde(try_from = "String")]
pub enum Method {
    GET,
    POST,
    PUT,
    DELETE,
}

impl TryFrom<String> for Method {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "get" => Ok(Method::GET),
            "post" => Ok(Method::POST),
            "put" => Ok(Method::PUT),
            "delete" => Ok(Method::DELETE),
            _ => Err(format!("invalid method: {}", value)),
        }
    }
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

#[derive(Serialize, Deserialize)]
pub struct HttpRequest {
    pub uri: String,
    pub method: Method,
    pub headers: HashMap<String, String>,
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

#[derive(Serialize, Deserialize)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, Bytes)>,
    pub body: Option<Bytes>,
}

#[derive(Serialize, Deserialize)]
pub struct Redact {
    pub sent: Vec<Vec<u8>>,
    pub received: Vec<Vec<u8>>,
}
