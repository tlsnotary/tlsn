use crate::{
    BodyParams, DisclosurePolicy, DisclosureRule, HttpHandle, MessagePart, MessageType,
    prover::{HttpRequest, ProverParams},
};

use crate::prover::Output;
use http_body_util::Full;
use hyper::{Request as HyperRequest, body::Bytes};
use rangeset::RangeSet;
use serde::{Deserialize, Serialize};
use tlsn::{
    config::ProtocolConfig,
    prover::{ProverConfig, TlsConfig},
};
use tlsn_core::{
    ProveConfig, ProveConfigBuilder, ProverOutput,
    connection::{DnsName, ServerName},
    transcript::{Transcript, TranscriptCommitConfig, TranscriptCommitConfigBuilder},
    webpki::RootCertStore,
};
use tlsn_formats::{
    http::{Body, Request, Requests, Response, Responses},
    json::JsonValue,
    spansy,
    spansy::Spanned,
};

/// Prover plugin config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub prover_params: ProverParams,
    pub request: HttpRequest,
    /// Data which will be disclosed to the verifier.
    pub disclose: Vec<DisclosureRule>,
    /// Data which will be exposed in the plugin output.
    pub expose: Vec<HttpHandle>,
    pub root_store: RootCertStore,
    pub verifier_endpoint: String,
    /// Proxy endpoint for connecting to the server.
    pub proxy_endpoint: Option<String>,
}

impl Config {
    /// Returns the verifier endpoint.
    pub fn prover_endpoint(&self) -> &String {
        &self.verifier_endpoint
    }

    /// Builds and returns [ProverConfig].
    pub fn prover_config(&self) -> Result<ProverConfig, ConfigError> {
        let dns_name: DnsName = self
            .prover_params
            .server_dns
            .clone()
            .try_into()
            .map_err(|_| ConfigError("prover_config error".to_string()))?;

        let mut builder = TlsConfig::builder();
        builder.root_store(self.root_store.clone());
        let tls_config = builder.build().unwrap();

        let config = ProverConfig::builder()
            .server_name(ServerName::Dns(dns_name))
            .tls_config(tls_config)
            .protocol_config(
                ProtocolConfig::builder()
                    .max_sent_data(self.prover_params.max_sent_data)
                    .max_recv_data(self.prover_params.max_recv_data)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        Ok(config)
    }

    /// Returns the HTTP request.
    pub fn http_request(&self) -> Result<HyperRequest<Full<Bytes>>, ConfigError> {
        let mut request = HyperRequest::builder()
            .uri(self.request.url.clone())
            .header("Host", self.prover_params.server_dns.clone());

        for (k, v) in &self.request.headers {
            request = request.header(k, v);
        }

        request = request.method(self.request.method.as_str());
        let body = match &self.request.body {
            Some(data) => Full::<Bytes>::from(data.clone()),
            None => Full::<Bytes>::from(vec![]),
        };

        request
            .body(body)
            .map_err(|_| ConfigError("http_request error".to_string()))
    }

    /// Creates a [ProveConfig] for the given `transcript`.
    pub fn prove_config(&self, transcript: &Transcript) -> Result<ProveConfig, ConfigError> {
        let mut prove_cfg = ProveConfig::builder(transcript);
        let mut commit_cfg = TranscriptCommitConfig::builder(transcript);

        if self.prover_params.prove_server_identity {
            prove_cfg.server_identity();
        }

        let reqs = Requests::new_from_slice(transcript.sent())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ConfigError("prove_config error".to_string()))?;
        let resps = Responses::new_from_slice(transcript.received())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ConfigError("prove_config error".to_string()))?;

        let req = reqs.first().expect("at least one request");
        let resp = resps.first().expect("at least one response");

        let req_rules = self
            .disclose
            .iter()
            .filter(|h| h.http.typ == MessageType::Request);
        let resp_rules = self
            .disclose
            .iter()
            .filter(|h| h.http.typ == MessageType::Response);

        disclose_req(req, req_rules, &mut commit_cfg, &mut prove_cfg);
        disclose_resp(resp, resp_rules, &mut commit_cfg, &mut prove_cfg);

        prove_cfg.transcript_commit(commit_cfg.build().unwrap());
        Ok(prove_cfg.build().unwrap())
    }

    /// Returns the output of the plugin.
    pub fn output(
        &self,
        transcript: Transcript,
        prover_output: ProverOutput,
    ) -> Result<Output, ConfigError> {
        let reqs = Requests::new_from_slice(transcript.sent())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ConfigError("output error".to_string()))?;
        let resps = Responses::new_from_slice(transcript.received())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ConfigError("output error".to_string()))?;

        let req = reqs.first().expect("at least one request");
        let resp = resps.first().expect("at least one response");

        let mut exposed = Vec::new();

        // Extract the to-be-exposed data from the transcript.
        for h in self.expose.iter() {
            let range = if h.typ == MessageType::Request {
                req_part_range(req, h)
            } else {
                resp_part_range(resp, h)
            };

            let seq = transcript
                .get((&h.typ).into(), &range)
                .ok_or(ConfigError("range not found in transcript".to_string()))?;

            exposed.push((h.clone(), seq.data().to_vec()));
        }

        Ok(Output {
            output: prover_output,
            plaintext: exposed,
        })
    }
}

#[derive(Debug, thiserror::Error)]
#[error("config error: {0}")]
pub struct ConfigError(String);

/// Processes disclosure rules for the request.
fn disclose_req<'a, I>(
    req: &Request,
    rules: I,
    commit_cfg: &mut TranscriptCommitConfigBuilder<'_>,
    prove_cfg: &mut ProveConfigBuilder<'_>,
) where
    I: Iterator<Item = &'a DisclosureRule>,
{
    for r in rules {
        let range = req_part_range(req, &r.http);

        if range.is_empty() {
            // TODO: maybe return an error here when the part was not found.
            return;
        }

        match &r.policy {
            DisclosurePolicy::Commit(alg) => {
                commit_cfg
                    .commit_with_kind(&range, (&r.http.typ).into(), alg.into())
                    .expect("range is in the transcript");
            }
            DisclosurePolicy::Reveal => {
                prove_cfg
                    .reveal_sent(&range)
                    .expect("range is in the transcript");
            }
        }
    }
}

/// Processes disclosure rules for the response.
fn disclose_resp<'a, I>(
    resp: &Response,
    rules: I,
    commit_cfg: &mut TranscriptCommitConfigBuilder<'_>,
    prove_cfg: &mut ProveConfigBuilder<'_>,
) where
    I: Iterator<Item = &'a DisclosureRule>,
{
    for r in rules {
        let range = resp_part_range(resp, &r.http);

        if range.is_empty() {
            // TODO: maybe return an error here when the part was not found.
            return;
        }

        match &r.policy {
            DisclosurePolicy::Commit(alg) => {
                commit_cfg
                    .commit_with_kind(&range, (&r.http.typ).into(), alg.into())
                    .expect("range is in the transcript");
            }
            DisclosurePolicy::Reveal => {
                prove_cfg
                    .reveal_recv(&range)
                    .expect("range is in the transcript");
            }
        }
    }
}

/// Returns the range for the given `part` of the HTTP request,
fn req_part_range(req: &Request, part: &HttpHandle) -> RangeSet<usize> {
    match &part.part {
        MessagePart::All => {
            (req.span().indices().min().unwrap()..req.span().indices().end().unwrap()).into()
        }

        MessagePart::StartLine => req.request.span().indices().clone(),

        MessagePart::Header(params) => req
            .headers_with_name(params.key.as_str())
            .map(|h| h.span().indices())
            .fold(RangeSet::default(), |acc, r| acc | r),

        MessagePart::Body(params) => match &req.body {
            Some(body) => {
                // Body offset from the start of an HTTP message.
                let body_offset = body
                    .span()
                    .indices()
                    .min()
                    .expect("body span cannot be empty");
                let mut range = body_params_range(body, params);
                range.shift_right(&body_offset);
                range
            }
            None => RangeSet::default(),
        },
    }
}

/// Returns the range for the given `part` of the HTTP response,
fn resp_part_range(resp: &Response, part: &HttpHandle) -> RangeSet<usize> {
    match &part.part {
        MessagePart::All => {
            (resp.span().indices().min().unwrap()..resp.span().indices().end().unwrap()).into()
        }
        MessagePart::StartLine => resp.status.span().indices().clone(),
        MessagePart::Header(params) => resp
            .headers_with_name(params.key.as_str())
            .map(|h| h.span().indices())
            .fold(RangeSet::default(), |acc, r| acc | r),
        MessagePart::Body(params) => match &resp.body {
            Some(body) => {
                // Body offset from the start of an HTTP message.
                let body_offset = body.span().indices().min().expect("body cannot be empty");
                let mut range = body_params_range(body, params);
                range.shift_right(&body_offset);
                range
            }
            None => RangeSet::default(),
        },
    }
}

/// Returns the byte range of the `params` in the given `body`.
fn body_params_range(body: &Body, params: &BodyParams) -> RangeSet<usize> {
    match params {
        BodyParams::JsonPath(path) => {
            // TODO: use a better approach than re-parsing the entire
            // json for each path.
            match spansy::json::parse(body.as_bytes().to_vec().into()) {
                Ok(json) => json_path_range(&json, path),
                Err(_) => RangeSet::default(),
            }
        }
        _ => unimplemented!("only json parsing is currently supported"),
    }
}

/// Returns the byte range of the key–value pair corresponding to the given
/// `path` in a JSON value `source`.
///
/// If the path points to an array element, only the range of the **value**
/// of the element is returned.
fn json_path_range(source: &JsonValue, path: &String) -> RangeSet<usize> {
    let val = match source.get(path) {
        Some(val) => val,
        None => return RangeSet::default(),
    };

    let dot = ".";
    let last = path.split(dot).last().unwrap();
    // Whether `path` is a top-level key.
    let is_top_level = last == path;

    if last.parse::<usize>().is_ok() {
        // The path points to an array element, so we only need the range of
        // the **value**.
        val.span().indices().clone()
    } else {
        let parent_val = if is_top_level {
            source
        } else {
            source
                .get(&path[..path.len() - last.len() - dot.len()])
                .expect("path is valid")
        };
        let JsonValue::Object(parent_obj) = parent_val else {
            unreachable!("parent value is always an object");
        };

        // We need the range of the **key-value** pair.
        let kv = parent_obj
            .elems
            .iter()
            .find(|kv| kv.value == *val)
            .expect("element exists");

        kv.without_separator()
    }
}

#[cfg(test)]
mod tests {
    use crate::HeaderParams;

    use super::*;
    use spansy::http::parse_response;
    use tlsn_data_fixtures::http::{request, response};
    use tlsn_formats::spansy::http::parse_request;

    #[test]
    fn test_req_part_range() {
        let data = request::POST_JSON;
        let req = parse_request(data).unwrap();
        let s = std::str::from_utf8(data).unwrap();

        //===============All
        let part = HttpHandle {
            part: MessagePart::All,
            typ: MessageType::Request,
        };
        let range = req_part_range(&req, &part);
        assert_eq!(range, 0..data.len());

        //===============StartLine
        let part = HttpHandle {
            part: MessagePart::StartLine,
            typ: MessageType::Request,
        };
        let range = req_part_range(&req, &part);
        let end = s.find("\r\n").unwrap() + 2;
        assert_eq!(range, 0..end);

        //===============Header
        let part = HttpHandle {
            part: MessagePart::Header(HeaderParams {
                key: "Content-Length".to_string(),
            }),
            typ: MessageType::Request,
        };
        let range = req_part_range(&req, &part);

        let target: &'static str = "Content-Length: 44";
        let start = s.find(target).unwrap();
        let end = start + target.len() + 2;
        assert_eq!(range, start..end);

        //===============Body
        let part = HttpHandle {
            part: MessagePart::Body(BodyParams::JsonPath("bazz".to_string())),
            typ: MessageType::Request,
        };
        let range = req_part_range(&req, &part);

        let target: &'static str = "\"bazz\": 123";
        let start = s.find(target).unwrap();
        let end = start + target.len();
        assert_eq!(range, start..end);
    }

    #[test]
    fn test_resp_part_range() {
        let data = response::OK_JSON;
        let resp = parse_response(data).unwrap();
        let s = std::str::from_utf8(data).unwrap();

        //===============All
        let part = HttpHandle {
            part: MessagePart::All,
            typ: MessageType::Response,
        };
        let range = resp_part_range(&resp, &part);
        assert_eq!(range, 0..data.len());

        //===============StartLine
        let part = HttpHandle {
            part: MessagePart::StartLine,
            typ: MessageType::Response,
        };
        let range = resp_part_range(&resp, &part);
        let end = s.find("\r\n").unwrap() + 2;
        assert_eq!(range, 0..end);

        //===============Header
        let part = HttpHandle {
            part: MessagePart::Header(HeaderParams {
                key: "Content-Length".to_string(),
            }),
            typ: MessageType::Response,
        };
        let range = resp_part_range(&resp, &part);

        let target: &'static str = "Content-Length: 44";
        let start = s.find(target).unwrap();
        let end = start + target.len() + 2;
        assert_eq!(range, start..end);

        //===============Body
        let part = HttpHandle {
            part: MessagePart::Body(BodyParams::JsonPath("bazz".to_string())),
            typ: MessageType::Request,
        };
        let range = resp_part_range(&resp, &part);

        let target: &'static str = "\"bazz\": 123";
        let start = s.find(target).unwrap();
        let end = start + target.len();
        assert_eq!(range, start..end);
    }
}
