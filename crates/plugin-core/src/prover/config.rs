use std::{any::Any, f32::consts::E};

use http_body_util::{Empty, Full};
use hyper::{Request as HyperRequest, body::Bytes};
use rangeset::RangeSet;
use spansy::{
    Spanned,
    http::{BodyContent, Request, Requests, Response, Responses},
    json::JsonValue,
};
use tlsn::{
    config::ProtocolConfig,
    prover::{ProverConfig, TlsConfig},
};
use tlsn_core::{
    ProveConfig, ProveConfigBuilder, ProverOutput,
    connection::{DnsName, ServerName},
    transcript::{Direction, Transcript, TranscriptCommitConfig, TranscriptCommitConfigBuilder},
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_formats::spansy;
use tlsn_server_fixture_certs::CA_CERT_DER;

use super::*;

/// Prover plugin config.
pub struct Config {
    prover_params: ProverParams,
    req: RequestParams,
    handles: Vec<Handle>,
    expose: Vec<ExposeHandle>,
    root_store: Option<RootCertStore>,
    prove_server_identity: bool,
    pub is_http: bool,
}

impl Config {
    /// Builds and returns ProverConfig.
    pub fn prover_config(&self) -> ProverConfig {
        let name = ServerName::Dns(self.prover_params.serverDns.clone().try_into().unwrap());

        let mut builder = TlsConfig::builder();
        builder.root_store(RootCertStore {
            roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
        });
        let tls_config = builder.build().unwrap();

        let config = ProverConfig::builder()
            .server_name(name)
            .tls_config(tls_config)
            .protocol_config(
                ProtocolConfig::builder()
                    .max_sent_data(self.prover_params.maxSentData)
                    .max_recv_data(self.prover_params.maxRecvData)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();

        config
    }

    /// Validates that the config is well-formed.
    pub fn validate(&self) -> bool {
        // Invariants:
        // - headers/body are consistent with the handles
        // ...
        // TODO: figure out at what stage to validate.
        true
    }

    // Returns the HTTP request.
    pub fn http_request(&self) -> HyperRequest<Full<Bytes>> {
        let mut request = HyperRequest::builder()
            .uri(self.req.url.clone())
            .header("Host", self.prover_params.serverDns.clone());

        for (k, v) in &self.req.headers {
            request = request.header(k, v);
        }

        request = request.method(self.req.method.as_str());
        let body = match &self.req.body {
            Some(data) => Full::<Bytes>::from(data.clone()),
            None => Full::<Bytes>::from(vec![]),
        };

        request.body(body).unwrap()
    }

    /// Creates a `ProveConfig`.
    pub fn prove_config(&self, transcript: &Transcript) -> ProveConfig {
        let mut prove_cfg = ProveConfig::builder(transcript);
        let mut commit_cfg = TranscriptCommitConfig::builder(transcript);

        if self.prove_server_identity {
            prove_cfg.server_identity();
        }

        let reqs = Requests::new_from_slice(transcript.sent())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let resps = Responses::new_from_slice(transcript.received())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let req = reqs.first().expect("at least one request");
        let resp = resps.first().expect("at least one response");

        let req_hnd = self
            .handles
            .iter()
            .filter(|h| h.typ == MessageType::Request);
        let resp_hnd = self
            .handles
            .iter()
            .filter(|h| h.typ == MessageType::Response);

        handle_req(&req, req_hnd, &mut commit_cfg, &mut prove_cfg);
        handle_resp(&resp, resp_hnd, &mut commit_cfg, &mut prove_cfg);

        prove_cfg.transcript_commit(commit_cfg.build().unwrap());
        prove_cfg.build().unwrap()
    }

    /// Returns the output of the plugin.
    pub fn output(&self, transcript: Transcript, prover_output: ProverOutput) -> Output {
        let reqs = Requests::new_from_slice(transcript.sent())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let resps = Responses::new_from_slice(transcript.received())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        let req = reqs.first().expect("at least one request");
        let resp = resps.first().expect("at least one response");

        let mut exposed = Vec::new();
        // Extract the to-be-exposed data from the transcript.
        for h in self.expose.iter() {
            let range = if h.typ == MessageType::Request {
                req_part_range(&req, &h.part, h.params.as_ref())
            } else {
                resp_part_range(&resp, &h.part, h.params.as_ref())
            };

            let seq = transcript.get((&h.typ).into(), &range).unwrap();

            exposed.push((h.clone(), seq.data().to_vec()));
        }

        Output {
            prover_output,
            exposed,
        }
    }
}

/// Processes the handles for the request.
fn handle_req<'a, I>(
    req: &Request,
    handles: I,
    commit_cfg: &mut TranscriptCommitConfigBuilder<'_>,
    prove_cfg: &mut ProveConfigBuilder<'_>,
) where
    I: Iterator<Item = &'a Handle>,
{
    for h in handles {
        let range = req_part_range(&req, &h.part, h.params.as_ref());

        match &h.action {
            ActionType::Commit(alg) => {
                commit_cfg
                    .commit_with_kind(&range, (&h.typ).into(), alg.into())
                    .unwrap();
            }
            ActionType::Reveal => {
                prove_cfg.reveal_sent(&range).unwrap();
            }
        }
    }
}

/// Processes the handles for the response.
fn handle_resp<'a, I>(
    resp: &Response,
    handles: I,
    commit_cfg: &mut TranscriptCommitConfigBuilder<'_>,
    prove_cfg: &mut ProveConfigBuilder<'_>,
) where
    I: Iterator<Item = &'a Handle>,
{
    for h in handles {
        let range = resp_part_range(resp, &h.part, h.params.as_ref());

        match &h.action {
            ActionType::Commit(alg) => {
                commit_cfg
                    .commit_with_kind(&range, (&h.typ).into(), alg.into())
                    .unwrap();
            }
            ActionType::Reveal => {
                prove_cfg.reveal_recv(&range).unwrap();
            }
        }
    }
}

/// Returns the range for the given `part` of the HTTP request,
fn req_part_range(
    req: &Request,
    part: &MessagePart,
    params: Option<&PartParams>,
) -> RangeSet<usize> {
    match part {
        MessagePart::All => {
            assert!(params.is_none());
            RangeSet::from([
                req.span().indices().min().unwrap()..req.span().indices().end().unwrap()
            ])
        }
        MessagePart::StartLine => {
            assert!(params.is_none());
            req.request.span().indices().clone()
        }
        MessagePart::Header => {
            let key = if let Some(PartParams::Header(params)) = &params {
                &params.key
            } else {
                panic!("HeaderParams must be present")
            };
            req.headers_with_name(key.as_str())
                .map(|h| h.span().indices())
                .fold(RangeSet::default(), |acc, r| acc | r)
        }
        MessagePart::Body => {
            let body_params = if let Some(PartParams::Body(b)) = params {
                b
            } else {
                panic!("BodyParams must be present")
            };
            match body_params {
                BodyParams::JsonPath(path) => {
                    let body = req.body.as_ref().unwrap();
                    // TODO: find a better way than re-parsing the entire
                    // json for each path.
                    json_path_range(body, &path)
                }
                _ => unimplemented!("only json path is currently supported"),
            }
        }
    }
}

/// Returns the range for the given `part` of the HTTP response,
fn resp_part_range(
    resp: &Response,
    part: &MessagePart,
    params: Option<&PartParams>,
) -> RangeSet<usize> {
    match part {
        MessagePart::All => {
            assert!(params.is_none());
            RangeSet::from([
                resp.span().indices().min().unwrap()..resp.span().indices().end().unwrap()
            ])
        }
        MessagePart::StartLine => {
            assert!(params.is_none());
            resp.status.span().indices().clone()
        }
        MessagePart::Header => {
            let key = if let Some(PartParams::Header(params)) = &params {
                &params.key
            } else {
                panic!("HeaderParams must be present")
            };
            resp.headers_with_name(key.as_str())
                .map(|h| h.span().indices())
                .fold(RangeSet::default(), |acc, r| acc | r)
        }
        MessagePart::Body => {
            let body_params = if let Some(PartParams::Body(b)) = params {
                b
            } else {
                panic!("BodyParams must be present")
            };
            match body_params {
                BodyParams::JsonPath(path) => {
                    let body = resp.body.as_ref().unwrap();
                    // TODO: use a better approach than re-parsing the entire
                    // json for each path.
                    json_path_range(body, &path)
                }
                _ => unimplemented!("only json parsing is currently supported"),
            }
        }
    }
}

/// Returns the byte range (in source coordinates) of the key–value pair
/// corresponding to the given `path` in the HTTP `body` containing a JSON
/// value.
///
/// If the path points to an array element, only the range of the **value**
/// of the element is returned.
///
/// Note: the returned range is **absolute within the original HTTP message**,  
/// not relative to the body slice itself.
fn json_path_range(body: &spansy::http::Body, path: &String) -> RangeSet<usize> {
    // Offset of the body from the start of the HTTP message.
    let body_offset = body.span().indices().min().unwrap();

    let json = spansy::json::parse(body.as_bytes().to_vec().into()).unwrap();

    let val = json.get(path).unwrap();

    let dot = ".";
    let last = path.split(dot).last().unwrap();

    let mut range = if last.parse::<usize>().is_ok() {
        // The path points to an array element, so we only need the range of the
        // **value**.
        val.span().indices().clone()
    } else {
        // We need the range of the **key-value** pair.
        let parent_val = if last == path {
            // Path points to a top-level value.
            &json
        } else {
            json.get(&path[..path.len() - last.len() - dot.len()])
                .unwrap()
        };
        let parent_obj = match parent_val {
            JsonValue::Object(obj) => obj,
            _ => unreachable!("parent must be a JSON object"),
        };

        let kv = parent_obj.elems.iter().find(|kv| kv.value == *val).unwrap();
        let mut range = kv.span().indices().clone();

        // If a trailing comma is present, don't include it in the range.
        if kv.span().as_str().ends_with(",") {
            range = (range.min().unwrap()..range.end().unwrap() - 1).into();
        }

        range
    };

    range.shift_right(&body_offset);
    range.clone()
}

// temporary defult, not for prod
impl Default for Config {
    fn default() -> Self {
        Self {
            prover_params: ProverParams {
                maxRecvData: 1000,
                maxSentData: 100,
                serverDns: "test-server.io".to_string(),
                proxyUrl: None,
                verifierUrl: "wss:://localhost:8081".to_string(),
            },
            req: RequestParams {
                url: "/data".to_string(),
                method: "GET".to_string(),
                body: None,
                headers: vec![],
            },
            handles: vec![Handle {
                action: ActionType::Commit(Alg::Blake3),
                typ: MessageType::Request,
                params: Some(PartParams::Body(BodyParams::JsonPath(
                    "json.path".to_string(),
                ))),
                part: MessagePart::Body,
            }],
            root_store: None,
            prove_server_identity: true,
            is_http: true,
            expose: vec![ExposeHandle {
                typ: MessageType::Request,
                params: Some(PartParams::Body(BodyParams::JsonPath(
                    "json.path".to_string(),
                ))),
                part: MessagePart::Body,
            }],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spansy::http::parse_response;
    use tlsn_data_fixtures::http::{request, response};
    use tlsn_formats::spansy::http::parse_request;

    #[test]
    fn test_req_part_range() {
        let data = request::POST_JSON;
        let req = parse_request(&data).unwrap();
        let s = std::str::from_utf8(data).unwrap();

        //===============All
        let part = MessagePart::All;
        let range = req_part_range(&req, &part, None);
        assert_eq!(range, 0..data.len());

        //===============StartLine
        let part = MessagePart::StartLine;
        let range = req_part_range(&req, &part, None);
        let end = s.find("\r\n").unwrap() + 2;
        assert_eq!(range, 0..end);

        //===============Header
        let part = MessagePart::Header;
        let param = PartParams::Header(HeaderParams {
            key: "Content-Length".to_string(),
        });
        let range = req_part_range(&req, &part, Some(&param));

        let target: &'static str = "Content-Length: 44";
        let start = s.find(target).unwrap();
        let end = start + target.len() + 2;
        assert_eq!(range, start..end);

        //===============Body
        let part = MessagePart::Body;
        let param = PartParams::Body(BodyParams::JsonPath("bazz".to_string()));
        let range = req_part_range(&req, &part, Some(&param));

        let target: &'static str = "\"bazz\": 123";
        let start = s.find(target).unwrap();
        let end = start + target.len();
        assert_eq!(range, start..end);
    }

    #[test]
    fn test_resp_part_range() {
        let data = response::OK_JSON;
        let resp = parse_response(&data).unwrap();
        let s = std::str::from_utf8(data).unwrap();

        //===============All
        let part = MessagePart::All;
        let range = resp_part_range(&resp, &part, None);
        assert_eq!(range, 0..data.len());

        //===============StartLine
        let part = MessagePart::StartLine;
        let range = resp_part_range(&resp, &part, None);
        let end = s.find("\r\n").unwrap() + 2;
        assert_eq!(range, 0..end);

        //===============Header
        let part = MessagePart::Header;
        let param = PartParams::Header(HeaderParams {
            key: "Content-Length".to_string(),
        });
        let range = resp_part_range(&resp, &part, Some(&param));

        let target: &'static str = "Content-Length: 44";
        let start = s.find(target).unwrap();
        let end = start + target.len() + 2;
        assert_eq!(range, start..end);

        //===============Body
        let part = MessagePart::Body;
        let param = PartParams::Body(BodyParams::JsonPath("bazz".to_string()));
        let range = resp_part_range(&resp, &part, Some(&param));

        let target: &'static str = "\"bazz\": 123";
        let start = s.find(target).unwrap();
        let end = start + target.len();
        assert_eq!(range, start..end);
    }
}
