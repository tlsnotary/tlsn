//! This module handles the notarization phase of the verifier.
//!
//! The TLS verifier is only a notary.

use std::collections::HashMap;

use super::{state::Notarize, Verifier, VerifierError};
use httparse::{Request, Response, Status};
use serio::SinkExt;
use signature::Signer;
use tlsn_core::{msg::SignedSession, Signature};

use sha2::{Digest, Sha256};
use tracing::{debug, info, instrument, trace};
use zeroize::Zeroize;

use lazy_static::lazy_static;
use prometheus::{register_histogram, Histogram};

lazy_static! {
    static ref FINALIZATION_HISTOGRAM: Histogram = register_histogram!(
        "finalization_duration_seconds",
        "The duration of finalization in seconds"
    ).unwrap();
}

impl Verifier<Notarize> {
    /// Notarizes the TLS session.
    ///
    /// # Arguments
    ///
    /// * `signer` - The signer used to sign the notarization result.
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub async fn finalize<T>(self, signer: &impl Signer<T>) -> Result<SignedSession, VerifierError>
    where
        T: Into<Signature>,
    {
        debug!("starting finalization");
        let timer = FINALIZATION_HISTOGRAM.start_timer();
        let Notarize {
            mut io,
            mux_ctrl,
            mut mux_fut,
            mut response_data,
            mut request_data,
            ..
        } = self.state;

        let mut request_headers = [httparse::EMPTY_HEADER; 64];
        let mut request = Request::new(&mut request_headers);
        let request_data_mut = request_data.to_owned();
        let req_bytes = request_data_mut.as_bytes();
        let _req_result = request.parse(&req_bytes).unwrap();

        let mut response_headers = [httparse::EMPTY_HEADER; 64];
        let mut response = Response::new(&mut response_headers);
        let response_data_mut = response_data.to_owned();
        let resp_bytes = response_data_mut.as_bytes();
        let resp_size = match response.parse(resp_bytes).unwrap() {
            Status::Complete(size) => {
                info!("response parsed");
                size
            }
            Status::Partial => {
                info!("response partial");
                0
            }
        };
        let body = String::from_utf8_lossy(&resp_bytes[resp_size..]).to_string();
        let mut attestations: HashMap<String, Signature> = HashMap::new();

        match request.path {
            Some(path) => {
                trace!("request path: {:?}", path);
                if path.starts_with("https://swapi.dev/api/people/1") {
                } else if path.starts_with("https://api.x.com/1.1/account/settings.json") {
                } else if path.starts_with(
                    "https://x.com/i/api/graphql/Yka-W8dz7RaEuQNkroPkYw/UserByScreenName",
                ) {
                    let parsed: crate::tls::x::UserByScreenName =
                        serde_json::from_str(&body).unwrap();
                    let statuses_count = parsed.data.user.result.legacy.statuses_count;
                    trace!("x.com statuses count: {:?}", statuses_count);
                    if statuses_count > 100 {
                        trace!("statuses count greater than 100");
                        let attestation = "statuses>100";
                        let signature = signer.sign(attestation.as_bytes());
                        attestations.insert(attestation.to_string(), signature.into());
                    }

                    let screen_name = parsed.data.user.result.legacy.screen_name;
                    let attestation = format!("screen_name={}", screen_name);
                    let signature = signer.sign(attestation.as_bytes());
                    attestations.insert(attestation.to_string(), signature.into());

                    let followers_count = parsed.data.user.result.legacy.followers_count;
                    trace!("x.com follower count: {:?}", followers_count);
                    if followers_count > 100 {
                        trace!("follower count greater than 100");
                        let attestation = "followers>100";
                        let signature = signer.sign(attestation.as_bytes());
                        attestations.insert(attestation.to_string(), signature.into());
                    }
                } else {
                    trace!("request path not found");
                }
            }
            None => {
                info!("request path not found");
            }
        }

        let session_header = mux_fut
            .poll_with(async {
                let mut data = Vec::new();
                data.extend_from_slice(req_bytes);
                data.extend_from_slice(resp_bytes);
                let mut hasher = Sha256::new();
                hasher.update(&data);
                let hash = hasher.finalize();
                let signature = signer.sign(&hash);
                info!("signing session");
                let signed_session = SignedSession {
                    application_data: hex::encode(hash),
                    signature: signature.into(),
                    attestations,
                };
                info!("sending signed session");
                io.send(signed_session.clone()).await?;
                info!(
                    "sent signed session {:?}",
                    signed_session.attestations.keys()
                );
                info!("signed session hash: {:?}", signed_session.application_data);

                // Finalize all TEE before signing the session header.
                Ok::<_, VerifierError>(signed_session)
            })
            .await?;

        request_data.zeroize();
        response_data.zeroize();
        drop(response);
        drop(request);

        if !mux_fut.is_complete() {
            mux_ctrl.mux().close();
            mux_fut.await?;
        }

        timer.stop_and_record();
        debug!("finalization complete");

        Ok(session_header)
    }
}
