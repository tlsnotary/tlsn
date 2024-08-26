//! This module handles the notarization phase of the verifier.
//!
//! The TLS verifier is only a notary.

use super::{state::Notarize, Verifier, VerifierError};
use httparse::{Request, Response};
use serio::SinkExt;
use signature::Signer;
use tlsn_core::{msg::SignedSession, Signature};

use sha2::{Digest, Sha256};
use tracing::{debug, info, instrument};

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
        let Notarize {
            mut io,
            mux_ctrl,
            mut mux_fut,
            response_data,
            request_data,
            ..
        } = self.state;

        let mut request_headers = [httparse::EMPTY_HEADER; 16];
        let mut request = Request::new(&mut request_headers);
        let _req_result = request.parse(request_data.as_bytes()).unwrap();

        let mut response_headers = [httparse::EMPTY_HEADER; 16];
        let mut response = Response::new(&mut response_headers);
        let _resp_result = response.parse(response_data.as_bytes()).unwrap();

        let session_header = mux_fut
            .poll_with(async {
                let mut data = Vec::new();
                data.extend_from_slice(response_data.as_bytes());
                data.extend_from_slice(request_data.as_bytes());
                let mut hasher = Sha256::new();
                hasher.update(&data);
                let hash = hasher.finalize();
                let signature = signer.sign(&hash);
                info!("signing session");
                let signed_session = SignedSession {
                    application_data: hex::encode(hash),
                    signature: signature.into(),
                };
                info!("sending signed session");
                io.send(signed_session.clone()).await?;
                info!(
                    "sent signed session. signature {:?}",
                    signed_session.signature
                );
                info!("signed session hash: {:?}", signed_session.application_data);

                // Finalize all TEE before signing the session header.
                Ok::<_, VerifierError>(signed_session)
            })
            .await?;

        if !mux_fut.is_complete() {
            mux_ctrl.mux().close();
            mux_fut.await?;
        }

        debug!("finalization complete");

        Ok(session_header)
    }
}
