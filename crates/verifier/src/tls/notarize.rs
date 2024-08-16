//! This module handles the notarization phase of the verifier.
//!
//! The TLS verifier is only a notary.

use super::{state::Notarize, Verifier, VerifierError};
use serio::SinkExt;
use signature::Signer;
use tlsn_core::{msg::SignedSession, Signature};

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
            application_data,
            ..
        } = self.state;

        let session_header = mux_fut
            .poll_with(async {
                let signature = signer.sign(application_data.as_bytes());
                info!("signing session");
                let signed_session = SignedSession {
                    application_data: application_data.clone(),
                    signature: signature.into(),
                };
                info!("sending signed session");
                io.send(signed_session.clone()).await?;
                info!("sent signed session. signature {:?}", signed_session.signature);

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
