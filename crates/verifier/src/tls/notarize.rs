//! This module handles the notarization phase of the verifier.
//!
//! The TLS verifier is only a notary.

use super::{state::Notarize, Verifier, VerifierError};
use signature::Signer;
use tlsn_core::Signature;

use tracing::instrument;

impl Verifier<Notarize> {
    /// Notarizes the TLS session.
    ///
    /// # Arguments
    ///
    /// * `signer` - The signer used to sign the notarization result.
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub async fn finalize<T>(self, _signer: &impl Signer<T>) -> Result<(), VerifierError>
    where
        T: Into<Signature>,
    {
        let Notarize {
            mux_ctrl,
            mut mux_fut,
            ..
        } = self.state;

        let session_header = mux_fut
            .poll_with(async {

                // Finalize all TEE before signing the session header.
                Ok::<_, VerifierError>(())
            })
            .await?;

        if !mux_fut.is_complete() {
            mux_ctrl.mux().close();
            mux_fut.await?;
        }

        Ok(session_header)
    }
}
