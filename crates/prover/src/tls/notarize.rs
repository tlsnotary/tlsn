//! This module handles the notarization phase of the prover.
//!
//! The prover deals with a TLS verifier that is only a notary.

use super::{state::Notarize, Prover, ProverError};
use serio::stream::IoStreamExt as _;
use tlsn_core::msg::SignedSession;
use tracing::{debug, instrument};

impl Prover<Notarize> {
    /// Finalizes the notarization returning a [`NotarizedSession`].
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub async fn finalize(self) -> Result<SignedSession, ProverError> {
        let Notarize {
            mut io,
            mux_ctrl,
            mut mux_fut,
            ..
        } = self.state;

        let signed_session = mux_fut
            .poll_with(async {
                debug!("starting finalization");

                let signed_session: SignedSession = io.expect_next().await?;

                Ok::<_, ProverError>(signed_session)
            })
            .await?;

        // Wait for the notary to correctly close the connection.
        if !mux_fut.is_complete() {
            mux_ctrl.mux().close();
            mux_fut.await?;
        }

        Ok(SignedSession::new(signed_session.application_data, signed_session.signature))
    }
}
