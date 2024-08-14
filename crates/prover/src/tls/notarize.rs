//! This module handles the notarization phase of the prover.
//!
//! The prover deals with a TLS verifier that is only a notary.

use super::{state::Notarize, Prover, ProverError};
use tracing::instrument;

impl Prover<Notarize> {
    /// Finalizes the notarization returning a [`NotarizedSession`].
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub async fn finalize(self) -> Result<(), ProverError> {
        let Notarize {
            mux_ctrl, mux_fut, ..
        } = self.state;

        // Wait for the notary to correctly close the connection.
        if !mux_fut.is_complete() {
            mux_ctrl.mux().close();
            mux_fut.await?;
        }

        Ok(())
    }
}
