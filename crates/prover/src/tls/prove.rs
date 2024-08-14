//! This module handles the proving phase of the prover.
//!
//! Here the prover deals with a verifier directly, so there is no notary involved. Instead
//! the verifier directly verifies parts of the transcript.

use super::{state::Prove as ProveState, Prover, ProverError};

use tracing::instrument;

impl Prover<ProveState> {
    /// Prove transcript values
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub async fn prove(&mut self) -> Result<(), ProverError> {
        Ok(())
    }

    /// Finalize the proving
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub async fn finalize(self) -> Result<(), ProverError> {
        let ProveState {
            mux_ctrl,
            mux_fut,
            ..
        } = self.state;

        // Wait for the verifier to correctly close the connection.
        if !mux_fut.is_complete() {
            mux_ctrl.mux().close();
            mux_fut.await?;
        }

        Ok(())
    }
}
