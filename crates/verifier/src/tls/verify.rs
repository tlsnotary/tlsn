//! This module handles the verification phase of the verifier.
//!
//! The TLS verifier is an application-specific verifier.

use super::{state::Verify as VerifyState, Verifier, VerifierError};

use tracing::{info, instrument};

impl Verifier<VerifyState> {
    /// Receives the **purported** transcript from the Prover.
    ///
    /// # Warning
    ///
    /// The content of the received transcripts can not be considered authentic until after finalization.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn receive(&mut self) -> Result<(), VerifierError> {
        self.state
            .mux_fut
            .poll_with(async {
                info!("Successfully created redacted transcripts");

                Ok::<_, VerifierError>(())
            })
            .await
    }

    /// Verifies the TLS session.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn finalize(self) -> Result<(), VerifierError> {
        let VerifyState {
            mux_ctrl,
            mut mux_fut,
            ..
        } = self.state;

        let _session_info = mux_fut
            .poll_with(async {
                info!("Finalized all TEE");

                Ok::<_, VerifierError>(())
            })
            .await?;

        info!("Successfully verified session");

        if !mux_fut.is_complete() {
            mux_ctrl.mux().close();
            mux_fut.await?;
        }

        Ok(())
    }
}
