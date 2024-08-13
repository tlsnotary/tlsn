//! This module handles the proving phase of the prover.
//!
//! Here the prover deals with a verifier directly, so there is no notary involved. Instead
//! the verifier directly verifies parts of the transcript.

use super::{state::Prove as ProveState, Prover, ProverError};
use mpz_garble::{Memory, Prove};
use mpz_ot::VerifiableOTReceiver;
use serio::SinkExt as _;
use tlsn_core::{proof::SessionInfo, transcript::get_value_ids, Direction, ServerName, Transcript};
use utils::range::{RangeSet, RangeUnion};

use tracing::{info, instrument};

impl Prover<ProveState> {
    /// Reveal certain parts of the transcripts to the verifier
    ///
    /// This function allows to collect certain transcript ranges. When [Prover::prove] is called, these
    /// ranges will be opened to the verifier.
    ///
    /// # Arguments
    /// * `ranges` - The ranges of the transcript to reveal
    /// * `direction` - The direction of the transcript to reveal
    pub fn reveal(
        &mut self,
        ranges: impl Into<RangeSet<usize>>,
        direction: Direction,
    ) -> Result<(), ProverError> {
        Ok(())
    }

    /// Prove transcript values
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub async fn prove(&mut self) -> Result<(), ProverError> {
        Ok(())
    }

    /// Finalize the proving
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub async fn finalize(self) -> Result<(), ProverError> {
        let ProveState {
            mut io,
            mux_ctrl,
            mut mux_fut,
            mut ctx,
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
