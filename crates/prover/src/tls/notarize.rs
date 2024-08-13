//! This module handles the notarization phase of the prover.
//!
//! The prover deals with a TLS verifier that is only a notary.

use super::{state::Notarize, Prover, ProverError};
use mpz_ot::VerifiableOTReceiver;
use serio::{stream::IoStreamExt as _, SinkExt as _};
use tlsn_core::{
    commitment::TranscriptCommitmentBuilder, msg::SignedSessionHeader, transcript::Transcript,
    NotarizedSession, ServerName, SessionData,
};
use tracing::{debug, instrument};

impl Prover<Notarize> {
    /// Returns the transcript of the sent data.
    // pub fn sent_transcript(&self) -> &Transcript {
    //     &self.state.transcript_tx
    // }

    // /// Returns the transcript of the received data.
    // pub fn recv_transcript(&self) -> &Transcript {
    //     &self.state.transcript_rx
    // }

    // /// Returns the transcript commitment builder.
    // pub fn commitment_builder(&mut self) -> &mut TranscriptCommitmentBuilder {
    //     &mut self.state.builder
    // }

    /// Finalizes the notarization returning a [`NotarizedSession`].
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub async fn finalize(self) -> Result<(), ProverError> {
        let Notarize {
            mut io,
            mux_ctrl,
            mut mux_fut,
            mut ctx,
            start_time,
        } = self.state;

        // Wait for the notary to correctly close the connection.
        if !mux_fut.is_complete() {
            mux_ctrl.mux().close();
            mux_fut.await?;
        }

        Ok(())
    }
}
