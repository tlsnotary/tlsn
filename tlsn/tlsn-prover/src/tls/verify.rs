//! This module handles the verification phase of the prover.
//!
//! The prover deals with a TLS verifier that is a notary and a verifier.

use super::{state::Verify, Prover, ProverError};
use tlsn_core::Transcript;

impl Prover<Verify> {
    /// Returns the transcript of the sent requests
    pub fn sent_transcript(&self) -> &Transcript {
        &self.state.transcript_tx
    }

    /// Returns the transcript of the received responses
    pub fn recv_transcript(&self) -> &Transcript {
        &self.state.transcript_rx
    }

    /// Finalize the verification
    pub fn finalize(self) -> Result<(), ProverError> {
        let Verify {
            mut notary_mux,
            mut mux_fut,
            mut vm,
            mut ot_fut,
            mut gf2,
            start_time,
            handshake_decommitment,
            server_public_key,
            transcript_tx,
            transcript_rx,
        } = self.state;

        // TODO: Have a session_data struct without commitments
        //        let session_data = SessionData::new(
        //            ServerName::Dns(self.config.server_dns().to_string()),
        //            handshake_decommitment,
        //            transcript_tx,
        //            transcript_rx,
        //        );
        todo!()
    }
}
