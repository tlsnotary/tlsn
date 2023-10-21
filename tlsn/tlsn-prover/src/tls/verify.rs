//! This module handles the verification phase of the prover.
//!
//! The prover deals with a TLS verifier that is a notary and a verifier.

use super::{state::Verify, Prover, ProverError};
use futures::FutureExt;
use mpz_garble::{Decode, ValueRef, Vm};
use mpz_share_conversion::ShareConversionReveal;
use tlsn_core::{ServerName, SessionData, Transcript};
use utils_aio::mux::MuxChannel;

impl Prover<Verify> {
    /// Returns the transcript of the sent requests
    pub fn sent_transcript(&self) -> &Transcript {
        &self.state.transcript_tx
    }

    /// Returns the transcript of the received responses
    pub fn recv_transcript(&self) -> &Transcript {
        &self.state.transcript_rx
    }

    /// TODO: Returns the alternate `SubstringProofBuilder`
    ///
    /// This is a `SubstringProofBuilder` which works without commitments
    /// and lives somewhere in tlsn_core::proof::substrings
    pub fn proof_builder(&mut self) -> &mut () {
        todo!()
    }

    /// Finalize the verification
    pub async fn finalize(self) -> Result<(), ProverError> {
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

        let session_data = SessionData::new(
            ServerName::Dns(self.config.server_dns().to_string()),
            handshake_decommitment,
            transcript_tx,
            transcript_rx,
        );

        let mut verify_fut = Box::pin(async move {
            //let mut channel = notary_mux.get_channel("verify").await?;

            let new_vm_thread = vm.new_thread("verify").await?;

            // TODO:
            // - Get ValueRefs for the transcript parts we want to prove to the Verifier
            // - Get the corresponding values from the DEAPVM using `decode`
            // - Send the values to the verifier

            // let values = new_vm_thread.decode(ValueRef).await;

            // This is a temporary approach until a maliciously secure share conversion protocol is implemented.
            // The prover is essentially revealing the TLS MAC key. In some exotic scenarios this allows a malicious
            // TLS verifier to modify the prover's request.
            gf2.reveal()
                .await
                .map_err(|e| ProverError::MpcError(Box::new(e)))?;

            _ = vm
                .finalize()
                .await
                .map_err(|e| ProverError::MpcError(Box::new(e)))?
                .expect("encoder seed returned");

            Ok::<_, ProverError>(())
        })
        .fuse();

        todo!()
    }
}
