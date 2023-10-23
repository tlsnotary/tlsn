//! This module handles the verification phase of the prover.
//!
//! The prover deals with a TLS verifier that is a notary and a verifier.

use crate::tls::error::OTShutdownError;

use super::{state::Verify, Prover, ProverError};
use futures::FutureExt;
use mpz_garble::{Decode, Memory, Thread, ValueRef, Vm};
use mpz_share_conversion::ShareConversionReveal;
use tlsn_core::{proof::DirectSubstringsProofBuilder, ServerName, SessionData, Transcript};
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
    pub fn proof_builder(&mut self) -> &mut DirectSubstringsProofBuilder {
        &mut self.state.proof_builder
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
            proof_builder,
        } = self.state;

        let session_data = SessionData::new(
            ServerName::Dns(self.config.server_dns().to_string()),
            handshake_decommitment,
            transcript_tx,
            transcript_rx,
        );

        // Collect server information
        let server_info = session_data.server_info();

        // Get the transcript parts to be revealed
        let (tx_reveal, rx_reveal) = proof_builder.build();
        let tx_ids = tx_reveal.iter().map(|id| format!("tx/{id}"));
        let rx_ids = rx_reveal.iter().map(|id| format!("rx/{id}"));
        let ids = tx_ids.chain(rx_ids).collect::<Vec<_>>();

        let mut verify_fut = Box::pin(async move {
            let decode_thread = vm.new_thread("cleartext_values").await?;
            let value_refs = tx_ids
                .chain(rx_ids)
                .map(|id| {
                    decode_thread
                        .get_value(id.as_ref())
                        .ok_or(ProverError::TranscriptDecodeError)
                })
                .collect::<Result<Vec<ValueRef>, ProverError>>()?;
            let values = decode_thread.decode(value_refs.as_slice()).await?;

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

            Ok::<_, ProverError>(values)
        })
        .fuse();

        let values = futures::select_biased! {
            res = verify_fut => res?,
            _ = ot_fut => return Err(OTShutdownError)?,
            _ = mux_fut => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?,
        };

        todo!()
    }
}
