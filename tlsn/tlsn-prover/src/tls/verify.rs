//! This module handles the verification phase of the prover.
//!
//! Here the prover deals with a TLS verifier that is a notary and a verifier.

use super::{state::Verify, Prover, ProverError};
use crate::tls::error::OTShutdownError;
use futures::{FutureExt, SinkExt};
use mpz_garble::{value::ValueRef, Decode, Memory, Vm};
use mpz_share_conversion::ShareConversionReveal;
use tlsn_core::{
    msg::{DecodingInfo, TlsnMessage},
    proof::substring::LabelProofBuilder,
    ServerName, SessionData, Transcript,
};
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

    /// Returns the label proof builder
    pub fn proof_builder(&mut self) -> &mut LabelProofBuilder {
        &mut self.state.proof_builder
    }

    /// Finalize the verification
    pub async fn finalize(self) -> Result<SessionData, ProverError> {
        let Verify {
            mut verify_mux,
            mut mux_fut,
            mut vm,
            mut ot_fut,
            mut gf2,
            handshake_decommitment,
            transcript_tx,
            transcript_rx,
            proof_builder,
        } = self.state;

        // Get the transcript parts which are to be revealed
        let (tx_reveal, rx_reveal) = proof_builder.build();

        // TODO: Remove these hard-coded `transcript_id`s
        let tx_ids = tx_reveal.iter().map(|id| format!("tx/{id}"));
        let rx_ids = rx_reveal.iter().map(|id| format!("rx/{id}"));

        // Create session data and tls_info
        let session_data = SessionData::new(
            ServerName::Dns(self.config.server_dns().to_string()),
            handshake_decommitment,
            transcript_tx,
            transcript_rx,
        );
        let tls_info = session_data.build_tls_info();

        let mut verify_fut = Box::pin(async move {
            let mut channel = verify_mux.get_channel("verify").await?;

            let mut decode_thread = vm.new_thread("cleartext_values").await?;
            let ids = tx_ids.chain(rx_ids).collect::<Vec<String>>();
            let decoding_info = DecodingInfo { ids: ids.clone() };

            // Send the ids to the verifier so that he can also create the corresponding value refs
            channel
                .send(TlsnMessage::DecodingInfo(decoding_info))
                .await?;

            // Get the decoded value refs from the DEAP vm
            let value_refs = ids
                .iter()
                .map(|id| {
                    decode_thread
                        .get_value(id.as_ref())
                        .ok_or(ProverError::TranscriptDecodeError)
                })
                .collect::<Result<Vec<ValueRef>, ProverError>>()?;

            // Decode the corresponding values
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

            // Send tls_info to the verifier
            channel.send(TlsnMessage::TlsInfo(tls_info)).await?;

            Ok::<_, ProverError>(values)
        })
        .fuse();

        let _ = futures::select_biased! {
            res = verify_fut => res?,
            _ = ot_fut => return Err(OTShutdownError)?,
            _ = mux_fut => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?,
        };

        Ok(session_data)
    }
}
