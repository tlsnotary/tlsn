//! This module handles the verification phase of the prover.
//!
//! Here the prover deals with a TLS verifier that is a notary and a verifier.

use super::{state::Verify, Prover, ProverError};
use crate::tls::error::OTShutdownError;
use futures::{FutureExt, SinkExt};
use mpz_garble::{value::ValueRef, Decode, Memory, Vm};
use mpz_share_conversion::ShareConversionReveal;
use tlsn_core::{
    msg::TlsnMessage,
    proof::substring::{LabelProof, LabelProofBuilder},
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
    pub fn proof_builder(&self) -> LabelProofBuilder {
        LabelProofBuilder::new(
            self.sent_transcript().data().len(),
            "tx",
            self.recv_transcript().data().len(),
            "rx",
        )
    }

    /// Finalize the verification
    pub async fn finalize(self, label_proof: LabelProof) -> Result<SessionData, ProverError> {
        let Verify {
            mut verify_mux,
            mut mux_fut,
            mut vm,
            mut ot_fut,
            mut gf2,
            handshake_decommitment,
            transcript_tx,
            transcript_rx,
        } = self.state;

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

            let mut decode_thread = vm.new_thread("decode").await?;

            // Get the decoded value refs from the DEAP vm
            let value_refs = label_proof
                .iter_ids()
                .map(|id| {
                    decode_thread
                        .get_value(id.as_str())
                        .ok_or(ProverError::from(
                            "Transcript value cannot be decoded from VM thread",
                        ))
                })
                .collect::<Result<Vec<ValueRef>, ProverError>>()?;

            // Send the ids to the verifier so that he can also create the corresponding value refs
            channel
                .send(TlsnMessage::DecodingInfo(label_proof.into()))
                .await?;

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
