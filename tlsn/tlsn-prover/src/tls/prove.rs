//! This module handles the proving phase of the prover.
//!
//! Here the prover deals with a verifier directly, so there is no notary involved. Instead
//! the verifier directly verifies parts of the transcript.

use super::{state::Prove as ProveState, Prover, ProverError};
use crate::tls::{convert_mpc_tls_data, error::OTShutdownError};
use futures::{FutureExt, SinkExt};
use mpz_garble::{Memory, Prove, Vm};
use mpz_share_conversion::ShareConversionReveal;
use tlsn_common::{
    msg::{ServerIdentityProof, SubstringProofData, TlsnMessage},
    util::get_subsequence_ids,
};
use tlsn_core::{
    conn::ServerIdentity, substring::SubstringProofConfigBuilder, transcript::Subsequence,
    Transcript,
};
use utils_aio::mux::MuxChannel;

#[cfg(feature = "tracing")]
use tracing::info;

impl Prover<ProveState> {
    /// Returns a reference to the transcript.
    pub fn transcript(&self) -> &Transcript {
        &self.state.transcript
    }

    /// Returns a mutable reference to the substring proof builder.
    pub fn substring_proof_builder(&mut self) -> &mut SubstringProofConfigBuilder {
        &mut self.state.substring_proof_builder
    }

    /// Prove transcript values
    pub async fn prove(&mut self) -> Result<(), ProverError> {
        let builder = std::mem::replace(
            &mut self.state.substring_proof_builder,
            SubstringProofConfigBuilder::new(&self.state.transcript),
        );

        let config = builder.build().unwrap();

        let proof_data = SubstringProofData {
            seqs: config
                .iter()
                .map(|idx| Subsequence {
                    idx: idx.clone(),
                    data: self
                        .state
                        .transcript
                        .get_subsequence(idx)
                        .expect("ranges were checked to be in bounds"),
                })
                .collect(),
        };

        let mut prove_fut = Box::pin(async {
            // Create a new channel and vm thread if not already present
            let channel = if let Some(ref mut channel) = self.state.channel {
                channel
            } else {
                self.state.channel = Some(self.state.mux_ctrl.get_channel("prove-verify").await?);
                self.state.channel.as_mut().unwrap()
            };

            let prove_thread = if let Some(ref mut prove_thread) = self.state.prove_thread {
                prove_thread
            } else {
                self.state.prove_thread = Some(self.state.vm.new_thread("prove-verify").await?);
                self.state.prove_thread.as_mut().unwrap()
            };

            // Send the proof data to the verifier
            channel
                .send(TlsnMessage::SubstringProofData(proof_data))
                .await?;

            #[cfg(feature = "tracing")]
            info!("Sent substring proof data to verifier");

            // Now prove the transcript parts which have been marked for reveal
            let subseq_refs = config
                .iter()
                .map(|idx| {
                    let byte_refs = get_subsequence_ids(idx)
                        .map(|id| {
                            prove_thread
                                .get_value(id.as_str())
                                .expect("Byte should be in VM memory")
                        })
                        .collect::<Vec<_>>();

                    prove_thread
                        .array_from_values(&byte_refs)
                        .expect("Byte should be in VM Memory")
                })
                .collect::<Vec<_>>();

            // Prove the subsequences.
            prove_thread.prove(&subseq_refs).await?;

            #[cfg(feature = "tracing")]
            info!("Successfully proved cleartext");

            Ok::<_, ProverError>(())
        })
        .fuse();

        futures::select_biased! {
            res = prove_fut => res?,
            _ = &mut self.state.ot_fut => return Err(OTShutdownError)?,
            _ = &mut self.state.mux_fut => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?,
        };

        Ok(())
    }

    /// Finalize the proving
    pub async fn finalize(self) -> Result<(), ProverError> {
        let ProveState {
            mut mux_ctrl,
            mut mux_fut,
            mut vm,
            mut ot_fut,
            mut gf2,
            mpc_tls_data,
            ..
        } = self.state;

        // Create session data and session_info
        let (_, cert_data) = convert_mpc_tls_data(mpc_tls_data);

        let mut finalize_fut = Box::pin(async move {
            let mut channel = mux_ctrl.get_channel("finalize").await?;

            _ = vm
                .finalize()
                .await
                .map_err(|e| ProverError::MpcError(Box::new(e)))?
                .expect("encoder seed returned");

            // This is a temporary approach until a maliciously secure share conversion protocol is implemented.
            // The prover is essentially revealing the TLS MAC key. In some exotic scenarios this allows a malicious
            // TLS verifier to modify the prover's request.
            gf2.reveal()
                .await
                .map_err(|e| ProverError::MpcError(Box::new(e)))?;

            // Send session_info to the verifier
            channel
                .send(TlsnMessage::ServerIdentityProof(ServerIdentityProof {
                    cert_data,
                    identity: ServerIdentity::new(self.config.server_dns().to_string()),
                }))
                .await?;

            Ok::<_, ProverError>(())
        })
        .fuse();

        futures::select_biased! {
            res = finalize_fut => res?,
            _ = ot_fut => return Err(OTShutdownError)?,
            _ = &mut mux_fut => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?,
        };

        // We need to wait for the verifier to correctly close the connection. Otherwise the prover
        // would rush ahead and close the connection before the verifier has finished.
        mux_fut.await?;
        Ok(())
    }
}
