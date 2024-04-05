//! This module handles the verification phase of the verifier.
//!
//! The TLS verifier is an application-specific verifier.

use futures::{FutureExt, StreamExt, TryFutureExt};
use mpz_circuits::types::Value;
use mpz_garble::{Memory, Verify, Vm};
use mpz_share_conversion::ShareConversionVerify;

use tlsn_common::{
    msg::{ServerIdentityProof, TlsnMessage},
    util::get_subsequence_ids,
};
use tlsn_core::{conn::ServerIdentity, Direction, PartialTranscript};
use utils_aio::{expect_msg_or_err, mux::MuxChannel};

use crate::tls::{convert_mpc_tls_data, state::Verify as VerifyState, Verifier, VerifierError};

#[cfg(feature = "tracing")]
use tracing::info;

impl Verifier<VerifyState> {
    /// Receives the **purported** transcript from the Prover.
    ///
    /// # Warning
    ///
    /// The content of the received transcripts can not be considered authentic until after finalization.
    pub async fn receive(&mut self) -> Result<PartialTranscript, VerifierError> {
        let verify_fut = async {
            // Create a new channel and vm thread if not already present
            let channel = if let Some(ref mut channel) = self.state.channel {
                channel
            } else {
                self.state.channel = Some(self.state.mux_ctrl.get_channel("prove-verify").await?);
                self.state.channel.as_mut().unwrap()
            };

            let verify_thread = if let Some(ref mut verify_thread) = self.state.verify_thread {
                verify_thread
            } else {
                self.state.verify_thread = Some(self.state.vm.new_thread("prove-verify").await?);
                self.state.verify_thread.as_mut().unwrap()
            };

            // Receive the proving info from the prover
            let proof_data = expect_msg_or_err!(channel, TlsnMessage::SubstringProofData)?;

            #[cfg(feature = "tracing")]
            info!("Received substring proof data from prover");

            // Check ranges
            if proof_data.seqs.iter().any(|seq| {
                if seq.idx.ranges.len() != seq.data.len() {
                    return true;
                }
                let Some(end) = seq.idx.ranges.end() else {
                    return true;
                };
                match seq.idx.direction {
                    Direction::Sent => end > self.state.mpc_tls_data.bytes_sent,
                    Direction::Received => end > self.state.mpc_tls_data.bytes_recv,
                }
            }) {
                return Err(VerifierError::InvalidRange);
            }

            // Now verify the transcript parts which the prover wants to reveal
            let (subseq_refs, subseqs): (Vec<_>, Vec<_>) = proof_data
                .seqs
                .clone()
                .into_iter()
                .map(|seq| {
                    let byte_refs = get_subsequence_ids(&seq.idx)
                        .map(|id| {
                            verify_thread
                                .get_value(id.as_str())
                                .expect("Byte should be in VM memory")
                        })
                        .collect::<Vec<_>>();

                    let subseq_refs = verify_thread
                        .array_from_values(&byte_refs)
                        .expect("Byte should be in VM Memory");

                    let subseq = Value::Array(seq.data.into_iter().map(Into::into).collect());

                    (subseq_refs, subseq)
                })
                .unzip();

            // Check that purported values are correct
            verify_thread.verify(&subseq_refs, &subseqs).await?;

            // Create redacted transcripts
            let mut transcript = PartialTranscript::new(
                self.state.mpc_tls_data.bytes_sent,
                self.state.mpc_tls_data.bytes_recv,
            );

            proof_data
                .seqs
                .iter()
                .for_each(|seq| transcript.union_subsequence(seq));

            Ok::<_, VerifierError>(transcript)
        };

        futures::select! {
            res = verify_fut.fuse() => res,
            _ = &mut self.state.mux_fut => Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?,
        }
    }

    /// Verify the TLS session.
    pub async fn finalize(self) -> Result<ServerIdentity, VerifierError> {
        let VerifyState {
            mut mux_ctrl,
            mut mux_fut,
            mut vm,
            ot_send,
            ot_recv,
            ot_fut,
            mut gf2,
            start_time,
            mpc_tls_data,
            ..
        } = self.state;

        let finalize_fut = async {
            let mut channel = mux_ctrl.get_channel("finalize").await?;

            // Finalize all MPC
            let (mut ot_sender_actor, _, _) = futures::try_join!(
                ot_fut,
                ot_send.shutdown().map_err(VerifierError::from),
                ot_recv.shutdown().map_err(VerifierError::from)
            )?;

            ot_sender_actor.reveal().await?;

            vm.finalize()
                .await
                .map_err(|e| VerifierError::MpcError(Box::new(e)))?;

            gf2.verify()
                .await
                .map_err(|e| VerifierError::MpcError(Box::new(e)))?;

            let server_identity_proof =
                expect_msg_or_err!(channel, TlsnMessage::ServerIdentityProof)?;

            #[cfg(feature = "tracing")]
            info!("Finalized all MPC");

            Ok::<_, VerifierError>(server_identity_proof)
        };

        let server_identity_proof = futures::select! {
            res = finalize_fut.fuse() => res?,
            _ = &mut mux_fut => Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?,
        };

        let (conn_info, handshake_data) = convert_mpc_tls_data(mpc_tls_data, start_time);

        // Verify the server identity.
        let ServerIdentityProof {
            cert_data,
            identity,
        } = server_identity_proof;

        cert_data
            .verify_with_verifier(
                &conn_info,
                &handshake_data,
                &identity,
                self.config.cert_verifier(),
            )
            .unwrap();

        #[cfg(feature = "tracing")]
        info!("Successfully verified session");

        let mut mux_ctrl = mux_ctrl.into_inner();

        futures::try_join!(mux_ctrl.close().map_err(VerifierError::from), mux_fut)?;

        Ok(identity)
    }
}
