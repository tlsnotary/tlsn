//! This module handles the verification phase of the verifier.
//!
//! The TLS verifier is an application-specific verifier.

use super::{state::Verify as VerifyState, Verifier, VerifierError};
use futures::{FutureExt, StreamExt, TryFutureExt};
use mpz_circuits::types::Value;
use mpz_garble::{Memory, Verify, Vm};
use mpz_share_conversion::ShareConversionVerify;
use tlsn_core::{
    msg::TlsnMessage, proof::SessionInfo, transcript::get_value_ids, Direction, HandshakeSummary,
    RedactedTranscript, TranscriptSlice,
};
use utils_aio::{expect_msg_or_err, mux::MuxChannel};

#[cfg(feature = "tracing")]
use tracing::info;

impl Verifier<VerifyState> {
    /// Receives the **purported** transcript from the Prover.
    ///
    /// # Warning
    ///
    /// The content of the received transcripts can not be considered authentic until after finalization.
    pub async fn receive(
        &mut self,
    ) -> Result<(RedactedTranscript, RedactedTranscript), VerifierError> {
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
            let mut proving_info = expect_msg_or_err!(channel, TlsnMessage::ProvingInfo)?;
            let mut cleartext = proving_info.cleartext.clone();

            #[cfg(feature = "tracing")]
            info!("Received proving info from prover");

            // Check ranges
            if proving_info.sent_ids.max().unwrap_or_default() > self.state.sent_len
                || proving_info.recv_ids.max().unwrap_or_default() > self.state.recv_len
            {
                return Err(VerifierError::InvalidRange);
            }

            // Now verify the transcript parts which the prover wants to reveal
            let sent_value_ids = proving_info
                .sent_ids
                .iter_ranges()
                .map(|r| get_value_ids(&r.into(), Direction::Sent).collect::<Vec<String>>());
            let recv_value_ids = proving_info
                .recv_ids
                .iter_ranges()
                .map(|r| get_value_ids(&r.into(), Direction::Received).collect::<Vec<String>>());

            let value_refs = sent_value_ids
                .chain(recv_value_ids)
                .map(|ids| {
                    let inner_refs = ids
                        .iter()
                        .map(|id| {
                            verify_thread
                                .get_value(id.as_str())
                                .expect("Byte should be in VM memory")
                        })
                        .collect::<Vec<_>>();

                    verify_thread
                        .array_from_values(inner_refs.as_slice())
                        .expect("Byte should be in VM Memory")
                })
                .collect::<Vec<_>>();

            let values = proving_info
                .sent_ids
                .iter_ranges()
                .chain(proving_info.recv_ids.iter_ranges())
                .map(|range| {
                    Value::Array(cleartext.drain(..range.len()).map(|b| (b).into()).collect())
                })
                .collect::<Vec<_>>();

            // Check that purported values are correct
            verify_thread.verify(&value_refs, &values).await?;

            #[cfg(feature = "tracing")]
            info!("Successfully verified purported cleartext");

            // Create redacted transcripts
            let mut transcripts = proving_info
                .sent_ids
                .iter_ranges()
                .chain(proving_info.recv_ids.iter_ranges())
                .map(|range| {
                    TranscriptSlice::new(
                        range.clone(),
                        proving_info.cleartext.drain(..range.len()).collect(),
                    )
                })
                .collect::<Vec<_>>();

            let recv_transcripts =
                transcripts.split_off(proving_info.sent_ids.iter_ranges().count());
            let (sent_redacted, recv_redacted) = (
                RedactedTranscript::new(self.state.sent_len, transcripts),
                RedactedTranscript::new(self.state.recv_len, recv_transcripts),
            );

            #[cfg(feature = "tracing")]
            info!("Successfully created redacted transcripts");

            Ok::<_, VerifierError>((sent_redacted, recv_redacted))
        };

        futures::select! {
            res = verify_fut.fuse() => res,
            _ = &mut self.state.mux_fut => Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?,
        }
    }

    /// Verify the TLS session.
    pub async fn finalize(self) -> Result<SessionInfo, VerifierError> {
        let VerifyState {
            mux_ctrl: mut mux,
            mut mux_fut,
            mut vm,
            ot_send,
            ot_recv,
            ot_fut,
            mut gf2,
            start_time,
            server_ephemeral_key,
            handshake_commitment,
            ..
        } = self.state;

        let finalize_fut = async {
            let mut channel = mux.get_channel("finalize").await?;

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

            let session_info = expect_msg_or_err!(channel, TlsnMessage::SessionInfo)?;

            #[cfg(feature = "tracing")]
            info!("Finalized all MPC");

            Ok::<_, VerifierError>(session_info)
        };

        let session_info = futures::select! {
            res = finalize_fut.fuse() => res?,
            _ = &mut mux_fut => Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?,
        };

        let handshake_summary =
            HandshakeSummary::new(start_time, server_ephemeral_key, handshake_commitment);

        // Verify the TLS session
        session_info.verify(&handshake_summary, self.config.cert_verifier())?;

        #[cfg(feature = "tracing")]
        info!("Successfully verified session");

        let mut mux = mux.into_inner();

        futures::try_join!(mux.close().map_err(VerifierError::from), mux_fut)?;

        Ok(session_info)
    }
}
