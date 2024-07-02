//! This module handles the verification phase of the verifier.
//!
//! The TLS verifier is an application-specific verifier.

use super::{state::Verify as VerifyState, Verifier, VerifierError};
use mpz_circuits::types::Value;
use mpz_garble::{Memory, Verify};
use mpz_ot::CommittedOTSender;
use serio::stream::IoStreamExt;
use tlsn_core::{
    msg::ProvingInfo, proof::SessionInfo, transcript::get_value_ids, Direction, HandshakeSummary,
    RedactedTranscript, TranscriptSlice,
};

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
        self.state
            .mux_fut
            .poll_with(async {
                // Receive the proving info from the prover
                let mut proving_info: ProvingInfo = self.state.io.expect_next().await?;
                let mut cleartext = proving_info.cleartext.clone();

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
                let recv_value_ids = proving_info.recv_ids.iter_ranges().map(|r| {
                    get_value_ids(&r.into(), Direction::Received).collect::<Vec<String>>()
                });

                let value_refs = sent_value_ids
                    .chain(recv_value_ids)
                    .map(|ids| {
                        let inner_refs = ids
                            .iter()
                            .map(|id| {
                                self.state
                                    .vm
                                    .get_value(id.as_str())
                                    .expect("Byte should be in VM memory")
                            })
                            .collect::<Vec<_>>();

                        self.state
                            .vm
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
                self.state.vm.verify(&value_refs, &values).await?;

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

                info!("Successfully created redacted transcripts");

                Ok::<_, VerifierError>((sent_redacted, recv_redacted))
            })
            .await
    }

    /// Verifies the TLS session.
    pub async fn finalize(self) -> Result<SessionInfo, VerifierError> {
        let VerifyState {
            mut io,
            mux_ctrl,
            mut mux_fut,
            mut vm,
            mut ot_send,
            mut ctx,
            start_time,
            server_ephemeral_key,
            handshake_commitment,
            ..
        } = self.state;

        let session_info = mux_fut
            .poll_with(async {
                // Finalize all MPC
                ot_send.reveal(&mut ctx).await?;

                vm.finalize()
                    .await
                    .map_err(|e| VerifierError::MpcError(Box::new(e)))?;

                let session_info: SessionInfo = io.expect_next().await?;

                info!("Finalized all MPC");

                Ok::<_, VerifierError>(session_info)
            })
            .await?;

        let handshake_summary =
            HandshakeSummary::new(start_time, server_ephemeral_key, handshake_commitment);

        // Verify the TLS session
        session_info.verify(&handshake_summary, self.config.cert_verifier())?;

        info!("Successfully verified session");

        if !mux_fut.is_complete() {
            mux_ctrl.mux().close();
            mux_fut.await?;
        }

        Ok(session_info)
    }
}
