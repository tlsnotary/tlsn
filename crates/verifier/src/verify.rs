//! This module handles the verification phase of the verifier.
//!
//! The TLS verifier is an application-specific verifier.

use crate::SessionInfo;

use super::{state::Verify as VerifyState, Verifier, VerifierError};
use mpz_circuits::types::Value;
use mpz_garble::{Memory, Verify};
use mpz_ot::CommittedOTSender;
use serio::stream::IoStreamExt;
use tlsn_common::msg::ServerIdentityProof;
use tlsn_core::transcript::{get_value_ids, Direction, PartialTranscript};

use tracing::{info, instrument};

impl Verifier<VerifyState> {
    /// Receives the **purported** transcript from the Prover.
    ///
    /// # Warning
    ///
    /// The content of the received transcripts can not be considered authentic
    /// until after finalization.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn receive(&mut self) -> Result<PartialTranscript, VerifierError> {
        self.state
            .mux_fut
            .poll_with(async {
                // Receive partial transcript from the prover
                let partial_transcript: PartialTranscript = self.state.io.expect_next().await?;

                info!("Received partial transcript from prover");

                // Check ranges
                if partial_transcript.len_sent()
                    != self.state.connection_info.transcript_length.sent as usize
                    || partial_transcript.len_received()
                        != self.state.connection_info.transcript_length.received as usize
                {
                    return Err(VerifierError::verify(
                        "prover sent transcript with incorrect length",
                    ));
                }

                // Now verify the transcript parts which the prover wants to reveal
                let sent_value_ids =
                    get_value_ids(Direction::Sent, partial_transcript.sent_authed());
                let recv_value_ids =
                    get_value_ids(Direction::Received, partial_transcript.received_authed());

                let value_refs = sent_value_ids
                    .chain(recv_value_ids)
                    .map(|id| {
                        self.state
                            .vm
                            .get_value(id.as_str())
                            .expect("Byte should be in VM memory")
                    })
                    .collect::<Vec<_>>();

                let values = partial_transcript
                    .iter(Direction::Sent)
                    .chain(partial_transcript.iter(Direction::Received))
                    .map(Value::U8)
                    .collect::<Vec<_>>();

                // Check that purported values are correct
                self.state.vm.verify(&value_refs, &values).await?;

                info!("Successfully verified purported cleartext");

                Ok::<_, VerifierError>(partial_transcript)
            })
            .await
    }

    /// Verifies the TLS session.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn finalize(self) -> Result<SessionInfo, VerifierError> {
        let VerifyState {
            mut io,
            mux_ctrl,
            mut mux_fut,
            mut vm,
            mut ot_send,
            mut ctx,
            server_ephemeral_key,
            connection_info,
            ..
        } = self.state;

        let ServerIdentityProof {
            name: server_name,
            data,
        } = mux_fut
            .poll_with(async {
                // Finalize all MPC
                ot_send.reveal(&mut ctx).await?;

                vm.finalize().await?;

                info!("Finalized all MPC");

                let identity_proof: ServerIdentityProof = io.expect_next().await?;

                Ok::<_, VerifierError>(identity_proof)
            })
            .await?;

        // Verify the server identity data.
        data.verify_with_provider(
            self.config.crypto_provider(),
            connection_info.time,
            &server_ephemeral_key,
            &server_name,
        )
        .map_err(VerifierError::verify)?;

        info!("Successfully verified session");

        if !mux_fut.is_complete() {
            mux_ctrl.mux().close();
            mux_fut.await?;
        }

        Ok(SessionInfo {
            server_name,
            connection_info,
        })
    }
}
