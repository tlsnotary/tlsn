//! This module handles the verification phase of the verifier.
//!
//! The TLS verifier is an application-specific verifier.

use crate::SessionInfo;

use super::{state::Verify as VerifyState, Verifier, VerifierError};
use mpz_memory_core::MemoryExt;
use mpz_vm_core::Execute;
use serio::stream::IoStreamExt;
use tlsn_common::msg::ServerIdentityProof;
use tlsn_core::transcript::{Direction, PartialTranscript};

use tracing::{info, instrument};

impl Verifier<VerifyState> {
    /// Receives the **purported** transcript from the Prover.
    ///
    /// # Warning
    ///
    /// The content of the received transcript can not be considered authentic
    /// until after finalization.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn receive(&mut self) -> Result<PartialTranscript, VerifierError> {
        self.state
            .mux_fut
            .poll_with(async {
                // Receive partial transcript from the prover.
                let partial_transcript: PartialTranscript =
                    self.state.ctx.io_mut().expect_next().await?;

                info!("Received partial transcript from prover");

                // Check ranges.
                if partial_transcript.len_sent()
                    != self.state.connection_info.transcript_length.sent as usize
                    || partial_transcript.len_received()
                        != self.state.connection_info.transcript_length.received as usize
                {
                    return Err(VerifierError::verify(
                        "prover sent transcript with incorrect length",
                    ));
                }

                // Now verify the transcript parts which the prover wants to reveal.
                let sent_refs = self
                    .state
                    .transcript_refs
                    .get(Direction::Sent, partial_transcript.sent_authed())
                    .expect("index is in bounds");
                let recv_refs = self
                    .state
                    .transcript_refs
                    .get(Direction::Received, partial_transcript.received_authed())
                    .expect("index is in bounds");

                let plaintext_futs = sent_refs
                    .into_iter()
                    .chain(recv_refs)
                    .map(|slice| self.state.vm.decode(slice).map_err(VerifierError::zk))
                    .collect::<Result<Vec<_>, _>>()?;

                self.state.vm.flush(&mut self.state.ctx).await.unwrap();

                let mut purported_data = Vec::new();
                for mut fut in plaintext_futs {
                    let plaintext = fut
                        .try_recv()
                        .map_err(VerifierError::zk)?
                        .expect("plaintext should be decoded");
                    purported_data.extend_from_slice(&plaintext);
                }

                // Check that purported values are correct.
                if purported_data
                    .into_iter()
                    .zip(
                        partial_transcript
                            .iter(Direction::Sent)
                            .chain(partial_transcript.iter(Direction::Received)),
                    )
                    .any(|(a, b)| a != b)
                {
                    return Err(VerifierError::verify("purported transcript is incorrect"));
                }

                info!("Successfully verified purported transcript");

                Ok::<_, VerifierError>(partial_transcript)
            })
            .await
    }

    /// Verifies the TLS session.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn finalize(self) -> Result<SessionInfo, VerifierError> {
        let VerifyState {
            mux_ctrl,
            mut mux_fut,
            mut ctx,
            server_ephemeral_key,
            connection_info,
            ..
        } = self.state;

        let ServerIdentityProof {
            name: server_name,
            data,
        } = mux_fut.poll_with(ctx.io_mut().expect_next()).await?;

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
            mux_ctrl.close();
            mux_fut.await?;
        }

        Ok(SessionInfo {
            server_name,
            connection_info,
        })
    }
}
