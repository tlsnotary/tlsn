//! This module handles the proving phase of the prover.
//!
//! Here the prover deals with a verifier directly, so there is no notary
//! involved. Instead the verifier directly verifies parts of the transcript.

use super::{state::Prove as ProveState, Prover, ProverError};
use mpz_garble::{Memory, Prove};
use mpz_ot::VerifiableOTReceiver;
use serio::SinkExt as _;
use tlsn_common::msg::ServerIdentityProof;
use tlsn_core::transcript::{get_value_ids, Direction, Idx, Transcript};

use tracing::{info, instrument};

impl Prover<ProveState> {
    /// Returns the transcript.
    pub fn transcript(&self) -> &Transcript {
        &self.state.transcript
    }

    /// Prove subsequences in the transcript to the verifier.
    ///
    /// # Arguments
    ///
    /// * `sent` - Indices of the sent data.
    /// * `recv` - Indices of the received data.
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub async fn prove_transcript(&mut self, sent: Idx, recv: Idx) -> Result<(), ProverError> {
        let partial_transcript = self.transcript().to_partial(sent.clone(), recv.clone());

        let sent_value_ids = get_value_ids(Direction::Sent, &sent);
        let recv_value_ids = get_value_ids(Direction::Received, &recv);

        let value_refs = sent_value_ids
            .chain(recv_value_ids)
            .map(|id| {
                self.state
                    .vm
                    .get_value(id.as_str())
                    .expect("Byte should be in VM memory")
            })
            .collect::<Vec<_>>();

        self.state
            .mux_fut
            .poll_with(async {
                // Send the partial transcript to the verifier.
                self.state.io.send(partial_transcript).await?;

                info!("Sent partial transcript");

                // Prove the partial transcript to the verifier.
                self.state.vm.prove(value_refs.as_slice()).await?;

                info!("Proved partial transcript");

                Ok::<_, ProverError>(())
            })
            .await?;

        Ok(())
    }

    /// Finalize the proving
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub async fn finalize(self) -> Result<(), ProverError> {
        let ProveState {
            mut io,
            mux_ctrl,
            mut mux_fut,
            mut vm,
            mut ot_recv,
            mut ctx,
            server_cert_data,
            ..
        } = self.state;

        mux_fut
            .poll_with(async move {
                ot_recv.accept_reveal(&mut ctx).await?;

                vm.finalize().await?;

                // Send identity proof to the verifier
                io.send(ServerIdentityProof {
                    name: self.config.server_name().clone(),
                    data: server_cert_data,
                })
                .await?;

                Ok::<_, ProverError>(())
            })
            .await?;

        // Wait for the verifier to correctly close the connection.
        if !mux_fut.is_complete() {
            mux_ctrl.mux().close();
            mux_fut.await?;
        }

        Ok(())
    }
}
