//! This module handles the proving phase of the prover.
//!
//! The prover interacts with a TLS verifier directly, without involving a
//! Notary. The verifier verifies transcript data.

use mpz_memory_core::MemoryExt;
use mpz_vm_core::Execute;
use serio::SinkExt as _;
use tlsn_common::msg::ServerIdentityProof;
use tlsn_core::transcript::{Direction, Idx, Transcript};
use tracing::{info, instrument};

use crate::{state::Prove as ProveState, Prover, ProverError};

impl Prover<ProveState> {
    /// Returns the transcript.
    pub fn transcript(&self) -> &Transcript {
        &self.state.transcript
    }

    /// Proves subsequences in the transcript to the verifier.
    ///
    /// # Arguments
    ///
    /// * `sent` - Indices of the sent data.
    /// * `recv` - Indices of the received data.
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub async fn prove_transcript(&mut self, sent: Idx, recv: Idx) -> Result<(), ProverError> {
        let partial_transcript = self.transcript().to_partial(sent.clone(), recv.clone());

        let sent_refs = self
            .state
            .transcript_refs
            .get(Direction::Sent, &sent)
            .expect("index is in bounds");
        let recv_refs = self
            .state
            .transcript_refs
            .get(Direction::Received, &recv)
            .expect("index is in bounds");

        for slice in sent_refs.into_iter().chain(recv_refs) {
            let _ = self.state.vm.decode(slice).map_err(ProverError::zk)?;
        }

        self.state
            .mux_fut
            .poll_with(async {
                // Send the partial transcript to the verifier.
                self.state.ctx.io_mut().send(partial_transcript).await?;

                info!("Sent partial transcript");

                // Prove the partial transcript to the verifier.
                self.state
                    .vm
                    .flush(&mut self.state.ctx)
                    .await
                    .map_err(ProverError::zk)?;

                info!("Proved partial transcript");

                Ok::<_, ProverError>(())
            })
            .await?;

        Ok(())
    }

    /// Finalizes the proving.
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub async fn finalize(self) -> Result<(), ProverError> {
        let ProveState {
            mux_ctrl,
            mut mux_fut,
            mut ctx,
            server_cert_data,
            ..
        } = self.state;

        mux_fut
            .poll_with(async move {
                // Send identity proof to the verifier.
                ctx.io_mut()
                    .send(ServerIdentityProof {
                        name: self.config.server_name().clone(),
                        data: server_cert_data,
                    })
                    .await?;

                Ok::<_, ProverError>(())
            })
            .await?;

        // Wait for the verifier to correctly close the connection.
        if !mux_fut.is_complete() {
            mux_ctrl.close();
            mux_fut.await?;
        }

        Ok(())
    }
}
