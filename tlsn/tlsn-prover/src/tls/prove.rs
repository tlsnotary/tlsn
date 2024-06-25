//! This module handles the proving phase of the prover.
//!
//! Here the prover deals with a verifier directly, so there is no notary involved. Instead
//! the verifier directly verifies parts of the transcript.

use super::{state::Prove as ProveState, Prover, ProverError};
use mpz_garble::{Memory, Prove};
use mpz_ot::VerifiableOTReceiver;
use serio::SinkExt as _;
use tlsn_core::{proof::SessionInfo, transcript::get_value_ids, Direction, ServerName, Transcript};
use utils::range::{RangeSet, RangeUnion};

use tracing::{info, instrument};

impl Prover<ProveState> {
    /// Returns the transcript of the sent requests
    pub fn sent_transcript(&self) -> &Transcript {
        &self.state.transcript_tx
    }

    /// Returns the transcript of the received responses
    pub fn recv_transcript(&self) -> &Transcript {
        &self.state.transcript_rx
    }

    /// Reveal certain parts of the transcripts to the verifier
    ///
    /// This function allows to collect certain transcript ranges. When [Prover::prove] is called, these
    /// ranges will be opened to the verifier.
    ///
    /// # Arguments
    /// * `ranges` - The ranges of the transcript to reveal
    /// * `direction` - The direction of the transcript to reveal
    pub fn reveal(
        &mut self,
        ranges: impl Into<RangeSet<usize>>,
        direction: Direction,
    ) -> Result<(), ProverError> {
        let sent_ids = &mut self.state.proving_info.sent_ids;
        let recv_ids = &mut self.state.proving_info.recv_ids;

        let range_set = ranges.into();

        // Check ranges
        let transcript = match direction {
            Direction::Sent => &self.state.transcript_tx,
            Direction::Received => &self.state.transcript_rx,
        };

        if range_set.max().unwrap_or_default() > transcript.data().len() {
            return Err(ProverError::InvalidRange);
        }

        match direction {
            Direction::Sent => *sent_ids = sent_ids.union(&range_set),
            Direction::Received => *recv_ids = recv_ids.union(&range_set),
        }

        Ok(())
    }

    /// Prove transcript values
    #[instrument(level = "debug", skip_all, err)]
    pub async fn prove(&mut self) -> Result<(), ProverError> {
        let mut proving_info = std::mem::take(&mut self.state.proving_info);

        self.state
            .mux_fut
            .poll_with(async {
                // Now prove the transcript parts which have been marked for reveal
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

                // Extract cleartext we want to reveal from transcripts
                let mut cleartext =
                    Vec::with_capacity(proving_info.sent_ids.len() + proving_info.recv_ids.len());
                proving_info
                    .sent_ids
                    .iter_ranges()
                    .for_each(|r| cleartext.extend_from_slice(&self.state.transcript_tx.data()[r]));
                proving_info
                    .recv_ids
                    .iter_ranges()
                    .for_each(|r| cleartext.extend_from_slice(&self.state.transcript_rx.data()[r]));
                proving_info.cleartext = cleartext;

                // Send the proving info to the verifier
                self.state.io.send(proving_info).await?;

                info!("Sent proving info to verifier");

                // Prove the revealed transcript parts
                self.state.vm.prove(value_refs.as_slice()).await?;

                info!("Successfully proved cleartext");

                Ok::<_, ProverError>(())
            })
            .await?;

        Ok(())
    }

    /// Finalize the proving
    #[instrument(level = "debug", skip_all, err)]
    pub async fn finalize(self) -> Result<(), ProverError> {
        let ProveState {
            mut io,
            mux_ctrl,
            mut mux_fut,
            mut vm,
            mut ot_recv,
            mut ctx,
            handshake_decommitment,
            ..
        } = self.state;

        // Create session info.
        let session_info = SessionInfo {
            server_name: ServerName::Dns(self.config.server_dns().to_string()),
            handshake_decommitment,
        };

        mux_fut
            .poll_with(async move {
                ot_recv.accept_reveal(&mut ctx).await?;

                _ = vm
                    .finalize()
                    .await
                    .map_err(|e| ProverError::MpcError(Box::new(e)))?
                    .expect("encoder seed returned");

                // Send session_info to the verifier
                io.send(session_info).await?;

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
