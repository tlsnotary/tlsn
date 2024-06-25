//! This module handles the notarization phase of the prover.
//!
//! The prover deals with a TLS verifier that is only a notary.

use super::{state::Notarize, Prover, ProverError};
use mpz_ot::VerifiableOTReceiver;
use serio::{stream::IoStreamExt as _, SinkExt as _};
use tlsn_core::{
    commitment::TranscriptCommitmentBuilder, msg::SignedSessionHeader, transcript::Transcript,
    NotarizedSession, ServerName, SessionData,
};
use tracing::{debug, instrument};

impl Prover<Notarize> {
    /// Returns the transcript of the sent data.
    pub fn sent_transcript(&self) -> &Transcript {
        &self.state.transcript_tx
    }

    /// Returns the transcript of the received data.
    pub fn recv_transcript(&self) -> &Transcript {
        &self.state.transcript_rx
    }

    /// Returns the transcript commitment builder.
    pub fn commitment_builder(&mut self) -> &mut TranscriptCommitmentBuilder {
        &mut self.state.builder
    }

    /// Finalizes the notarization returning a [`NotarizedSession`].
    #[instrument(level = "debug", skip_all, err)]
    pub async fn finalize(self) -> Result<NotarizedSession, ProverError> {
        let Notarize {
            mut io,
            mux_ctrl,
            mut mux_fut,
            mut vm,
            mut ot_recv,
            mut ctx,
            start_time,
            handshake_decommitment,
            server_public_key,
            transcript_tx,
            transcript_rx,
            builder,
        } = self.state;

        let commitments = builder.build()?;

        let session_data = SessionData::new(
            ServerName::Dns(self.config.server_dns().to_string()),
            handshake_decommitment,
            transcript_tx,
            transcript_rx,
            commitments,
        );

        let merkle_root = session_data.commitments().merkle_root();

        let (notary_encoder_seed, SignedSessionHeader { header, signature }) = mux_fut
            .poll_with(async {
                debug!("starting finalization");

                io.send(merkle_root).await?;

                ot_recv.accept_reveal(&mut ctx).await?;

                debug!("received OT secret");

                let notary_encoder_seed = vm
                    .finalize()
                    .await
                    .map_err(|e| ProverError::MpcError(Box::new(e)))?
                    .expect("encoder seed returned");

                let signed_header: SignedSessionHeader = io.expect_next().await?;

                Ok::<_, ProverError>((notary_encoder_seed, signed_header))
            })
            .await?;

        // Wait for the notary to correctly close the connection.
        if !mux_fut.is_complete() {
            mux_ctrl.mux().close();
            mux_fut.await?;
        }

        // Check the header is consistent with the Prover's view.
        header
            .verify(
                start_time,
                &server_public_key,
                &session_data.commitments().merkle_root(),
                &notary_encoder_seed,
                &session_data.session_info().handshake_decommitment,
            )
            .map_err(|_| {
                ProverError::NotarizationError(
                    "notary signed an inconsistent session header".to_string(),
                )
            })?;

        Ok(NotarizedSession::new(header, Some(signature), session_data))
    }
}
