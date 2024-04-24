//! This module handles the notarization phase of the prover.
//!
//! The prover deals with a TLS verifier that is only a notary.

use crate::tls::error::OTShutdownError;

use super::{ff::ShareConversionReveal, state::Notarize, Prover, ProverError};
use futures::{FutureExt, SinkExt, StreamExt};
use tlsn_core::{
    commitment::TranscriptCommitmentBuilder,
    msg::{SignedSessionHeader, TlsnMessage},
    transcript::Transcript,
    NotarizedSession, ServerName, SessionData,
};
#[cfg(feature = "tracing")]
use tracing::instrument;
use utils_aio::{expect_msg_or_err, mux::MuxChannel};

impl Prover<Notarize> {
    /// Returns the transcript of the sent data.
    pub fn sent_transcript(&self) -> &Transcript {
        &self.state.transcript_tx
    }

    /// Returns the transcript of the received data.
    pub fn recv_transcript(&self) -> &Transcript {
        &self.state.transcript_rx
    }

    /// Returns the transcript commitment builder
    pub fn commitment_builder(&mut self) -> &mut TranscriptCommitmentBuilder {
        &mut self.state.builder
    }

    /// Finalize the notarization returning a [`NotarizedSession`]
    #[cfg_attr(feature = "tracing", instrument(level = "info", skip(self), err))]
    pub async fn finalize(self) -> Result<NotarizedSession, ProverError> {
        let Notarize {
            mut mux_ctrl,
            mut mux_fut,
            mut vm,
            mut ot_fut,
            mut gf2,
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

        let mut notarize_fut = Box::pin(async move {
            let mut channel = mux_ctrl.get_channel("notarize").await?;

            channel
                .send(TlsnMessage::TranscriptCommitmentRoot(merkle_root))
                .await?;

            let notary_encoder_seed = vm
                .finalize()
                .await
                .map_err(|e| ProverError::MpcError(Box::new(e)))?
                .expect("encoder seed returned");

            // This is a temporary approach until a maliciously secure share conversion protocol is implemented.
            // The prover is essentially revealing the TLS MAC key. In some exotic scenarios this allows a malicious
            // TLS verifier to modify the prover's sent data.
            gf2.reveal()
                .await
                .map_err(|e| ProverError::MpcError(Box::new(e)))?;

            let signed_header = expect_msg_or_err!(channel, TlsnMessage::SignedSessionHeader)?;

            Ok::<_, ProverError>((notary_encoder_seed, signed_header))
        })
        .fuse();

        let (notary_encoder_seed, SignedSessionHeader { header, signature }) = futures::select_biased! {
            res = notarize_fut => res?,
            _ = ot_fut => return Err(OTShutdownError)?,
            _ = &mut mux_fut => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?,
        };
        // Wait for the notary to correctly close the connection
        mux_fut.await?;

        // Check the header is consistent with the Prover's view
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
