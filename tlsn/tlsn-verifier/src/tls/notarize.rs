//! This module handles the notarization phase of the verifier.
//!
//! The TLS verifier is only a notary.

use super::{state::Notarize, Verifier, VerifierError};
use mpz_core::serialize::CanonicalSerialize;
use mpz_ot::CommittedOTSender;
use serio::{stream::IoStreamExt, SinkExt as _};
use signature::Signer;
use tlsn_core::{
    merkle::MerkleRoot, msg::SignedSessionHeader, HandshakeSummary, SessionHeader, Signature,
};

use tracing::{debug, info, instrument};

impl Verifier<Notarize> {
    /// Notarizes the TLS session.
    ///
    /// # Arguments
    ///
    /// * `signer` - The signer used to sign the notarization result.
    #[instrument(level = "debug", skip_all, err)]
    pub async fn finalize<T>(self, signer: &impl Signer<T>) -> Result<SessionHeader, VerifierError>
    where
        T: Into<Signature>,
    {
        let Notarize {
            mut io,
            mux_ctrl,
            mut mux_fut,
            mut vm,
            mut ot_send,
            mut ctx,
            encoder_seed,
            start_time,
            server_ephemeral_key,
            handshake_commitment,
            sent_len,
            recv_len,
        } = self.state;

        let session_header = mux_fut
            .poll_with(async {
                let merkle_root: MerkleRoot = io.expect_next().await?;

                // Finalize all MPC before signing the session header.
                ot_send.reveal(&mut ctx).await?;

                debug!("revealed OT secret");

                vm.finalize()
                    .await
                    .map_err(|e| VerifierError::MpcError(Box::new(e)))?;

                info!("Finalized all MPC");

                let handshake_summary =
                    HandshakeSummary::new(start_time, server_ephemeral_key, handshake_commitment);

                let session_header = SessionHeader::new(
                    encoder_seed,
                    merkle_root,
                    sent_len,
                    recv_len,
                    handshake_summary,
                );

                let signature = signer.sign(&session_header.to_bytes());

                info!("Signed session header");

                io.send(SignedSessionHeader {
                    header: session_header.clone(),
                    signature: signature.into(),
                })
                .await?;

                info!("Sent session header");

                Ok::<_, VerifierError>(session_header)
            })
            .await?;

        if !mux_fut.is_complete() {
            mux_ctrl.mux().close();
            mux_fut.await?;
        }

        Ok(session_header)
    }
}
