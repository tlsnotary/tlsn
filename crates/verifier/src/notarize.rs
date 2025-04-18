//! This module handles the notarization phase of the verifier.
//!
//! The TLS verifier acts as a Notary, i.e. the verifier produces an
//! attestation but does not verify transcript data.

use super::{state::Notarize, Verifier, VerifierError};
use rand::Rng;
use serio::{stream::IoStreamExt, SinkExt as _};

use tlsn_common::encoding;
use tlsn_core::{
    attestation::{Attestation, AttestationConfig},
    request::Request,
    transcript::encoding::EncoderSecret,
};
use tracing::{info, instrument};

impl Verifier<Notarize> {
    /// Notarizes the TLS session.
    ///
    /// # Arguments
    ///
    /// * `config` - The attestation configuration.
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub async fn finalize(self, config: &AttestationConfig) -> Result<Attestation, VerifierError> {
        let Notarize {
            mux_ctrl,
            mut mux_fut,
            delta,
            mut ctx,
            vm,
            server_ephemeral_key,
            connection_info,
            transcript_refs,
            ..
        } = self.state;

        let encoder_secret = EncoderSecret::new(rand::rng().random(), delta.as_block().to_bytes());

        let attestation = mux_fut
            .poll_with(async {
                let sent_keys = transcript_refs
                    .sent()
                    .iter()
                    .flat_map(|plaintext| vm.get_keys(*plaintext).expect("reference is valid"))
                    .map(|key| key.as_block());
                let recv_keys = transcript_refs
                    .recv()
                    .iter()
                    .flat_map(|plaintext| vm.get_keys(*plaintext).expect("reference is valid"))
                    .map(|key| key.as_block());

                // Convert encodings into a structured format.
                encoding::transfer(&mut ctx, &encoder_secret, sent_keys, recv_keys).await?;

                // Receive attestation request, which also contains commitments required before
                // finalization.
                let request: Request = ctx.io_mut().expect_next().await?;

                let mut builder = Attestation::builder(config)
                    .accept_request(request)
                    .map_err(VerifierError::attestation)?;

                builder
                    .connection_info(connection_info)
                    .server_ephemeral_key(server_ephemeral_key)
                    .encoder_secret(encoder_secret);

                let attestation = builder
                    .build(self.config.crypto_provider())
                    .map_err(VerifierError::attestation)?;

                ctx.io_mut().send(attestation.clone()).await?;

                info!("Sent attestation");

                Ok::<_, VerifierError>(attestation)
            })
            .await?;

        if !mux_fut.is_complete() {
            mux_ctrl.close();
            mux_fut.await?;
        }

        Ok(attestation)
    }
}
