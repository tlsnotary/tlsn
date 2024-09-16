//! This module handles the notarization phase of the verifier.
//!
//! The TLS verifier is only a notary.

use super::{state::Notarize, Verifier, VerifierError};
use mpz_ot::CommittedOTSender;
use serio::{stream::IoStreamExt, SinkExt as _};

use tlsn_core::{
    attestation::{Attestation, AttestationConfig},
    request::Request,
};
use tracing::{debug, info, instrument};

impl Verifier<Notarize> {
    /// Notarizes the TLS session.
    ///
    /// # Arguments
    ///
    /// * `signer` - The signer used to sign the notarization result.
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub async fn finalize(self, config: &AttestationConfig) -> Result<Attestation, VerifierError> {
        let Notarize {
            mut io,
            mux_ctrl,
            mut mux_fut,
            mut vm,
            mut ot_send,
            mut ctx,
            encoder_seed,
            server_ephemeral_key,
            connection_info,
        } = self.state;

        let attestation = mux_fut
            .poll_with(async {
                // Receive attestation request, which also contains commitments required before
                // finalization.
                let request: Request = io.expect_next().await?;

                // Finalize all MPC before attesting.
                ot_send.reveal(&mut ctx).await?;

                debug!("revealed OT secret");

                vm.finalize().await?;

                info!("Finalized all MPC");

                let mut builder = Attestation::builder(config)
                    .accept_request(request)
                    .map_err(VerifierError::attestation)?;

                builder
                    .connection_info(connection_info)
                    .server_ephemeral_key(server_ephemeral_key)
                    .encoding_seed(encoder_seed.to_vec());

                let attestation = builder
                    .build(self.config.crypto_provider())
                    .map_err(VerifierError::attestation)?;

                io.send(attestation.clone()).await?;

                info!("Sent session header");

                Ok::<_, VerifierError>(attestation)
            })
            .await?;

        if !mux_fut.is_complete() {
            mux_ctrl.mux().close();
            mux_fut.await?;
        }

        Ok(attestation)
    }
}
