//! This module handles the notarization phase of the prover.
//!
//! The prover interacts with a TLS verifier who acts as a Notary, i.e. the
//! verifier produces an attestation but does not verify transcript data.

use super::{state::Notarize, Prover, ProverError};
use serio::{stream::IoStreamExt as _, SinkExt as _};
use tlsn_common::encoding;
use tlsn_core::{
    attestation::{Attestation, AttestationUnchecked},
    request::{Request, RequestConfig},
    transcript::{encoding::EncodingTree, Transcript, TranscriptCommitConfig},
    Secrets,
};
use tracing::{debug, instrument};

impl Prover<Notarize> {
    /// Returns the transcript.
    pub fn transcript(&self) -> &Transcript {
        &self.state.transcript
    }

    /// Configures transcript commitments.
    pub fn transcript_commit(&mut self, config: TranscriptCommitConfig) {
        self.state.transcript_commit_config = Some(config);
    }

    /// Finalizes the notarization.
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub async fn finalize(
        self,
        config: &RequestConfig,
    ) -> Result<(Attestation, Secrets), ProverError> {
        let Notarize {
            mux_ctrl,
            mut mux_fut,
            mut ctx,
            vm,
            connection_info,
            server_cert_data,
            transcript,
            transcript_refs,
            transcript_commit_config,
            ..
        } = self.state;

        let sent_macs = transcript_refs
            .sent()
            .iter()
            .flat_map(|plaintext| vm.get_macs(*plaintext).expect("reference is valid"))
            .map(|mac| mac.as_block());
        let recv_macs = transcript_refs
            .recv()
            .iter()
            .flat_map(|plaintext| vm.get_macs(*plaintext).expect("reference is valid"))
            .map(|mac| mac.as_block());

        let encoding_provider = mux_fut
            .poll_with(encoding::receive(&mut ctx, sent_macs, recv_macs))
            .await?;

        let provider = self.config.crypto_provider();

        let hasher = provider
            .hash
            .get(config.hash_alg())
            .map_err(ProverError::config)?;

        let mut builder = Request::builder(config);

        builder
            .server_name(self.config.server_name().clone())
            .server_cert_data(server_cert_data)
            .transcript(transcript);

        if let Some(config) = transcript_commit_config {
            if config.has_encoding() {
                builder.encoding_tree(
                    EncodingTree::new(
                        hasher,
                        config.iter_encoding(),
                        &encoding_provider,
                        &connection_info.transcript_length,
                    )
                    .map_err(ProverError::commit)?,
                );
            }
        }

        let (request, secrets) = builder.build(provider).map_err(ProverError::attestation)?;

        let attestation = mux_fut
            .poll_with(async {
                debug!("sending attestation request");

                ctx.io_mut().send(request.clone()).await?;

                let unchecked: AttestationUnchecked = ctx.io_mut().expect_next().await?;
                let attestation = Attestation::try_from_unchecked(unchecked, provider)
                    .map_err(ProverError::attestation)?;

                Ok::<_, ProverError>(attestation)
            })
            .await?;

        // Wait for the notary to correctly close the connection.
        if !mux_fut.is_complete() {
            mux_ctrl.close();
            mux_fut.await?;
        }

        // Check the attestation is consistent with the Prover's view.
        request
            .validate(&attestation)
            .map_err(ProverError::attestation)?;

        Ok((attestation, secrets))
    }
}
