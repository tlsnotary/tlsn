//! This module handles the notarization phase of the prover.
//!
//! The prover deals with a TLS verifier that is only a notary.

use crate::{state::Notarize, Prover, ProverError};

use mpz_ot::VerifiableOTReceiver;
use serio::{stream::IoStreamExt as _, SinkExt as _};
use tlsn_core::{
    attestation::Attestation,
    request::{Request, RequestConfig},
    transcript::{encoding::EncodingTree, Transcript, TranscriptCommitConfig},
    Secrets,
};
use tracing::{debug, instrument};

#[cfg(feature = "authdecode_unsafe")]
use std::ops::Range;

#[cfg(feature = "authdecode_unsafe")]
use crate::authdecode::{authdecode_prover, TranscriptProver};
#[cfg(feature = "authdecode_unsafe")]
use tlsn_core::{
    hash::{Blinder, HashAlgId},
    transcript::Direction,
};

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
            mut io,
            mux_ctrl,
            mut mux_fut,
            mut vm,
            mut ot_recv,
            mut ctx,
            connection_info,
            server_cert_data,
            transcript,
            encoding_provider,
            transcript_commit_config,
            encoding_commitments,
        } = self.state;

        let provider = self.config.crypto_provider();

        let hasher = provider.hash.get(config.hash_alg()).unwrap();

        let mut builder = Request::builder(config);

        builder
            .server_name(self.config.server_name().clone())
            .server_cert_data(server_cert_data)
            .transcript(transcript.clone());

        if let Some(config) = transcript_commit_config {
            if config.has_encoding() {
                let tree = match encoding_commitments {
                    Some(tree) => tree,
                    None => EncodingTree::new(
                        hasher,
                        config.iter_encoding(),
                        &*encoding_provider,
                        &connection_info.transcript_length,
                    )
                    .map_err(ProverError::attestation)?,
                };

                builder.encoding_tree(tree);
            }

            if config.has_plaintext_hashes() {
                builder.plaintext_hashes(config.plaintext_hashes());
            }
        }

        let (request, secrets) = builder.build(provider).map_err(ProverError::attestation)?;

        let attestation = mux_fut
            .poll_with(async {
                debug!("starting finalization");

                io.send(request.clone()).await?;

                ot_recv.accept_reveal(&mut ctx).await?;

                debug!("received OT secret");

                vm.finalize().await?;

                let attestation: Attestation = io.expect_next().await?;

                Ok::<_, ProverError>(attestation)
            })
            .await?;

        // Wait for the notary to correctly close the connection.
        if !mux_fut.is_complete() {
            mux_ctrl.mux().close();
            mux_fut.await?;
        }

        // Check the attestation is consistent with the Prover's view.
        request
            .validate(&attestation)
            .map_err(ProverError::attestation)?;

        Ok((attestation, secrets))
    }

    /// Finalizes the notarization and runs the AuthDecode protocol.
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    #[cfg(feature = "authdecode_unsafe")]
    pub async fn finalize_with_authdecode(
        self,
        config: &RequestConfig,
        authdecode_inputs: Vec<(Direction, Range<usize>, HashAlgId, Blinder)>,
    ) -> Result<(Attestation, Secrets), ProverError> {
        let Notarize {
            mut io,
            mux_ctrl,
            mut mux_fut,
            mut vm,
            mut ot_recv,
            mut ctx,
            connection_info,
            server_cert_data,
            transcript,
            encoding_provider,
            transcript_commit_config,
            encoding_commitments,
        } = self.state;

        let provider = self.config.crypto_provider();

        let hasher = provider.hash.get(config.hash_alg()).unwrap();

        let mut builder = Request::builder(config);

        builder
            .server_name(self.config.server_name().clone())
            .server_cert_data(server_cert_data)
            .transcript(transcript.clone());

        if let Some(config) = transcript_commit_config {
            if config.has_encoding() {
                let tree = match encoding_commitments {
                    Some(tree) => tree,
                    None => EncodingTree::new(
                        hasher,
                        config.iter_encoding(),
                        &*encoding_provider,
                        &connection_info.transcript_length,
                    )
                    .map_err(ProverError::attestation)?,
                };

                builder.encoding_tree(tree);
            }

            if config.has_plaintext_hashes() {
                builder.plaintext_hashes(config.plaintext_hashes());
            }
        }

        let (request, secrets) = builder.build(provider).map_err(ProverError::attestation)?;

        let attestation = mux_fut
            .poll_with(async {
                debug!("starting finalization");

                io.send(request.clone()).await?;

                let max = self.config.protocol_config().max_authdecode_data();
                let mut authdecode_prover =
                    authdecode_prover(authdecode_inputs, &*encoding_provider, &transcript, max)?;

                io.send(authdecode_prover.alg()).await?;
                io.send(authdecode_prover.commit()?).await?;

                debug!("sent AuthDecode commitment");

                ot_recv.accept_reveal(&mut ctx).await?;

                debug!("received OT secret");

                let seed = vm
                    .finalize()
                    .await?
                    .expect("The seed should be returned to the leader");

                // Now that the full encodings were authenticated, it is safe to proceed to the
                // proof generation phase of the AuthDecode protocol.
                io.send(authdecode_prover.prove(seed)?).await?;

                debug!("sent AuthDecode proof");

                let attestation: Attestation = io.expect_next().await?;

                Ok::<_, ProverError>(attestation)
            })
            .await?;

        // Wait for the notary to correctly close the connection.
        if !mux_fut.is_complete() {
            mux_ctrl.mux().close();
            mux_fut.await?;
        }

        // Check the attestation is consistent with the Prover's view.
        request
            .validate(&attestation)
            .map_err(ProverError::attestation)?;

        Ok((attestation, secrets))
    }
}
