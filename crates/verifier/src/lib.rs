//! TLSNotary verifier library.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

pub(crate) mod config;
mod error;
pub mod state;

use std::sync::Arc;

pub use config::{VerifierConfig, VerifierConfigBuilder, VerifierConfigBuilderError};
pub use error::VerifierError;
pub use tlsn_core::{VerifierOutput, VerifyConfig, VerifyConfigBuilder, VerifyConfigBuilderError};

use futures::{AsyncRead, AsyncWrite, TryFutureExt};
use mpc_tls::{FollowerData, MpcTlsFollower, SessionKeys};
use mpz_common::Context;
use mpz_core::Block;
use mpz_garble_core::Delta;
use mpz_vm_core::prelude::*;
use serio::{stream::IoStreamExt, SinkExt};
use tls_core::msgs::enums::ContentType;
use tlsn_common::{
    commit::{commit_records, hash::verify_hash},
    config::ProtocolConfig,
    context::build_mt_context,
    encoding,
    mux::attach_mux,
    tag::verify_tags,
    transcript::{decode_transcript, verify_transcript, Record, TlsTranscript},
    zk_aes_ctr::ZkAesCtr,
    Role,
};
use tlsn_core::{
    attestation::{Attestation, AttestationConfig},
    connection::{ConnectionInfo, ServerName, TlsVersion, TranscriptLength},
    request::Request,
    transcript::TranscriptCommitment,
    ProvePayload,
};
use tlsn_deap::Deap;
use tokio::sync::Mutex;
use web_time::{SystemTime, UNIX_EPOCH};

use tracing::{debug, info, info_span, instrument, Span};

pub(crate) type RCOTSender = mpz_ot::rcot::shared::SharedRCOTSender<
    mpz_ot::ferret::Sender<mpz_ot::kos::Sender<mpz_ot::chou_orlandi::Receiver>>,
    mpz_core::Block,
>;
pub(crate) type RCOTReceiver = mpz_ot::rcot::shared::SharedRCOTReceiver<
    mpz_ot::kos::Receiver<mpz_ot::chou_orlandi::Sender>,
    bool,
    mpz_core::Block,
>;
pub(crate) type Mpc =
    mpz_garble::protocol::semihonest::Evaluator<mpz_ot::cot::DerandCOTReceiver<RCOTReceiver>>;
pub(crate) type Zk = mpz_zk::Verifier<RCOTSender>;

/// Information about the TLS session.
#[derive(Debug)]
pub struct SessionInfo {
    /// Server's name.
    pub server_name: ServerName,
    /// Connection information.
    pub connection_info: ConnectionInfo,
}

/// A Verifier instance.
pub struct Verifier<T: state::VerifierState = state::Initialized> {
    config: VerifierConfig,
    span: Span,
    state: T,
}

impl Verifier<state::Initialized> {
    /// Creates a new verifier.
    pub fn new(config: VerifierConfig) -> Self {
        let span = info_span!("verifier");
        Self {
            config,
            span,
            state: state::Initialized,
        }
    }

    /// Sets up the verifier.
    ///
    /// This performs all MPC setup.
    ///
    /// # Arguments
    ///
    /// * `socket` - The socket to the prover.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn setup<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
        self,
        socket: S,
    ) -> Result<Verifier<state::Setup>, VerifierError> {
        let (mut mux_fut, mux_ctrl) = attach_mux(socket, Role::Verifier);
        let mut mt = build_mt_context(mux_ctrl.clone());
        let mut ctx = mux_fut.poll_with(mt.new_context()).await?;

        // Receives protocol configuration from prover to perform compatibility check.
        let protocol_config = mux_fut
            .poll_with(async {
                let peer_configuration: ProtocolConfig = ctx.io_mut().expect_next().await?;
                self.config
                    .protocol_config_validator()
                    .validate(&peer_configuration)?;

                Ok::<_, VerifierError>(peer_configuration)
            })
            .await?;

        let delta = Delta::random(&mut rand::rng());
        let (vm, mut mpc_tls) = build_mpc_tls(&self.config, &protocol_config, delta, ctx);

        // Allocate resources for MPC-TLS in VM.
        let mut keys = mpc_tls.alloc()?;
        translate_keys(&mut keys, &vm.try_lock().expect("VM is not locked"))?;

        // Allocate for committing to plaintext.
        let mut zk_aes_ctr = ZkAesCtr::new(Role::Verifier);
        zk_aes_ctr.set_key(keys.server_write_key, keys.server_write_iv);
        zk_aes_ctr.alloc(
            &mut (*vm.try_lock().expect("VM is not locked").zk()),
            protocol_config.max_recv_data(),
        )?;

        debug!("setting up mpc-tls");

        mux_fut.poll_with(mpc_tls.preprocess()).await?;

        debug!("mpc-tls setup complete");

        Ok(Verifier {
            config: self.config,
            span: self.span,
            state: state::Setup {
                mux_ctrl,
                mux_fut,
                delta,
                mpc_tls,
                zk_aes_ctr,
                _keys: keys,
                vm,
            },
        })
    }

    /// Runs the verifier to completion and attests to the TLS session.
    ///
    /// This is a convenience method which runs all the steps needed for
    /// notarization.
    ///
    /// # Arguments
    ///
    /// * `socket` - The socket to the prover.
    /// * `config` - The attestation configuration.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    #[deprecated(
        note = "attestation functionality will be removed from this API in future releases."
    )]
    pub async fn notarize<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
        self,
        socket: S,
        config: &AttestationConfig,
    ) -> Result<Attestation, VerifierError> {
        let mut verifier = self.setup(socket).await?.run().await?;

        #[allow(deprecated)]
        let attestation = verifier.notarize(config).await?;

        verifier.close().await?;

        Ok(attestation)
    }

    /// Runs the TLS verifier to completion, verifying the TLS session.
    ///
    /// This is a convenience method which runs all the steps needed for
    /// verification.
    ///
    /// # Arguments
    ///
    /// * `socket` - The socket to the prover.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn verify<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
        self,
        socket: S,
        config: &VerifyConfig,
    ) -> Result<VerifierOutput, VerifierError> {
        let mut verifier = self.setup(socket).await?.run().await?;

        let output = verifier.verify(config).await?;

        verifier.close().await?;

        Ok(output)
    }
}

impl Verifier<state::Setup> {
    /// Runs the verifier until the TLS connection is closed.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn run(self) -> Result<Verifier<state::Committed>, VerifierError> {
        let state::Setup {
            mux_ctrl,
            mut mux_fut,
            delta,
            mpc_tls,
            mut zk_aes_ctr,
            vm,
            ..
        } = self.state;

        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be available")
            .as_secs();

        info!("starting MPC-TLS");

        let (
            mut ctx,
            FollowerData {
                server_key,
                mut transcript,
                keys,
                ..
            },
        ) = mux_fut.poll_with(mpc_tls.run()).await?;

        info!("finished MPC-TLS");

        {
            let mut vm = vm.try_lock().expect("VM should not be locked");

            translate_transcript(&mut transcript, &vm)?;

            debug!("finalizing mpc");

            mux_fut
                .poll_with(vm.finalize(&mut ctx))
                .await
                .map_err(VerifierError::mpc)?;

            debug!("mpc finalized");
        }

        // Pull out ZK VM.
        let (_, mut vm) = Arc::into_inner(vm)
            .expect("vm should have only 1 reference")
            .into_inner()
            .into_inner();

        // Prepare for the prover to prove tag verification of the received
        // records.
        let tag_proof = verify_tags(
            &mut vm,
            (keys.server_write_key, keys.server_write_iv),
            keys.server_write_mac_key,
            transcript.recv.clone(),
        )
        .map_err(VerifierError::zk)?;

        // Prepare for the prover to prove received plaintext.
        let proof = commit_records(
            &mut vm,
            &mut zk_aes_ctr,
            transcript
                .recv
                .iter_mut()
                .filter(|record| record.typ == ContentType::ApplicationData),
        )
        .map_err(VerifierError::zk)?;

        mux_fut
            .poll_with(vm.execute_all(&mut ctx).map_err(VerifierError::zk))
            .await?;

        // Verify the tags.
        // After the verification, the entire TLS trancript becomes
        // authenticated from the verifier's perspective.
        tag_proof.verify().map_err(VerifierError::zk)?;

        // Verify the plaintext proofs.
        proof.verify().map_err(VerifierError::zk)?;

        let sent = transcript
            .sent
            .iter()
            .filter(|record| record.typ == ContentType::ApplicationData)
            .map(|record| record.ciphertext.len())
            .sum::<usize>() as u32;
        let received = transcript
            .recv
            .iter()
            .filter(|record| record.typ == ContentType::ApplicationData)
            .map(|record| record.ciphertext.len())
            .sum::<usize>() as u32;

        let transcript_refs = transcript
            .to_transcript_refs()
            .expect("transcript should be complete");

        let connection_info = ConnectionInfo {
            time: start_time,
            version: TlsVersion::V1_2,
            transcript_length: TranscriptLength { sent, received },
        };

        Ok(Verifier {
            config: self.config,
            span: self.span,
            state: state::Committed {
                mux_ctrl,
                mux_fut,
                delta,
                ctx,
                vm,
                server_ephemeral_key: server_key
                    .try_into()
                    .expect("only supported key type should have been accepted"),
                connection_info,
                transcript_refs,
            },
        })
    }
}

impl Verifier<state::Committed> {
    /// Returns the connection information.
    pub fn connection_info(&self) -> &ConnectionInfo {
        &self.state.connection_info
    }

    /// Verifies information from the prover.
    ///
    /// # Arguments
    ///
    /// * `config` - Verification configuration.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn verify(
        &mut self,
        #[allow(unused_variables)] config: &VerifyConfig,
    ) -> Result<VerifierOutput, VerifierError> {
        let state::Committed {
            mux_fut,
            ctx,
            delta,
            vm,
            connection_info,
            server_ephemeral_key,
            transcript_refs,
            ..
        } = &mut self.state;

        let ProvePayload {
            server_identity,
            transcript,
            transcript_commit,
        } = mux_fut
            .poll_with(ctx.io_mut().expect_next().map_err(VerifierError::from))
            .await?;

        let server_name = if let Some((name, cert_data)) = server_identity {
            cert_data
                .verify_with_provider(
                    self.config.crypto_provider(),
                    connection_info.time,
                    server_ephemeral_key,
                    &name,
                )
                .map_err(VerifierError::verify)?;

            Some(name)
        } else {
            None
        };

        if let Some(partial_transcript) = &transcript {
            // Check ranges.
            if partial_transcript.len_sent() != connection_info.transcript_length.sent as usize
                || partial_transcript.len_received()
                    != connection_info.transcript_length.received as usize
            {
                return Err(VerifierError::verify(
                    "prover sent transcript with incorrect length",
                ));
            }

            decode_transcript(
                vm,
                partial_transcript.sent_authed(),
                partial_transcript.received_authed(),
                transcript_refs,
            )
            .map_err(VerifierError::zk)?;
        }

        let mut transcript_commitments = Vec::new();
        let mut hash_commitments = None;
        if let Some(commit_config) = transcript_commit {
            if commit_config.encoding() {
                let commitment = mux_fut
                    .poll_with(encoding::transfer(
                        ctx,
                        transcript_refs,
                        delta,
                        |plaintext| vm.get_keys(plaintext).expect("reference is valid"),
                    ))
                    .await?;

                transcript_commitments.push(TranscriptCommitment::Encoding(commitment));
            }

            if commit_config.has_hash() {
                hash_commitments = Some(
                    verify_hash(vm, transcript_refs, commit_config.iter_hash().cloned())
                        .map_err(VerifierError::verify)?,
                );
            }
        }

        mux_fut
            .poll_with(vm.execute_all(ctx).map_err(VerifierError::zk))
            .await?;

        // Verify revealed data.
        if let Some(partial_transcript) = &transcript {
            verify_transcript(vm, partial_transcript, transcript_refs)
                .map_err(VerifierError::verify)?;
        }

        if let Some(hash_commitments) = hash_commitments {
            for commitment in hash_commitments.try_recv().map_err(VerifierError::verify)? {
                transcript_commitments.push(TranscriptCommitment::Hash(commitment));
            }
        }

        Ok(VerifierOutput {
            server_name,
            transcript,
            transcript_commitments,
        })
    }

    /// Attests to the TLS session.
    ///
    /// # Arguments
    ///
    /// * `config` - Attestation configuration.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    #[deprecated(
        note = "attestation functionality will be removed from this API in future releases."
    )]
    pub async fn notarize(
        &mut self,
        config: &AttestationConfig,
    ) -> Result<Attestation, VerifierError> {
        let VerifierOutput {
            server_name,
            transcript,
            transcript_commitments,
        } = self.verify(&VerifyConfig::default()).await?;

        if server_name.is_some() {
            return Err(VerifierError::attestation(
                "server name can not be revealed to a notary",
            ));
        } else if transcript.is_some() {
            return Err(VerifierError::attestation(
                "transcript data can not be revealed to a notary",
            ));
        }

        let state::Committed {
            mux_fut,
            ctx,
            server_ephemeral_key,
            connection_info,
            ..
        } = &mut self.state;

        let request: Request = mux_fut
            .poll_with(ctx.io_mut().expect_next().map_err(VerifierError::from))
            .await?;

        let mut builder = Attestation::builder(config)
            .accept_request(request)
            .map_err(VerifierError::attestation)?;

        builder
            .connection_info(connection_info.clone())
            .server_ephemeral_key(server_ephemeral_key.clone())
            .transcript_commitments(transcript_commitments);

        let attestation = builder
            .build(self.config.crypto_provider())
            .map_err(VerifierError::attestation)?;

        mux_fut
            .poll_with(
                ctx.io_mut()
                    .send(attestation.clone())
                    .map_err(VerifierError::from),
            )
            .await?;

        info!("Sent attestation");

        Ok(attestation)
    }

    /// Closes the connection with the prover.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn close(self) -> Result<(), VerifierError> {
        let state::Committed {
            mux_ctrl, mux_fut, ..
        } = self.state;

        // Wait for the prover to correctly close the connection.
        if !mux_fut.is_complete() {
            mux_ctrl.close();
            mux_fut.await?;
        }

        Ok(())
    }
}

fn build_mpc_tls(
    config: &VerifierConfig,
    protocol_config: &ProtocolConfig,
    delta: Delta,
    ctx: Context,
) -> (Arc<Mutex<Deap<Mpc, Zk>>>, MpcTlsFollower) {
    let mut rng = rand::rng();

    let base_ot_send = mpz_ot::chou_orlandi::Sender::default();
    let base_ot_recv = mpz_ot::chou_orlandi::Receiver::default();
    let rcot_send = mpz_ot::kos::Sender::new(
        mpz_ot::kos::SenderConfig::default(),
        delta.into_inner(),
        base_ot_recv,
    );
    let rcot_send = mpz_ot::ferret::Sender::new(
        mpz_ot::ferret::FerretConfig::builder()
            .lpn_type(mpz_ot::ferret::LpnType::Regular)
            .build()
            .expect("ferret config is valid"),
        Block::random(&mut rng),
        rcot_send,
    );
    let rcot_recv =
        mpz_ot::kos::Receiver::new(mpz_ot::kos::ReceiverConfig::default(), base_ot_send);

    let rcot_send = mpz_ot::rcot::shared::SharedRCOTSender::new(rcot_send);
    let rcot_recv = mpz_ot::rcot::shared::SharedRCOTReceiver::new(rcot_recv);

    let mpc = Mpc::new(mpz_ot::cot::DerandCOTReceiver::new(rcot_recv.clone()));

    let zk = Zk::new(delta, rcot_send.clone());

    let vm = Arc::new(Mutex::new(Deap::new(tlsn_deap::Role::Follower, mpc, zk)));

    (
        vm.clone(),
        MpcTlsFollower::new(
            config.build_mpc_tls_config(protocol_config),
            ctx,
            vm,
            rcot_send,
            (rcot_recv.clone(), rcot_recv.clone(), rcot_recv),
        ),
    )
}

/// Translates VM references to the ZK address space.
fn translate_keys<Mpc, Zk>(
    keys: &mut SessionKeys,
    vm: &Deap<Mpc, Zk>,
) -> Result<(), VerifierError> {
    keys.client_write_key = vm
        .translate(keys.client_write_key)
        .map_err(VerifierError::mpc)?;
    keys.client_write_iv = vm
        .translate(keys.client_write_iv)
        .map_err(VerifierError::mpc)?;
    keys.server_write_key = vm
        .translate(keys.server_write_key)
        .map_err(VerifierError::mpc)?;
    keys.server_write_iv = vm
        .translate(keys.server_write_iv)
        .map_err(VerifierError::mpc)?;
    keys.server_write_mac_key = vm
        .translate(keys.server_write_mac_key)
        .map_err(VerifierError::mpc)?;

    Ok(())
}

/// Translates VM references to the ZK address space.
fn translate_transcript<Mpc, Zk>(
    transcript: &mut TlsTranscript,
    vm: &Deap<Mpc, Zk>,
) -> Result<(), VerifierError> {
    for Record { plaintext_ref, .. } in transcript.sent.iter_mut().chain(transcript.recv.iter_mut())
    {
        if let Some(plaintext_ref) = plaintext_ref.as_mut() {
            *plaintext_ref = vm.translate(*plaintext_ref).map_err(VerifierError::mpc)?;
        }
    }

    Ok(())
}
