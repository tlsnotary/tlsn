//! Verifier.

mod config;
mod error;
pub mod state;

pub use config::{VerifierConfig, VerifierConfigBuilder, VerifierConfigBuilderError};
pub use error::VerifierError;
pub use tlsn_core::{
    VerifierOutput, VerifyConfig, VerifyConfigBuilder, VerifyConfigBuilderError,
    webpki::ServerCertVerifier,
};

use std::sync::Arc;

use futures::{AsyncRead, AsyncWrite, TryFutureExt};
use mpc_tls::{MpcTlsFollower, SessionKeys};
use mpz_common::Context;
use mpz_core::Block;
use mpz_garble_core::Delta;
use mpz_vm_core::prelude::*;
use mpz_zk::VerifierConfig as ZkVerifierConfig;
use serio::stream::IoStreamExt;
use tlsn_core::{
    ProveRequest,
    connection::{ConnectionInfo, ServerName},
    transcript::{ContentType, TlsTranscript},
};
use tlsn_deap::Deap;
use tokio::sync::Mutex;
use tracing::{Span, debug, info, info_span, instrument};

use crate::{
    Role,
    commit::{ProvingState, TranscriptRefs},
    config::ProtocolConfig,
    context::build_mt_context,
    mux::attach_mux,
    tag::verify_tags,
    zk_aes_ctr::ZkAesCtr,
};

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

        // Allocate resources for MPC-TLS in the VM.
        let mut keys = mpc_tls.alloc()?;
        let vm_lock = vm.try_lock().expect("VM is not locked");
        translate_keys(&mut keys, &vm_lock)?;

        // Allocate for committing to plaintext.
        let mut zk_aes_ctr_sent = ZkAesCtr::new(Role::Verifier);
        zk_aes_ctr_sent.set_key(keys.client_write_key, keys.client_write_iv);
        zk_aes_ctr_sent.alloc(&mut *vm_lock.zk(), protocol_config.max_sent_data())?;

        let mut zk_aes_ctr_recv = ZkAesCtr::new(Role::Verifier);
        zk_aes_ctr_recv.set_key(keys.server_write_key, keys.server_write_iv);
        zk_aes_ctr_recv.alloc(&mut *vm_lock.zk(), protocol_config.max_recv_data())?;

        drop(vm_lock);

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
                zk_aes_ctr_sent,
                zk_aes_ctr_recv,
                keys,
                vm,
            },
        })
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
            zk_aes_ctr_sent,
            zk_aes_ctr_recv,
            vm,
            keys,
        } = self.state;

        info!("starting MPC-TLS");

        let (mut ctx, tls_transcript) = mux_fut.poll_with(mpc_tls.run()).await?;

        info!("finished MPC-TLS");

        {
            let mut vm = vm.try_lock().expect("VM should not be locked");

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
            *tls_transcript.version(),
            tls_transcript.recv().to_vec(),
        )
        .map_err(VerifierError::zk)?;

        mux_fut
            .poll_with(vm.execute_all(&mut ctx).map_err(VerifierError::zk))
            .await?;

        // Verify the tags.
        // After the verification, the entire TLS trancript becomes
        // authenticated from the verifier's perspective.
        tag_proof.verify().map_err(VerifierError::zk)?;

        let sent_len = tls_transcript
            .sent()
            .iter()
            .filter_map(|record| {
                if matches!(record.typ, ContentType::ApplicationData) {
                    Some(record.ciphertext.len())
                } else {
                    None
                }
            })
            .sum();
        let recv_len = tls_transcript
            .recv()
            .iter()
            .filter_map(|record| {
                if matches!(record.typ, ContentType::ApplicationData) {
                    Some(record.ciphertext.len())
                } else {
                    None
                }
            })
            .sum();

        let transcript_refs = TranscriptRefs::new(sent_len, recv_len);

        Ok(Verifier {
            config: self.config,
            span: self.span,
            state: state::Committed {
                mux_ctrl,
                mux_fut,
                delta,
                ctx,
                vm,
                tls_transcript,
                transcript_refs,
                zk_aes_ctr_sent,
                zk_aes_ctr_recv,
                keys,
                verified_server_name: None,
                encodings_transferred: false,
            },
        })
    }
}

impl Verifier<state::Committed> {
    /// Returns the TLS transcript.
    pub fn tls_transcript(&self) -> &TlsTranscript {
        &self.state.tls_transcript
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
            tls_transcript,
            transcript_refs,
            zk_aes_ctr_sent,
            zk_aes_ctr_recv,
            keys,
            verified_server_name,
            encodings_transferred,
            ..
        } = &mut self.state;

        let payload: ProveRequest = mux_fut
            .poll_with(ctx.io_mut().expect_next().map_err(VerifierError::from))
            .await?;

        let proving_state = ProvingState::for_verifier(
            payload,
            tls_transcript,
            transcript_refs,
            verified_server_name.clone(),
            *encodings_transferred,
        );

        let (output, encodings_executed) = mux_fut
            .poll_with(proving_state.verify(
                vm,
                ctx,
                zk_aes_ctr_sent,
                zk_aes_ctr_recv,
                keys.clone(),
                *delta,
                self.config.root_store(),
            ))
            .await?;

        *verified_server_name = output.server_name.clone();
        *encodings_transferred = encodings_executed;

        Ok(output)
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

    let zk = Zk::new(ZkVerifierConfig::default(), delta, rcot_send.clone());

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
