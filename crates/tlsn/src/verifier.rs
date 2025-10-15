//! Verifier.

pub(crate) mod config;
mod error;
pub mod state;
mod verify;

use std::sync::Arc;

pub use config::{VerifierConfig, VerifierConfigBuilder, VerifierConfigBuilderError};
pub use error::VerifierError;
pub use tlsn_core::{VerifierOutput, webpki::ServerCertVerifier};

use crate::{
    Role,
    config::ProtocolConfig,
    context::build_mt_context,
    msg::{Response, SetupRequest},
    mux::attach_mux,
    tag::verify_tags,
};
use futures::{AsyncRead, AsyncWrite, TryFutureExt};
use mpc_tls::{MpcTlsFollower, SessionKeys};
use mpz_common::Context;
use mpz_core::Block;
use mpz_garble_core::Delta;
use mpz_vm_core::prelude::*;
use mpz_zk::VerifierConfig as ZkVerifierConfig;
use serio::{SinkExt, stream::IoStreamExt};
use tlsn_core::{
    ProveRequest,
    connection::{ConnectionInfo, ServerName},
    transcript::TlsTranscript,
};
use tlsn_deap::Deap;
use tokio::sync::Mutex;

use tracing::{Span, debug, info, info_span, instrument};

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
    ) -> Result<Verifier<state::Config>, VerifierError> {
        let (mut mux_fut, mux_ctrl) = attach_mux(socket, Role::Verifier);
        let mut mt = build_mt_context(mux_ctrl.clone());
        let mut ctx = mux_fut.poll_with(mt.new_context()).await?;

        // Receives protocol configuration from prover to perform compatibility check.
        let SetupRequest { config, version } =
            mux_fut.poll_with(ctx.io_mut().expect_next()).await?;

        if version != *crate::config::VERSION {
            let msg = format!(
                "prover version does not match with verifier: {version} != {}",
                *crate::config::VERSION
            );
            mux_fut
                .poll_with(ctx.io_mut().send(Response::err(Some(msg.clone()))))
                .await?;

            // Wait for the prover to correctly close the connection.
            if !mux_fut.is_complete() {
                mux_ctrl.close();
                mux_fut.await?;
            }

            return Err(VerifierError::config(msg));
        }

        Ok(Verifier {
            config: self.config,
            span: self.span,
            state: state::Config {
                mux_ctrl,
                mux_fut,
                ctx,
                config,
            },
        })
    }
}

impl Verifier<state::Config> {
    /// Returns the proposed protocol configuration.
    pub fn config(&self) -> &ProtocolConfig {
        &self.state.config
    }

    /// Accepts the proposed protocol configuration.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn accept(self) -> Result<Verifier<state::Setup>, VerifierError> {
        let state::Config {
            mux_ctrl,
            mut mux_fut,
            mut ctx,
            config,
        } = self.state;

        mux_fut.poll_with(ctx.io_mut().send(Response::ok())).await?;

        let (vm, mut mpc_tls) = build_mpc_tls(&self.config, &config, ctx);

        // Allocate resources for MPC-TLS in the VM.
        let mut keys = mpc_tls.alloc()?;
        let vm_lock = vm.try_lock().expect("VM is not locked");
        translate_keys(&mut keys, &vm_lock)?;
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
                mpc_tls,
                keys,
                vm,
            },
        })
    }

    /// Rejects the proposed protocol configuration.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn reject(self, msg: Option<&str>) -> Result<(), VerifierError> {
        let state::Config {
            mux_ctrl,
            mut mux_fut,
            mut ctx,
            ..
        } = self.state;

        mux_fut
            .poll_with(ctx.io_mut().send(Response::err(msg)))
            .await?;

        // Wait for the prover to correctly close the connection.
        if !mux_fut.is_complete() {
            mux_ctrl.close();
            mux_fut.await?;
        }

        Ok(())
    }
}

impl Verifier<state::Setup> {
    /// Runs the verifier until the TLS connection is closed.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn run(self) -> Result<Verifier<state::Committed>, VerifierError> {
        let state::Setup {
            mux_ctrl,
            mut mux_fut,
            mpc_tls,
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

        Ok(Verifier {
            config: self.config,
            span: self.span,
            state: state::Committed {
                mux_ctrl,
                mux_fut,
                ctx,
                vm,
                keys,
                tls_transcript,
            },
        })
    }
}

impl Verifier<state::Committed> {
    /// Returns the TLS transcript.
    pub fn tls_transcript(&self) -> &TlsTranscript {
        &self.state.tls_transcript
    }

    /// Begins verification of statements from the prover.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn verify(self) -> Result<Verifier<state::Verify>, VerifierError> {
        let state::Committed {
            mux_ctrl,
            mut mux_fut,
            mut ctx,
            vm,
            keys,
            tls_transcript,
        } = self.state;

        let request = mux_fut
            .poll_with(ctx.io_mut().expect_next().map_err(VerifierError::from))
            .await?;

        Ok(Verifier {
            config: self.config,
            span: self.span,
            state: state::Verify {
                mux_ctrl,
                mux_fut,
                ctx,
                vm,
                keys,
                tls_transcript,
                request,
            },
        })
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

impl Verifier<state::Verify> {
    /// Returns the proving request.
    pub fn request(&self) -> &ProveRequest {
        &self.state.request
    }

    /// Accepts the proving request.
    pub async fn accept(
        self,
    ) -> Result<(VerifierOutput, Verifier<state::Committed>), VerifierError> {
        let state::Verify {
            mux_ctrl,
            mut mux_fut,
            mut ctx,
            mut vm,
            keys,
            tls_transcript,
            request,
        } = self.state;

        mux_fut.poll_with(ctx.io_mut().send(Response::ok())).await?;

        let cert_verifier = if let Some(root_store) = self.config.root_store() {
            ServerCertVerifier::new(root_store).map_err(VerifierError::config)?
        } else {
            ServerCertVerifier::mozilla()
        };

        let output = mux_fut
            .poll_with(verify::verify(
                &mut ctx,
                &mut vm,
                &keys,
                &cert_verifier,
                &tls_transcript,
                request,
            ))
            .await?;

        Ok((
            output,
            Verifier {
                config: self.config,
                span: self.span,
                state: state::Committed {
                    mux_ctrl,
                    mux_fut,
                    ctx,
                    vm,
                    keys,
                    tls_transcript,
                },
            },
        ))
    }

    /// Rejects the proving request.
    pub async fn reject(
        self,
        msg: Option<&str>,
    ) -> Result<Verifier<state::Committed>, VerifierError> {
        let state::Verify {
            mux_ctrl,
            mut mux_fut,
            mut ctx,
            vm,
            keys,
            tls_transcript,
            ..
        } = self.state;

        mux_fut
            .poll_with(ctx.io_mut().send(Response::err(msg)))
            .await?;

        Ok(Verifier {
            config: self.config,
            span: self.span,
            state: state::Committed {
                mux_ctrl,
                mux_fut,
                ctx,
                vm,
                keys,
                tls_transcript,
            },
        })
    }
}

fn build_mpc_tls(
    config: &VerifierConfig,
    protocol_config: &ProtocolConfig,
    ctx: Context,
) -> (Arc<Mutex<Deap<Mpc, Zk>>>, MpcTlsFollower) {
    let mut rng = rand::rng();

    let delta = Delta::random(&mut rng);
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
