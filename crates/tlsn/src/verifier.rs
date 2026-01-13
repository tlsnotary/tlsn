//! Verifier.

mod error;
pub mod state;
mod verify;

use std::sync::Arc;

pub use error::VerifierError;
pub use tlsn_core::{VerifierOutput, webpki::ServerCertVerifier};

use crate::{
    context::build_mt_context,
    mpz::{VerifierDeps, build_verifier_deps, translate_keys},
    msg::{ProveRequestMsg, Response, TlsCommitRequestMsg},
    mux::MuxFuture,
    tag::verify_tags,
};
use futures::{AsyncRead, AsyncWrite, TryFutureExt};
use mpz_vm_core::prelude::*;
use serio::{SinkExt, stream::IoStreamExt};
use tlsn_core::{
    config::{
        prove::ProveRequest,
        tls_commit::{TlsCommitProtocolConfig, TlsCommitRequest},
        verifier::VerifierConfig,
    },
    connection::{ConnectionInfo, ServerName},
    transcript::TlsTranscript,
};

use tracing::{Span, debug, info, info_span, instrument};

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

    /// Starts the TLS commitment protocol.
    ///
    /// This initiates the TLS commitment protocol, receiving the prover's
    /// configuration and providing the opportunity to accept or reject it.
    ///
    /// # Arguments
    ///
    /// * `socket` - The socket to the prover.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn commit<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
        self,
        socket: S,
    ) -> Result<Verifier<state::CommitStart<S>>, VerifierError> {
        let mut mux_fut = MuxFuture::new(socket);
        let mux_ctrl = mux_fut.handle()?;

        let mut mt = build_mt_context(mux_ctrl);
        let mut ctx = mux_fut.poll_with(mt.new_context()).await?;

        // Receives protocol configuration from prover to perform compatibility check.
        let TlsCommitRequestMsg { request, version } =
            mux_fut.poll_with(ctx.io_mut().expect_next()).await?;

        if version != *crate::VERSION {
            let msg = format!(
                "prover version does not match with verifier: {version} != {}",
                *crate::VERSION
            );
            mux_fut
                .poll_with(ctx.io_mut().send(Response::err(Some(msg.clone()))))
                .await?;

            mux_fut.close();
            mux_fut.await?;

            return Err(VerifierError::config(msg));
        }

        Ok(Verifier {
            config: self.config,
            span: self.span,
            state: state::CommitStart {
                mux_fut,
                ctx,
                request,
            },
        })
    }
}

impl<Io> Verifier<state::CommitStart<Io>>
where
    Io: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    /// Returns the TLS commitment request.
    pub fn request(&self) -> &TlsCommitRequest {
        &self.state.request
    }

    /// Accepts the proposed protocol configuration.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn accept(self) -> Result<Verifier<state::CommitAccepted<Io>>, VerifierError> {
        let state::CommitStart {
            mut mux_fut,
            mut ctx,
            request,
        } = self.state;

        mux_fut.poll_with(ctx.io_mut().send(Response::ok())).await?;

        let TlsCommitProtocolConfig::Mpc(mpc_tls_config) = request.protocol().clone() else {
            unreachable!("only MPC TLS is supported");
        };

        let VerifierDeps { vm, mut mpc_tls } = build_verifier_deps(mpc_tls_config, ctx);

        // Allocate resources for MPC-TLS in the VM.
        let mut keys = mpc_tls.alloc()?;
        let vm_lock = vm.try_lock().expect("VM is not locked");
        translate_keys(&mut keys, &vm_lock);
        drop(vm_lock);

        debug!("setting up mpc-tls");

        mux_fut.poll_with(mpc_tls.preprocess()).await?;

        debug!("mpc-tls setup complete");

        Ok(Verifier {
            config: self.config,
            span: self.span,
            state: state::CommitAccepted {
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
        let state::CommitStart {
            mut mux_fut,
            mut ctx,
            ..
        } = self.state;

        mux_fut
            .poll_with(ctx.io_mut().send(Response::err(msg)))
            .await?;

        mux_fut.close();
        mux_fut.await?;

        Ok(())
    }
}

impl<Io> Verifier<state::CommitAccepted<Io>>
where
    Io: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    /// Runs the verifier until the TLS connection is closed.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn run(self) -> Result<Verifier<state::Committed<Io>>, VerifierError> {
        let state::CommitAccepted {
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
                mux_fut,
                ctx,
                vm,
                keys,
                tls_transcript,
            },
        })
    }
}

impl<Io> Verifier<state::Committed<Io>>
where
    Io: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    /// Returns the TLS transcript.
    pub fn tls_transcript(&self) -> &TlsTranscript {
        &self.state.tls_transcript
    }

    /// Begins verification of statements from the prover.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn verify(self) -> Result<Verifier<state::Verify<Io>>, VerifierError> {
        let state::Committed {
            mut mux_fut,
            mut ctx,
            vm,
            keys,
            tls_transcript,
        } = self.state;

        let ProveRequestMsg {
            request,
            handshake,
            transcript,
        } = mux_fut
            .poll_with(ctx.io_mut().expect_next().map_err(VerifierError::from))
            .await?;

        Ok(Verifier {
            config: self.config,
            span: self.span,
            state: state::Verify {
                mux_fut,
                ctx,
                vm,
                keys,
                tls_transcript,
                request,
                handshake,
                transcript,
            },
        })
    }

    /// Closes the connection with the prover.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn close(mut self) -> Result<Io, VerifierError> {
        let mux_fut = &mut self.state.mux_fut;
        mux_fut.close();
        mux_fut.await?;

        self.state.mux_fut.into_io().map_err(VerifierError::from)
    }
}

impl<Io> Verifier<state::Verify<Io>>
where
    Io: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    /// Returns the proving request.
    pub fn request(&self) -> &ProveRequest {
        &self.state.request
    }

    /// Accepts the proving request.
    pub async fn accept(
        self,
    ) -> Result<(VerifierOutput, Verifier<state::Committed<Io>>), VerifierError> {
        let state::Verify {
            mut mux_fut,
            mut ctx,
            mut vm,
            keys,
            tls_transcript,
            request,
            handshake,
            transcript,
        } = self.state;

        mux_fut.poll_with(ctx.io_mut().send(Response::ok())).await?;

        let cert_verifier =
            ServerCertVerifier::new(self.config.root_store()).map_err(VerifierError::config)?;

        let output = mux_fut
            .poll_with(verify::verify(
                &mut ctx,
                &mut vm,
                &keys,
                &cert_verifier,
                &tls_transcript,
                request,
                handshake,
                transcript,
            ))
            .await?;

        Ok((
            output,
            Verifier {
                config: self.config,
                span: self.span,
                state: state::Committed {
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
    ) -> Result<Verifier<state::Committed<Io>>, VerifierError> {
        let state::Verify {
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
                mux_fut,
                ctx,
                vm,
                keys,
                tls_transcript,
            },
        })
    }
}
