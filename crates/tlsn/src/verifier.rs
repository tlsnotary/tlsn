//! Verifier.

mod error;
pub mod state;
mod verify;

use std::sync::Arc;

pub use error::VerifierError;
pub use tlsn_core::{VerifierOutput, webpki::ServerCertVerifier};

use crate::{
    BUF_CAP, Role,
    context::build_mt_context,
    mpz::{VerifierDeps, build_verifier_deps, translate_keys},
    msg::{ProveRequestMsg, Response, TlsCommitRequestMsg},
    mux::attach_mux,
    tag::verify_tags,
};
use futures::TryFutureExt;
use mpz_vm_core::prelude::*;
use serio::{SinkExt, stream::IoStreamExt};
use std::io::{Read, Write};
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
    pub async fn commit(self) -> Result<Verifier<state::CommitStart>, VerifierError> {
        let (duplex_a, duplex_b) = futures_plex::duplex(BUF_CAP);

        let (mut mux_fut, mux_ctrl) = attach_mux(duplex_b, Role::Verifier);
        let mut mt = build_mt_context(mux_ctrl.clone());
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
            state: state::CommitStart {
                mpc_duplex: duplex_a,
                mux_ctrl,
                mux_fut,
                ctx,
                request,
            },
        })
    }
}

impl Verifier<state::CommitStart> {
    /// Returns the TLS commitment request.
    pub fn request(&self) -> &TlsCommitRequest {
        &self.state.request
    }

    /// Accepts the proposed protocol configuration.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn accept(self) -> Result<Verifier<state::CommitAccepted>, VerifierError> {
        let state::CommitStart {
            mpc_duplex,
            mux_ctrl,
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
                mpc_duplex,
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
        let state::CommitStart {
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

    /// Returns `true` if the verifier wants to read data from the prover.
    pub fn wants_read_prover(&self) -> bool {
        self.state.mpc_duplex.remaining_mut() > 0
    }

    /// Returns `true` if the verifier wants to write data to the prover.
    pub fn wants_write_prover(&self) -> bool {
        self.state.mpc_duplex.remaining() > 0
    }

    /// Reads bytes for the verifier from a buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer.
    pub fn read_prover(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.state.mpc_duplex.write(buf)
    }

    /// Writes bytes for the prover into a buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer.
    pub fn write_prover(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.state.mpc_duplex.read(buf)
    }
}

impl Verifier<state::CommitAccepted> {
    /// Runs the verifier until the TLS connection is closed.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn run(self) -> Result<Verifier<state::Committed>, VerifierError> {
        let state::CommitAccepted {
            mpc_duplex,
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
                mpc_duplex,
                mux_ctrl,
                mux_fut,
                ctx,
                vm,
                keys,
                tls_transcript,
            },
        })
    }

    /// Returns `true` if the verifier wants to read data from the prover.
    pub fn wants_read_prover(&self) -> bool {
        self.state.mpc_duplex.remaining_mut() > 0
    }

    /// Returns `true` if the verifier wants to write data to the prover.
    pub fn wants_write_prover(&self) -> bool {
        self.state.mpc_duplex.remaining() > 0
    }

    /// Reads bytes for the verifier from a buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer.
    pub fn read_prover(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.state.mpc_duplex.write(buf)
    }

    /// Writes bytes for the prover into a buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer.
    pub fn write_prover(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.state.mpc_duplex.read(buf)
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
            mpc_duplex,
            mux_ctrl,
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
                mpc_duplex,
                mux_ctrl,
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

    /// Returns `true` if the verifier wants to read data from the prover.
    pub fn wants_read_prover(&self) -> bool {
        self.state.mpc_duplex.remaining_mut() > 0
    }

    /// Returns `true` if the verifier wants to write data to the prover.
    pub fn wants_write_prover(&self) -> bool {
        self.state.mpc_duplex.remaining() > 0
    }

    /// Reads bytes for the verifier from a buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer.
    pub fn read_prover(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.state.mpc_duplex.write(buf)
    }

    /// Writes bytes for the prover into a buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer.
    pub fn write_prover(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.state.mpc_duplex.read(buf)
    }

    /// Closes the connection with the prover.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn close(self) -> Result<(), VerifierError> {
        let state::Committed {
            mut mpc_duplex,
            mux_ctrl,
            mux_fut,
            ..
        } = self.state;

        // Wait for the prover to correctly close the connection.
        if !mux_fut.is_complete() {
            mux_ctrl.close();
            mux_fut.await?;
            futures::AsyncWriteExt::close(&mut mpc_duplex).await?;
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
            mpc_duplex,
            mux_ctrl,
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
                    mpc_duplex,
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
            mpc_duplex,
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
                mpc_duplex,
                mux_ctrl,
                mux_fut,
                ctx,
                vm,
                keys,
                tls_transcript,
            },
        })
    }

    /// Returns `true` if the verifier wants to read data from the prover.
    pub fn wants_read_prover(&self) -> bool {
        self.state.mpc_duplex.remaining_mut() > 0
    }

    /// Returns `true` if the verifier wants to write data to the prover.
    pub fn wants_write_prover(&self) -> bool {
        self.state.mpc_duplex.remaining() > 0
    }

    /// Reads bytes for the verifier from a buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer.
    pub fn read_prover(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.state.mpc_duplex.write(buf)
    }

    /// Writes bytes for the prover into a buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer.
    pub fn write_prover(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.state.mpc_duplex.read(buf)
    }
}
