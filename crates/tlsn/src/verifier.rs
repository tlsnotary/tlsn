//! Verifier.

pub mod state;
mod verify;

pub use tlsn_core::{VerifierOutput, webpki::ServerCertVerifier};

use crate::{
    Error, PROXY_STREAM_PREFIX, Result,
    deps::{ProtocolDeps, VerifierMpcDeps, VerifierProxyDeps},
    msg::{ProveRequestMsg, Response, TlsCommitRequestMsg},
    proxy::InspectReader,
    tag::verify_tags,
};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use mpz_common::Context;
use mpz_vm_core::prelude::*;
use serio::{SinkExt, stream::IoStreamExt};
use std::sync::Arc;
use tlsn_core::{
    config::{
        prove::ProveRequest,
        tls_commit::{TlsCommitRequest, mpc::MpcTlsConfig, proxy::ProxyTlsConfig},
        verifier::VerifierConfig,
    },
    connection::{ConnectionInfo, ServerName},
    transcript::TlsTranscript,
};
use tlsn_mux::Handle;
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
    ctx: Option<Context>,
    mux_handle: Handle,
    state: T,
}

impl Verifier<state::Initialized> {
    /// Creates a new verifier.
    ///
    /// # Arguments
    ///
    /// * `ctx` - A thread context.
    /// * `mux_handle` - A handle for the multiplexer.
    /// * `config` - The configuration for the verifier.
    pub(crate) fn new(ctx: Context, mux_handle: Handle, config: VerifierConfig) -> Self {
        let span = info_span!("verifier");
        Self {
            config,
            span,
            ctx: Some(ctx),
            mux_handle,
            state: state::Initialized,
        }
    }

    /// Starts the TLS commitment protocol.
    ///
    /// This initiates the TLS commitment protocol, receiving the prover's
    /// configuration and providing the opportunity to accept or reject it.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn commit(mut self) -> Result<Verifier<state::CommitStart>> {
        let mut ctx = self
            .ctx
            .take()
            .ok_or_else(|| Error::internal().with_msg("commitment protocol context was dropped"))?;

        // Receives protocol configuration from prover to perform compatibility check.
        let TlsCommitRequestMsg { request, version } =
            ctx.io_mut().expect_next().await.map_err(|e| {
                Error::io()
                    .with_msg("commitment protocol failed to receive request")
                    .with_source(e)
            })?;

        if version != *crate::VERSION {
            let msg = format!(
                "prover version does not match with verifier: {version} != {}",
                *crate::VERSION
            );
            ctx.io_mut()
                .send(Response::err(Some(msg.clone())))
                .await
                .map_err(|e| {
                    Error::io()
                        .with_msg("commitment protocol failed to send version mismatch response")
                        .with_source(e)
                })?;

            return Err(Error::config().with_msg(msg));
        }

        Ok(Verifier {
            config: self.config,
            span: self.span,
            ctx: Some(ctx),
            mux_handle: self.mux_handle,
            state: state::CommitStart { request },
        })
    }
}

/// Commit accepted verifiers for different protocols.
pub enum VerifierCommitAccepted {
    /// Verifier for MPC protocol.
    Mpc(Verifier<state::CommitAccepted<MpcTlsConfig>>),
    /// Verifier for Proxy protocol.
    Proxy(Verifier<state::CommitAccepted<ProxyTlsConfig>>),
}

impl Verifier<state::CommitStart> {
    /// Returns the TLS commitment request.
    pub fn request(&self) -> &TlsCommitRequest {
        &self.state.request
    }

    /// Accepts the proposed protocol configuration.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn accept(mut self) -> Result<VerifierCommitAccepted> {
        let mut ctx = self
            .ctx
            .take()
            .ok_or_else(|| Error::internal().with_msg("commitment protocol context was dropped"))?;

        ctx.io_mut().send(Response::ok()).await.map_err(|e| {
            Error::io()
                .with_msg("commitment protocol failed to send acceptance")
                .with_source(e)
        })?;

        match self.request() {
            TlsCommitRequest::Mpc(config) => {
                let mut deps = VerifierMpcDeps::new(config, ctx);
                deps.setup().await?;

                debug!("setup complete");

                let verifier = Verifier {
                    config: self.config,
                    span: self.span,
                    ctx: None,
                    mux_handle: self.mux_handle,
                    state: state::CommitAccepted { deps },
                };
                Ok(VerifierCommitAccepted::Mpc(verifier))
            }
            TlsCommitRequest::Proxy(config) => {
                let mut deps = VerifierProxyDeps::new(config, ctx);
                deps.setup().await?;

                debug!("setup complete");

                let verifier = Verifier {
                    config: self.config,
                    span: self.span,
                    ctx: None,
                    mux_handle: self.mux_handle,
                    state: state::CommitAccepted { deps },
                };
                Ok(VerifierCommitAccepted::Proxy(verifier))
            }
            _ => Err(Error::config().with_msg("unsupported protocol request")),
        }
    }

    /// Rejects the proposed protocol configuration.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn reject(mut self, msg: Option<&str>) -> Result<()> {
        let mut ctx = self
            .ctx
            .take()
            .ok_or_else(|| Error::internal().with_msg("commitment protocol context was dropped"))?;

        ctx.io_mut().send(Response::err(msg)).await.map_err(|e| {
            Error::io()
                .with_msg("commitment protocol failed to send rejection")
                .with_source(e)
        })?;

        Ok(())
    }
}

impl Verifier<state::CommitAccepted<MpcTlsConfig>> {
    /// Runs the verifier until the TLS connection is closed.
    ///
    /// This method is used for MPC mode only.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn run(self) -> Result<Verifier<state::Committed>> {
        let VerifierMpcDeps { vm, mpc_tls, keys } = self.state.deps;

        info!("starting MPC-TLS");
        let (mut ctx, tls_transcript) = mpc_tls.run().await.map_err(|e| {
            Error::internal()
                .with_msg("mpc-tls execution failed")
                .with_source(e)
        })?;

        info!("finished MPC-TLS");

        {
            let mut vm = vm.try_lock().expect("VM should not be locked");

            debug!("finalizing mpc");

            vm.finalize(&mut ctx).await.map_err(|e| {
                Error::internal()
                    .with_msg("mpc finalization failed")
                    .with_source(e)
            })?;

            debug!("mpc finalized");
        }

        // Pull out ZK VM.
        let (_, mut vm) = Arc::into_inner(vm)
            .expect("vm should have only 1 reference")
            .into_inner()
            .into_inner();
        let keys = keys.expect("keys should be available");

        // Prepare for the prover to prove tag verification of the received
        // records.
        let tag_proof = verify_tags(
            &mut vm,
            (keys.server_write_key, keys.server_write_iv),
            keys.server_write_mac_key,
            *tls_transcript.version(),
            tls_transcript.recv().to_vec(),
        )
        .map_err(|e| {
            Error::internal()
                .with_msg("tag verification setup failed")
                .with_source(e)
        })?;

        vm.execute_all(&mut ctx).await.map_err(|e| {
            Error::internal()
                .with_msg("tag verification zk execution failed")
                .with_source(e)
        })?;

        // Verify the tags.
        // After the verification, the entire TLS trancript becomes
        // authenticated from the verifier's perspective.
        tag_proof.verify().map_err(|e| {
            Error::internal()
                .with_msg("tag verification failed")
                .with_source(e)
        })?;

        debug!("verified tags successfully");

        Ok(Verifier {
            config: self.config,
            span: self.span,
            ctx: Some(ctx),
            mux_handle: self.mux_handle,
            state: state::Committed {
                vm,
                keys,
                tls_transcript,
            },
        })
    }
}

impl Verifier<state::CommitAccepted<ProxyTlsConfig>> {
    /// Runs the verifier until the TLS connection is closed.
    ///
    /// This method is used for proxy mode only.
    ///
    /// # Arguments
    ///
    /// * `server_socket` - The connection to the server.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn run<T>(self, server_socket: T) -> Result<Verifier<state::Committed>>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin,
    {
        let VerifierProxyDeps { verifier, id } = self.state.deps;

        let mut sent_buf = Vec::new();
        let mut recv_buf = Vec::new();

        info!("starting Proxy-TLS");

        let mut proxy_id = PROXY_STREAM_PREFIX.to_vec();
        proxy_id.extend_from_slice(id.as_bytes());

        let prover_socket = self.mux_handle.new_stream(&proxy_id)?;

        let (prover_read, mut prover_write) = prover_socket.split();
        let (server_read, mut server_write) = server_socket.split();

        let mut prover_reader = InspectReader::new(prover_read, &mut sent_buf);
        let mut server_reader = InspectReader::new(server_read, &mut recv_buf);

        futures::future::try_join(
            async {
                futures::io::copy(&mut prover_reader, &mut server_write).await?;
                server_write.close().await
            },
            async {
                futures::io::copy(&mut server_reader, &mut prover_write).await?;
                prover_write.close().await
            },
        )
        .await
        .map_err(|e| {
            Error::io()
                .with_msg("proxy traffic forwarding failed")
                .with_source(e)
        })?;
        info!("proxying TLS traffic finished");

        let conn_time = prover_reader
            .first_read()
            .expect("connection time should have been set");

        let (mut ctx, mut vm, output, cf_vd_check, sf_vd_check) =
            verifier.finalize(&sent_buf, &recv_buf, conn_time).await?;

        let keys = output.keys;
        let tls_transcript = output.tls_transcript;

        // Prepare for the prover to prove tag verification of the received
        // records.
        let tag_proof = verify_tags(
            &mut vm,
            (keys.server_write_key, keys.server_write_iv),
            keys.server_write_mac_key,
            *tls_transcript.version(),
            tls_transcript.recv().to_vec(),
        )
        .map_err(|e| {
            Error::internal()
                .with_msg("tag verification setup failed")
                .with_source(e)
        })?;

        vm.execute_all(&mut ctx).await.map_err(|e| {
            Error::internal()
                .with_msg("tag verification zk execution failed")
                .with_source(e)
        })?;

        // Verify the tags.
        // After the verification, the entire TLS trancript becomes
        // authenticated from the verifier's perspective.
        tag_proof.verify().map_err(|e| {
            Error::internal()
                .with_msg("tag verification failed")
                .with_source(e)
        })?;
        debug!("verified tags successfully");

        // Verify finished records
        cf_vd_check.check(&mut vm)?;
        sf_vd_check.check(&mut vm)?;
        debug!("verified finished records successfully");

        Ok(Verifier {
            config: self.config,
            span: self.span,
            ctx: Some(ctx),
            mux_handle: self.mux_handle,
            state: state::Committed {
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
    pub async fn verify(mut self) -> Result<Verifier<state::Verify>> {
        let mut ctx = self
            .ctx
            .take()
            .ok_or_else(|| Error::internal().with_msg("verification context was dropped"))?;
        let state::Committed {
            vm,
            keys,
            tls_transcript,
        } = self.state;

        let ProveRequestMsg {
            request,
            handshake,
            transcript,
        } = ctx.io_mut().expect_next().await.map_err(|e| {
            Error::io()
                .with_msg("verification failed to receive prove request")
                .with_source(e)
        })?;

        Ok(Verifier {
            config: self.config,
            span: self.span,
            ctx: Some(ctx),
            mux_handle: self.mux_handle,
            state: state::Verify {
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
    pub async fn close(self) -> Result<()> {
        Ok(())
    }
}

impl Verifier<state::Verify> {
    /// Returns the proving request.
    pub fn request(&self) -> &ProveRequest {
        &self.state.request
    }

    /// Accepts the proving request.
    pub async fn accept(mut self) -> Result<(VerifierOutput, Verifier<state::Committed>)> {
        let mut ctx = self
            .ctx
            .take()
            .ok_or_else(|| Error::internal().with_msg("verification context was dropped"))?;
        let state::Verify {
            mut vm,
            keys,
            tls_transcript,
            request,
            handshake,
            transcript,
        } = self.state;

        ctx.io_mut().send(Response::ok()).await.map_err(|e| {
            Error::io()
                .with_msg("verification failed to send acceptance")
                .with_source(e)
        })?;

        let cert_verifier = ServerCertVerifier::new(self.config.root_store()).map_err(|e| {
            Error::config()
                .with_msg("failed to create certificate verifier")
                .with_source(e)
        })?;

        let output = verify::verify(
            &mut ctx,
            &mut vm,
            &keys,
            &cert_verifier,
            &tls_transcript,
            request,
            handshake,
            transcript,
        )
        .await?;

        Ok((
            output,
            Verifier {
                config: self.config,
                span: self.span,
                ctx: Some(ctx),
                mux_handle: self.mux_handle,
                state: state::Committed {
                    vm,
                    keys,
                    tls_transcript,
                },
            },
        ))
    }

    /// Rejects the proving request.
    pub async fn reject(mut self, msg: Option<&str>) -> Result<Verifier<state::Committed>> {
        let mut ctx = self
            .ctx
            .take()
            .ok_or_else(|| Error::internal().with_msg("verification context was dropped"))?;
        let state::Verify {
            vm,
            keys,
            tls_transcript,
            ..
        } = self.state;

        ctx.io_mut().send(Response::err(msg)).await.map_err(|e| {
            Error::io()
                .with_msg("verification failed to send rejection")
                .with_source(e)
        })?;

        Ok(Verifier {
            config: self.config,
            span: self.span,
            ctx: Some(ctx),
            mux_handle: self.mux_handle,
            state: state::Committed {
                vm,
                keys,
                tls_transcript,
            },
        })
    }
}
