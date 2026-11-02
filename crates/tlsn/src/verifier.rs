//! Verifier.

pub mod state;
mod verify;

pub use tlsn_core::{VerifierOutput, webpki::ServerCertVerifier};

use crate::{
    Error, Mpc, PROXY_STREAM_PREFIX, Proxy, Result,
    deps::{VerifierDeps, VerifierMpcDeps, VerifierProxyDeps},
    future::{Aux, poll_with},
    msg::{ProveRequestMsg, Response, TlsCommitRequestMsg},
    proxy::InspectReader,
    session::SessionClosure,
    tag::verify_tags,
};
use futures::{
use futures::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
    future::{Either, select},
};
    future::{Either, select},
};
use mpz_common::Context;
use mpz_vm_core::prelude::*;
use serio::{SinkExt, stream::IoStreamExt};
use std::{marker::PhantomData, sync::Arc};
use tlsn_core::{
    config::{
        prove::ProveRequest,
        tls_commit::{TlsCommitConfig, mpc::MpcTlsConfig, proxy::ProxyTlsConfig},
        verifier::VerifierConfig,
    },
    connection::{ConnectionInfo, ServerName},
    transcript::TlsTranscript,
};
use tlsn_mux::Handle;
use tracing::{Span, debug, info, info_span, instrument, warn};

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
    closure: Arc<SessionClosure>,
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
    pub(crate) fn new(
        ctx: Context,
        mux_handle: Handle,
        config: VerifierConfig,
        closure: Arc<SessionClosure>,
    ) -> Self {
        let span = info_span!("verifier");
        Self {
            config,
            span,
            ctx: Some(ctx),
            mux_handle,
            closure,
            state: state::Initialized,
        }
    }

    /// Starts the TLS commitment protocol.
    ///
    /// This initiates the TLS commitment protocol, receiving the prover's
    /// configuration and providing the opportunity to accept or reject it.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn commit(mut self) -> Result<VerifierCommitStart> {
        let mut ctx = self
            .ctx
            .take()
            .ok_or_else(|| Error::internal().with_msg("commitment protocol context was dropped"))?;

        // Receives protocol configuration from prover to perform compatibility
        // check.
        let TlsCommitRequestMsg { config, version } =
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

        let verifier = match &config {
            TlsCommitConfig::Mpc(_) => VerifierCommitStart::Mpc(Verifier {
                config: self.config,
                span: self.span,
                ctx: Some(ctx),
                mux_handle: self.mux_handle,
                closure: self.closure,
                state: state::CommitStart {
                    config,
                    _pd: PhantomData,
                },
            }),
            TlsCommitConfig::Proxy(_) => VerifierCommitStart::Proxy(Verifier {
                config: self.config,
                span: self.span,
                ctx: Some(ctx),
                mux_handle: self.mux_handle,
                closure: self.closure,
                state: state::CommitStart {
                    config,
                    _pd: PhantomData,
                },
            }),
            _ => return Err(Error::config().with_msg("unknown protocol requested")),
        };

        Ok(verifier)
    }
}

/// Commit started verifiers for different protocols.
pub enum VerifierCommitStart {
    /// Verifier for MPC protocol.
    Mpc(Verifier<state::CommitStart<Mpc>>),
    /// Verifier for Proxy protocol.
    Proxy(Verifier<state::CommitStart<Proxy>>),
}

impl<P> Verifier<state::CommitStart<P>> {
    /// Accepts the proposed protocol configuration.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn accept(mut self) -> Result<Verifier<state::CommitAccepted<P>>> {
        let mut ctx = self
            .ctx
            .take()
            .ok_or_else(|| Error::internal().with_msg("commitment protocol context was dropped"))?;

        ctx.io_mut().send(Response::ok()).await.map_err(|e| {
            Error::io()
                .with_msg("commitment protocol failed to send acceptance")
                .with_source(e)
        })?;

        let mut deps = VerifierDeps::new(&self.state.config, ctx);
        deps.setup().await?;

        debug!("setup complete");

        let verifier = Verifier {
            config: self.config,
            span: self.span,
            ctx: None,
            mux_handle: self.mux_handle,
            closure: self.closure,
            state: state::CommitAccepted {
                deps,
                _pd: PhantomData,
            },
        };

        Ok(verifier)
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

impl Verifier<state::CommitStart<Mpc>> {
    /// Returns the commit config.
    pub fn config(&self) -> &MpcTlsConfig {
        let TlsCommitConfig::Mpc(config) = &self.state.config else {
            unreachable!("mpc-tls received incorrect config")
        };
        config
    }
}

impl Verifier<state::CommitStart<Proxy>> {
    /// Returns the commit config.
    pub fn config(&self) -> &ProxyTlsConfig {
        let TlsCommitConfig::Proxy(config) = &self.state.config else {
            unreachable!("proxy-tls received incorrect config")
        };
        config
    }
}

impl Verifier<state::CommitAccepted<Mpc>> {
    /// Runs the verifier until the TLS connection is closed.
    ///
    /// This method is used for MPC mode only.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn run(self) -> Result<Verifier<state::Committed>> {
        let closure = self.closure.clone();
        match select(Box::pin(self.run_inner()), Box::pin(closure.closed())).await {
            Either::Left((result, _)) => result,
            Either::Right(_) => {
                Err(Error::io().with_msg("session closed while the verifier was running"))
            }
        }
    }

    async fn run_inner(self) -> Result<Verifier<state::Committed>> {
        let VerifierDeps::Mpc(VerifierMpcDeps { vm, mpc_tls, keys }) = self.state.deps else {
            unreachable!("mpc-tls received incorrect deps")
        };

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
            tls_transcript.version(),
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
            closure: self.closure,
            state: state::Committed {
                vm,
                keys,
                tls_transcript,
            },
        })
    }
}

type ProxyForwardFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send + 'a>>;

/// The proxy forwarding direction which is still running.
enum RemainingProxy<'a> {
    ProverToServer(ProxyForwardFuture<'a>),
    ServerToProver(ProxyForwardFuture<'a>),
}

impl Verifier<state::CommitAccepted<Proxy>> {
    /// Runs the verifier until the TLS connection is closed.
    ///
    /// This method is used for proxy mode only.
    ///
    /// # Arguments
    ///
    /// * `server_socket` - The connection to the server. On TCP transports,
    ///   disable Nagle's algorithm; see [Performance](crate#performance).
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn run<T>(self, server_socket: T) -> Result<Verifier<state::Committed>>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin,
    {
        let closure = self.closure.clone();
        match select(
            Box::pin(self.run_inner(server_socket)),
            Box::pin(closure.closed()),
        )
        .await
        {
            Either::Left((result, _)) => result,
            Either::Right(_) => {
                Err(Error::io().with_msg("session closed while the verifier was running"))
            }
        }
    }

    async fn run_inner<T>(self, server_socket: T) -> Result<Verifier<state::Committed>>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin,
    {
        let VerifierDeps::Proxy(deps) = self.state.deps else {
            unreachable!("proxy-tls received incorrect deps")
        };
        let VerifierProxyDeps { mut verifier, id } = deps;

        let mut sent_buf = Vec::new();
        let mut recv_buf = Vec::new();

        info!("starting Proxy-TLS");

        let mut proxy_id = PROXY_STREAM_PREFIX.to_vec();
        proxy_id.extend_from_slice(id.as_bytes());

        let prover_socket = self.mux_handle.new_stream(&proxy_id)?;

        let (prover_read, prover_write) = prover_socket.split();
        let (server_read, server_write) = server_socket.split();

        let conn_time = {
            let mut prover_write = prover_write;
            let mut server_write = server_write;
            let mut prover_reader = InspectReader::new(prover_read, &mut sent_buf);
            let mut server_reader = InspectReader::new(server_read, &mut recv_buf);

            let p2s = Box::pin(async {
                // Failure to write prover data to the server is fatal.
                futures::io::copy(&mut prover_reader, &mut server_write).await?;
                if let Err(err) = server_write.close().await {
                    log_proxy_close_error("server", &err);
                }
                Ok::<(), std::io::Error>(())
            });
            let s2p = Box::pin(async {
                let result = futures::io::copy(&mut server_reader, &mut prover_write).await;
                if let Err(err) = prover_write.close().await {
                    log_proxy_close_error("prover", &err);
                }
                result.map(|_| ())
            });

            // Whichever direction ends first determines how the other
            // direction must be treated.
            let (first_result, remaining) = match select(p2s, s2p).await {
                // p2s completed first, so s2p remains.
                Either::Left((result, remaining)) => (
                    result,
                    RemainingProxy::ServerToProver(Box::pin(remaining)),
                ),
                // s2p completed first, so p2s remains.
                Either::Right((result, remaining)) => (
                    result,
                    RemainingProxy::ProverToServer(Box::pin(remaining)),
                ),
            };

            {
                // Keep the remaining future's borrow scoped to this block so
                // the prover reader can be inspected afterwards.
                let remaining_direction = remaining;

                match remaining_direction {
                    RemainingProxy::ServerToProver(server_to_prover) => {
                        // p2s completed first; a p2s failure is fatal.
                        first_result.map_err(|err| {
                            Error::io()
                                .with_msg("proxy traffic forwarding failed")
                                .with_source(err)
                        })?;

                        // The prover only signals completion after observing
                        // a terminal server signal through s2p. Keep
                        // forwarding server data until then; afterwards s2p
                        // may remain open.
                        let (finished_result, server_to_prover) =
                            poll_with(verifier.wait_finished(), server_to_prover).await;
                        finished_result?;

                        match server_to_prover {
                            Aux::Pending(future) => {
                                debug!(
                                    "server forwarding still in progress after the prover finished"
                                );
                                drop(future);
                            }
                            Aux::Completed(result) => {
                                if let Err(err) = result {
                                    debug!(
                                        "server forwarding ended with an error after the prover finished: {err}"
                                    );
                                }
                            }
                        }
                    }
                    RemainingProxy::ProverToServer(prover_to_server) => {
                        // s2p completed first. Its error does not imply the
                        // server is closed, so leave p2s running.
                        if let Err(err) = first_result {
                            debug!("server forwarding ended early: {err}");
                        }

                        // The prover may signal completion before its queued
                        // TLS bytes, including its FIN, have reached the
                        // verifier. Both the control message and p2s EOF are
                        // required.
                        let prover_to_server = async {
                            prover_to_server.await.map_err(|err| {
                                Error::io()
                                    .with_msg("proxy traffic forwarding failed")
                                    .with_source(err)
                            })
                        };

                        futures::try_join!(verifier.wait_finished(), prover_to_server)?;
                    }
                }
            }

            prover_reader.first_read()
        };

        info!("proxying TLS traffic finished");

        // If the prover goes away before forwarding a single byte there is no
        // connection time and no transcript to verify. This is a peer failure,
        // not an internal invariant, so surface it as an error.
        let conn_time = conn_time
            .ok_or_else(|| Error::io().with_msg("prover closed before sending any data"))?;

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
            tls_transcript.version(),
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
            closure: self.closure,
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
            closure: self.closure,
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
                closure: self.closure,
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
            closure: self.closure,
            state: state::Committed {
                vm,
                keys,
                tls_transcript,
            },
        })
    }
}

fn log_proxy_close_error(peer: &str, err: &std::io::Error) {
    if matches!(
        err.kind(),
        std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
    ) {
        debug!(
            "failed to close {peer} transport write half: {err}; \
             the peer may already be gone and the transport FIN may not have been delivered"
        );
    } else {
        warn!(
            "failed to close {peer} transport write half: {err}; \
             the transport FIN may not have been delivered"
        );
    }
}
