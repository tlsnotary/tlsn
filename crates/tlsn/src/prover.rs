//! Prover.

mod client;
mod conn;
mod control;
mod future;
mod prove;
pub mod state;

pub use conn::TlsConnection;
pub use control::ProverControl;
pub use future::ProverFuture;
pub use tlsn_core::ProverOutput;

use crate::{
    Error, Result,
    mpz::{ProverDeps, build_prover_deps, translate_keys},
    msg::{ProveRequestMsg, Response, TlsCommitRequestMsg},
    prover::{
        client::{MpcTlsClient, TlsOutput},
        state::ConnectedProj,
    },
};

use futures::{AsyncRead, AsyncWrite, TryFutureExt, ready};
use mpz_common::Context;
use rustls_pki_types::CertificateDer;
use serio::{SinkExt, stream::IoStreamExt};
use std::{pin::Pin, sync::Arc, task::Poll};
use tls_client::{ClientConnection, ServerName as TlsServerName};
use tlsn_core::{
    config::{
        prove::ProveConfig,
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::{TlsCommitConfig, TlsCommitProtocolConfig},
    },
    connection::{HandshakeData, ServerName},
    transcript::{TlsTranscript, Transcript},
};
use tracing::{Span, debug, info_span, instrument};
use webpki::anchor_from_trusted_cert;

const BUF_CAP: usize = 16 * 1024 * 1024;

/// A prover instance.
#[derive(Debug)]
pub struct Prover<T: state::ProverState = state::Initialized> {
    config: ProverConfig,
    span: Span,
    ctx: Option<Context>,
    state: T,
}

impl Prover<state::Initialized> {
    /// Creates a new prover.
    ///
    /// # Arguments
    ///
    /// * `ctx` - A thread context.
    /// * `config` - The configuration for the prover.
    pub(crate) fn new(ctx: Context, config: ProverConfig) -> Self {
        let span = info_span!("prover");
        Self {
            config,
            span,
            ctx: Some(ctx),
            state: state::Initialized,
        }
    }

    /// Starts the TLS commitment protocol.
    ///
    /// This initiates the TLS commitment protocol, including performing any
    /// necessary preprocessing operations.
    ///
    /// # Arguments
    ///
    /// * `config` - The TLS commitment configuration.
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub async fn commit(
        mut self,
        config: TlsCommitConfig,
    ) -> Result<Prover<state::CommitAccepted>> {
        let mut ctx = self
            .ctx
            .take()
            .ok_or_else(|| Error::internal().with_msg("commitment protocol context was dropped"))?;

        // Sends protocol configuration to verifier for compatibility check.
        ctx.io_mut()
            .send(TlsCommitRequestMsg {
                request: config.to_request(),
                version: crate::VERSION.clone(),
            })
            .await
            .map_err(|e| {
                Error::io()
                    .with_msg("commitment protocol failed to send request")
                    .with_source(e)
            })?;

        ctx.io_mut()
            .expect_next::<Response>()
            .await
            .map_err(|e| {
                Error::io()
                    .with_msg("commitment protocol failed to receive response")
                    .with_source(e)
            })?
            .result
            .map_err(|e| {
                Error::user()
                    .with_msg("commitment protocol rejected by verifier")
                    .with_source(e)
            })?;

        let TlsCommitProtocolConfig::Mpc(mpc_tls_config) = config.protocol().clone() else {
            unreachable!("only MPC TLS is supported");
        };

        let ProverDeps { vm, mut mpc_tls } = build_prover_deps(mpc_tls_config, ctx);

        // Allocate resources for MPC-TLS in the VM.
        let mut keys = mpc_tls.alloc().map_err(|e| {
            Error::internal()
                .with_msg("commitment protocol failed to allocate mpc-tls resources")
                .with_source(e)
        })?;
        let vm_lock = vm.try_lock().expect("VM is not locked");
        translate_keys(&mut keys, &vm_lock);
        drop(vm_lock);

        debug!("setting up mpc-tls");

        mpc_tls.preprocess().await.map_err(|e| {
            Error::internal()
                .with_msg("commitment protocol failed during mpc-tls preprocessing")
                .with_source(e)
        })?;

        debug!("mpc-tls setup complete");

        Ok(Prover {
            config: self.config,
            span: self.span,
            ctx: None,
            state: state::CommitAccepted { mpc_tls, keys, vm },
        })
    }
}

impl Prover<state::CommitAccepted> {
    /// Connects to the server using the provided socket.
    ///
    /// Returns a handle to the TLS connection, a future which returns the
    /// prover once the connection is closed and the TLS transcript is
    /// committed.
    ///
    /// # Arguments
    ///
    /// * `config` - The TLS client configuration.
    /// * `socket` - The socket to the server.
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub fn connect<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
        self,
        config: TlsClientConfig,
        socket: S,
    ) -> Result<(TlsConnection, ProverFuture<S>)> {
        let state::CommitAccepted {
            mpc_tls, keys, vm, ..
        } = self.state;

        let decrypt = mpc_tls.is_decrypting();
        let (mpc_ctrl, mpc_fut) = mpc_tls.run();

        let ServerName::Dns(server_name) = config.server_name();
        let server_name =
            TlsServerName::try_from(server_name.as_ref()).expect("name was validated");

        let root_store = tls_client::RootCertStore {
            roots: config
                .root_store()
                .roots
                .iter()
                .map(|cert| {
                    let der = CertificateDer::from_slice(&cert.0);
                    anchor_from_trusted_cert(&der)
                        .map(|anchor| anchor.to_owned())
                        .map_err(|e| {
                            Error::config()
                                .with_msg("failed to parse root certificate")
                                .with_source(e)
                        })
                })
                .collect::<Result<Vec<_>, _>>()?,
        };

        let rustls_config = tls_client::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store);

        let rustls_config = if let Some((cert, key)) = config.client_auth() {
            rustls_config
                .with_single_cert(
                    cert.iter()
                        .map(|cert| tls_client::Certificate(cert.0.clone()))
                        .collect(),
                    tls_client::PrivateKey(key.0.clone()),
                )
                .map_err(|e| {
                    Error::config()
                        .with_msg("failed to configure client authentication")
                        .with_source(e)
                })?
        } else {
            rustls_config.with_no_client_auth()
        };

        let client = ClientConnection::new(
            Arc::new(rustls_config),
            Box::new(mpc_ctrl.clone()),
            server_name,
        )
        .map_err(|e| {
            Error::config()
                .with_msg("failed to create tls client connection")
                .with_source(e)
        })?;

        let span = self.span.clone();
        let mpc_tls = MpcTlsClient::new(
            Box::new(mpc_fut.map_err(Error::from)),
            keys,
            vm,
            span,
            mpc_ctrl,
            client,
            decrypt,
        );

        let (client_io, tlsn_conn) = futures_plex::duplex(BUF_CAP);
        let (client_to_server, server_to_client) = futures_plex::duplex(BUF_CAP);

        let prover = Prover {
            ctx: self.ctx,
            config: self.config,
            span: self.span,
            state: state::Connected {
                server_name: config.server_name().clone(),
                tls_client: Box::new(mpc_tls),
                client_io,
                output: None,
                server_socket: socket,
                client_to_server,
                server_to_client,
                client_closed: false,
                server_closed: false,
            },
        };

        let conn = TlsConnection::new(tlsn_conn);
        let fut = ProverFuture {
            prover: Some(prover),
        };

        Ok((conn, fut))
    }
}

impl<S> Future for Prover<state::Connected<S>>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type Output = Result<(), Error>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Self::Output> {
        let mut state = Pin::new(&mut self.state).project();

        if state.output.is_none()
            && let Poll::Ready(output) = state.tls_client.poll(cx)?
        {
            *state.output = Some(output);
        }

        Self::io_client_conn(&mut state, cx)?;
        Self::io_client_server(&mut state, cx)?;

        if *state.server_closed && state.output.is_some() {
            ready!(state.client_io.poll_close(cx))?;
            ready!(state.server_socket.poll_close(cx))?;

            return Poll::Ready(Ok(()));
        }

        Poll::Pending
    }
}

impl<S> Prover<state::Connected<S>>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    fn finish(self) -> Result<Prover<state::Committed>, Error> {
        let TlsOutput {
            ctx,
            vm,
            keys,
            tls_transcript,
            transcript,
        } = self
            .state
            .output
            .ok_or(Error::internal().with_msg("prover has not yet closed the connection"))?;

        let prover = Prover {
            config: self.config,
            span: self.span,
            ctx: Some(ctx),
            state: state::Committed {
                vm,
                server_name: self.state.server_name,
                keys,
                tls_transcript,
                transcript,
            },
        };

        Ok(prover)
    }

    fn io_client_conn(
        state: &mut ConnectedProj<S>,
        cx: &mut std::task::Context<'_>,
    ) -> Result<(), Error> {
        // tls_conn -> tls_client
        // Always poll to register wakers, then check wants_write()
        if let Poll::Ready(mut simplex) = state.client_io.as_mut().poll_lock_read(cx)
            && let Poll::Ready(buf) = simplex.poll_get(cx)?
        {
            if !buf.is_empty() {
                if state.tls_client.wants_write() {
                    let write = state.tls_client.write(buf)?;
                    if write > 0 {
                        simplex.advance(write);
                    }
                }
            } else if !*state.client_closed && !*state.server_closed {
                *state.client_closed = true;
                state.tls_client.client_close();
            }
        }

        // tls_client -> tls_conn
        // Always poll to register wakers, then check wants_read()
        if let Poll::Ready(mut simplex) = state.client_io.as_mut().poll_lock_write(cx)
            && let Poll::Ready(buf) = simplex.poll_mut(cx)?
            && state.tls_client.wants_read()
        {
            let read = state.tls_client.read(buf)?;
            if read > 0 {
                simplex.advance_mut(read);
            }
        }
        Ok(())
    }

    fn io_client_server(
        state: &mut ConnectedProj<S>,
        cx: &mut std::task::Context<'_>,
    ) -> Result<(), Error> {
        // server_socket -> buf
        if let Poll::Ready(write) = state
            .server_to_client
            .poll_write_from(cx, state.server_socket.as_mut())?
            && write == 0
            && !*state.server_closed
        {
            *state.server_closed = true;
            state.tls_client.server_close();
        }

        // buf -> tls_client
        // Always poll to register wakers, then check wants_read_tls()
        if let Poll::Ready(mut simplex) = state.client_to_server.as_mut().poll_lock_read(cx)
            && let Poll::Ready(buf) = simplex.poll_get(cx)?
            && state.tls_client.wants_read_tls()
        {
            let read = state.tls_client.read_tls(buf)?;
            if read > 0 {
                simplex.advance(read);
            }
        }

        // tls_client -> buf
        // Always poll to register wakers, then check wants_write_tls()
        if let Poll::Ready(mut simplex) = state.client_to_server.as_mut().poll_lock_write(cx)
            && let Poll::Ready(buf) = simplex.poll_mut(cx)?
            && state.tls_client.wants_write_tls()
        {
            let write = state.tls_client.write_tls(buf)?;
            if write > 0 {
                simplex.advance_mut(write);
            }
        }

        // buf -> server_socket
        match state
            .server_to_client
            .poll_read_to(cx, state.server_socket.as_mut())
        {
            // do not attempt to write into closed sockets
            Poll::Ready(Err(err)) if matches!(err.kind(), std::io::ErrorKind::BrokenPipe) => {}
            Poll::Ready(Err(err)) if matches!(err.kind(), std::io::ErrorKind::ConnectionReset) => {}
            Poll::Ready(Err(err)) => return Err(Error::from(err)),
            _ => {}
        }

        Ok(())
    }
}

impl Prover<state::Committed> {
    /// Returns the TLS transcript.
    pub fn tls_transcript(&self) -> &TlsTranscript {
        &self.state.tls_transcript
    }

    /// Returns the transcript.
    pub fn transcript(&self) -> &Transcript {
        &self.state.transcript
    }

    /// Proves information to the verifier.
    ///
    /// # Arguments
    ///
    /// * `config` - The disclosure configuration.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn prove(&mut self, config: &ProveConfig) -> Result<ProverOutput> {
        let ctx = self
            .ctx
            .as_mut()
            .ok_or_else(|| Error::internal().with_msg("proving context was dropped"))?;
        let state::Committed {
            vm,
            keys,
            server_name,
            tls_transcript,
            transcript,
            ..
        } = &mut self.state;

        let handshake = config.server_identity().then(|| {
            (
                server_name.clone(),
                HandshakeData {
                    certs: tls_transcript
                        .server_cert_chain()
                        .expect("server cert chain is present")
                        .to_vec(),
                    sig: tls_transcript
                        .server_signature()
                        .expect("server signature is present")
                        .clone(),
                    binding: tls_transcript.certificate_binding().clone(),
                },
            )
        });

        let partial_transcript = config
            .reveal()
            .map(|(sent, recv)| transcript.to_partial(sent.clone(), recv.clone()));

        let msg = ProveRequestMsg {
            request: config.to_request(),
            handshake,
            transcript: partial_transcript,
        };

        ctx.io_mut().send(msg).await.map_err(|e| {
            Error::io()
                .with_msg("failed to send prove configuration")
                .with_source(e)
        })?;
        ctx.io_mut()
            .expect_next::<Response>()
            .await
            .map_err(|e| {
                Error::io()
                    .with_msg("failed to receive prove response from verifier")
                    .with_source(e)
            })?
            .result
            .map_err(|e| {
                Error::user()
                    .with_msg("proving rejected by verifier")
                    .with_source(e)
            })?;

        let output = prove::prove(ctx, vm, keys, transcript, tls_transcript, config).await?;

        Ok(output)
    }

    /// Closes the connection with the verifier.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn close(self) -> Result<()> {
        Ok(())
    }
}
