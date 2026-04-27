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
    Error, PROXY_STREAM_PREFIX, Protocol, Result, TlsOutput,
    deps::{ProtocolDeps, ProverMpcDeps, ProverProxyDeps},
    msg::{ProveRequestMsg, Response, TlsCommitRequestMsg},
    prover::{
        client::{MpcTlsClient, ProxyTlsClient, TlsClient},
        future::FutureState,
        state::ConnectedProj,
    },
    tag::verify_tags,
};

use futures::{AsyncRead, AsyncWrite, ready};
use mpz_common::Context;
use mpz_vm_core::Execute;
use serio::{SinkExt, stream::IoStreamExt};
use std::{fmt::Debug, pin::Pin, task::Poll};
use tls_client::ServerName as TlsServerName;
use tlsn_core::{
    config::{
        prove::ProveConfig,
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::{TlsCommitConfig, mpc::MpcTlsConfig, proxy::ProxyTlsConfig},
    },
    connection::{HandshakeData, ServerName},
    transcript::{TlsTranscript, Transcript},
};
use tlsn_mux::{Handle, Stream};
use tracing::{Span, debug, info_span, instrument};

const BUF_CAP: usize = 16 * 1024 * 1024;

/// A prover instance.
pub struct Prover<T: state::ProverState = state::Initialized> {
    config: ProverConfig,
    span: Span,
    ctx: Option<Context>,
    mux_handle: Handle,
    state: T,
}

impl<T: state::ProverState> Debug for Prover<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prover")
            .field("config", &self.config)
            .field("span", &self.span)
            .field("ctx", &self.ctx)
            .field("mux_handle", &"{{ .. }}")
            .field("state", &"{{ .. }}")
            .finish()
    }
}

impl Prover<state::Initialized> {
    /// Creates a new prover.
    ///
    /// # Arguments
    ///
    /// * `ctx` - A thread context.
    /// * `mux_handle` - A handle for the multiplexer.
    /// * `config` - The configuration for the prover.
    pub(crate) fn new(ctx: Context, mux_handle: Handle, config: ProverConfig) -> Self {
        let span = info_span!("prover");
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
    /// This initiates the TLS commitment protocol, including performing any
    /// necessary preprocessing operations.
    ///
    /// # Arguments
    ///
    /// * `config` - The TLS commitment configuration.
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub async fn commit<P: Protocol>(
        mut self,
        config: TlsCommitConfig<P>,
    ) -> Result<Prover<state::CommitAccepted<P>>> {
        let mut ctx = self
            .ctx
            .take()
            .ok_or_else(|| Error::internal().with_msg("commitment protocol context was dropped"))?;

        // Sends protocol configuration to verifier for compatibility check.
        ctx.io_mut()
            .send(TlsCommitRequestMsg {
                request: config.protocol().clone().into(),
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

        let mut deps = P::ProverDeps::new(config.protocol(), ctx);
        deps.setup().await?;

        debug!("setup complete");

        Ok(Prover {
            config: self.config,
            span: self.span,
            ctx: None,
            mux_handle: self.mux_handle,
            state: state::CommitAccepted { deps },
        })
    }
}

impl Prover<state::CommitAccepted<MpcTlsConfig>> {
    /// Connects to the server via MPC-TLS.
    ///
    /// This method is used for MPC mode only.
    ///
    /// # Arguments
    ///
    /// * `config` - The TLS client configuration.
    /// * `server_socket` - The connection to the server.
    ///
    /// # Returns
    ///
    /// * handle to the TLS connection
    /// * the connected prover
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub fn connect<S: AsyncWrite + AsyncRead + Send + Unpin>(
        self,
        config: TlsClientConfig,
        server_socket: S,
    ) -> Result<(TlsConnection, Prover<state::Connected<S>>)> {
        let ProverMpcDeps { vm, mpc_tls, keys } = self.state.deps;

        let ServerName::Dns(server_name) = config.server_name();
        let server_name =
            TlsServerName::try_from(server_name.as_ref()).expect("name was validated");
        let span = self.span.clone();

        let keys = keys.expect("keys should be available");
        let client = MpcTlsClient::new(keys, vm, span, &config, server_name, mpc_tls)?;
        let tls_client: Box<dyn TlsClient<Error = Error> + Send> = Box::new(client);

        let control = ProverControl {
            decrypt: tls_client.decrypt(),
        };

        let (client_io, tlsn_conn) = futures_plex::duplex(BUF_CAP);
        let (client_to_server, server_to_client) = futures_plex::duplex(BUF_CAP);

        let prover = Prover {
            ctx: self.ctx,
            mux_handle: self.mux_handle,
            config: self.config,
            span: self.span,
            state: state::Connected {
                server_name: config.server_name().clone(),
                tls_client,
                control,
                client_io,
                output: None,
                server_socket,
                client_to_server,
                server_to_client,
                client_closed: false,
                server_closed: false,
            },
        };

        let conn = TlsConnection::new(tlsn_conn);

        Ok((conn, prover))
    }
}

impl Prover<state::CommitAccepted<ProxyTlsConfig>> {
    /// Connects to the proxy.
    ///
    /// This method is used for proxy mode only. The proxy stream through the
    /// verifier is opened internally.
    ///
    /// # Arguments
    ///
    /// * `config` - The TLS client configuration.
    ///
    /// # Returns
    ///
    /// * handle to the TLS connection
    /// * the connected prover
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub fn connect(
        self,
        config: TlsClientConfig,
    ) -> Result<(TlsConnection, Prover<state::Connected<Stream>>)> {
        let ProverProxyDeps {
            prover: proxy_prover,
            id,
        } = self.state.deps;

        let mut proxy_id = PROXY_STREAM_PREFIX.to_vec();
        proxy_id.extend_from_slice(id.as_bytes());
        let proxy_socket = self.mux_handle.new_stream(&proxy_id)?;

        let ServerName::Dns(server_name) = config.server_name();
        let server_name =
            TlsServerName::try_from(server_name.as_ref()).expect("name was validated");

        let tls_client: Box<dyn TlsClient<Error = Error> + Send> =
            Box::new(ProxyTlsClient::new(proxy_prover, &config, server_name)?);

        let control = ProverControl {
            decrypt: tls_client.decrypt(),
        };

        let (client_io, tlsn_conn) = futures_plex::duplex(BUF_CAP);
        let (client_to_server, server_to_client) = futures_plex::duplex(BUF_CAP);

        let prover = Prover {
            ctx: self.ctx,
            mux_handle: self.mux_handle,
            config: self.config,
            span: self.span,
            state: state::Connected {
                server_name: config.server_name().clone(),
                tls_client,
                control,
                client_io,
                output: None,
                server_socket: proxy_socket,
                client_to_server,
                server_to_client,
                client_closed: false,
                server_closed: false,
            },
        };

        let conn = TlsConnection::new(tlsn_conn);

        Ok((conn, prover))
    }
}

impl<S> Prover<state::Connected<S>>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    /// Returns a [`ProverControl`] for connection specific settings.
    pub fn control(&self) -> ProverControl {
        self.state.control.clone()
    }

    fn poll(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Error>> {
        let mut state = Pin::new(&mut self.state).project();

        Self::io_to_tls_client(&mut state, cx)?;

        if state.output.is_none()
            && let Poll::Ready(output) = state.tls_client.poll(cx)?
        {
            *state.output = Some(output);
        }

        Self::io_from_tls_client(&mut state, cx)?;

        if *state.server_closed && state.output.is_some() {
            ready!(state.client_io.poll_close(cx))?;
            ready!(state.server_socket.poll_close(cx))?;

            return Poll::Ready(Ok(()));
        }

        Poll::Pending
    }
}

impl<S> IntoFuture for Prover<state::Connected<S>>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type Output = Result<Prover<state::Committed>, Error>;
    type IntoFuture = ProverFuture<S>;

    fn into_future(self) -> Self::IntoFuture {
        ProverFuture {
            state: FutureState::Connected {
                prover: Box::new(self),
            },
        }
    }
}

impl<S> Prover<state::Connected<S>>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    async fn finish(self) -> Result<Prover<state::Committed>, Error> {
        let (
            mut ctx,
            mut vm,
            TlsOutput {
                keys,
                tls_transcript,
            },
        ) = self
            .state
            .output
            .ok_or(Error::internal().with_msg("prover has not yet closed the connection"))?;

        // Prove tag verification of received records.
        // The prover drops the proof output.
        let _ = verify_tags(
            &mut vm,
            (keys.server_write_key, keys.server_write_iv),
            keys.server_write_mac_key,
            *tls_transcript.version(),
            tls_transcript.recv().to_vec(),
        )
        .map_err(|err| {
            Error::internal()
                .with_msg("tag verification setup failed")
                .with_source(err)
        })?;

        vm.execute_all(&mut ctx).await.map_err(|err| {
            Error::internal()
                .with_msg("tag verification zk execution failed")
                .with_source(err)
        })?;

        debug!("verified tags from server");

        let transcript = tls_transcript.to_transcript().map_err(|e| {
            Error::internal()
                .with_msg("prover could not create transcript")
                .with_source(e)
        })?;

        let prover = Prover {
            config: self.config,
            span: self.span,
            ctx: Some(ctx),
            mux_handle: self.mux_handle,
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

    fn io_to_tls_client(
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
                } else {
                    cx.waker().wake_by_ref();
                }
            } else if !*state.client_closed && !*state.server_closed {
                *state.client_closed = true;
                state.tls_client.client_close();
            }
        }

        // server_socket -> buf
        if let Poll::Ready(write) = state
            .server_to_client
            .poll_write_from(cx, state.server_socket.as_mut())?
        {
            if write == 0 && !*state.server_closed {
                *state.server_closed = true;
            } else if write > 0 {
                cx.waker().wake_by_ref();
            }
        }

        // buf -> tls_client
        // Always poll to register wakers, then check wants_read_tls()
        if let Poll::Ready(mut simplex) = state.client_to_server.as_mut().poll_lock_read(cx)
            && let Poll::Ready(buf) = simplex.poll_get(cx)?
        {
            if state.tls_client.wants_read_tls() {
                let read = state.tls_client.read_tls(buf)?;
                if read > 0 {
                    simplex.advance(read);
                    cx.waker().wake_by_ref();
                }
            } else if !buf.is_empty() {
                cx.waker().wake_by_ref();
            }
        } else if *state.server_closed {
            state.tls_client.server_close();
        }

        Ok(())
    }

    fn io_from_tls_client(
        state: &mut ConnectedProj<S>,
        cx: &mut std::task::Context<'_>,
    ) -> Result<(), Error> {
        // tls_client -> buf
        // Always poll to register wakers, then check wants_write_tls()
        if let Poll::Ready(mut simplex) = state.client_to_server.as_mut().poll_lock_write(cx)
            && let Poll::Ready(buf) = simplex.poll_mut(cx)?
        {
            let write = state.tls_client.write_tls(buf)?;
            if write > 0 {
                simplex.advance_mut(write);
            } else if state.tls_client.wants_write_tls() {
                cx.waker().wake_by_ref();
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
