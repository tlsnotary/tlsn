//! Prover.

mod client;
mod conn;
mod control;
mod error;
mod prove;
pub mod state;

pub use conn::TlsConnection;
pub use control::ProverControl;
pub use error::ProverError;
pub use tlsn_core::ProverOutput;

use crate::{
    BUF_CAP, Role,
    mpz::{ProverDeps, build_prover_deps, translate_keys},
    msg::{ProveRequestMsg, Response, TlsCommitRequestMsg},
    mux::attach_mux,
    prover::{
        client::{MpcTlsClient, TlsOutput},
        state::ConnectedProj,
    },
    utils::{CopyIo, await_with_copy_io, build_mt_context},
};

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, FutureExt, TryFutureExt, ready};
use rustls_pki_types::CertificateDer;
use serio::{SinkExt, stream::IoStreamExt};
use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
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

/// A prover instance.
#[derive(Debug)]
pub struct Prover<T: state::ProverState = state::Initialized> {
    config: ProverConfig,
    span: Span,
    state: T,
}

impl Prover<state::Initialized> {
    /// Creates a new prover.
    ///
    /// # Arguments
    ///
    /// * `config` - The configuration for the prover.
    pub fn new(config: ProverConfig) -> Self {
        let span = info_span!("prover");
        Self {
            config,
            span,
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
    /// * `verifier_io` - The IO to the TLS verifier.
    pub async fn commit<S: AsyncWrite + AsyncRead + Send + Unpin>(
        self,
        config: TlsCommitConfig,
        verifier_io: S,
    ) -> Result<Prover<state::CommitAccepted>, ProverError> {
        let (duplex_a, mut duplex_b) = futures_plex::duplex(BUF_CAP);
        let fut = Box::pin(self.commit_inner(config, duplex_a).fuse());
        let mut prover = await_with_copy_io(fut, verifier_io, &mut duplex_b).await?;

        prover.state.verifier_io = Some(duplex_b);
        Ok(prover)
    }

    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    async fn commit_inner<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
        self,
        config: TlsCommitConfig,
        verifier_io: S,
    ) -> Result<Prover<state::CommitAccepted>, ProverError> {
        let (mut mux_fut, mux_ctrl) = attach_mux(verifier_io, Role::Prover);
        let mut mt = build_mt_context(mux_ctrl.clone());
        let mut ctx = mux_fut.poll_with(mt.new_context()).await?;

        // Sends protocol configuration to verifier for compatibility check.
        mux_fut
            .poll_with(async {
                ctx.io_mut()
                    .send(TlsCommitRequestMsg {
                        request: config.to_request(),
                        version: crate::VERSION.clone(),
                    })
                    .await?;

                ctx.io_mut()
                    .expect_next::<Response>()
                    .await?
                    .result
                    .map_err(ProverError::from)
            })
            .await?;

        let TlsCommitProtocolConfig::Mpc(mpc_tls_config) = config.protocol().clone() else {
            unreachable!("only MPC TLS is supported");
        };

        let ProverDeps { vm, mut mpc_tls } = build_prover_deps(mpc_tls_config, ctx);

        // Allocate resources for MPC-TLS in the VM.
        let mut keys = mpc_tls.alloc()?;
        let vm_lock = vm.try_lock().expect("VM is not locked");
        translate_keys(&mut keys, &vm_lock);
        drop(vm_lock);

        debug!("setting up mpc-tls");

        mux_fut.poll_with(mpc_tls.preprocess()).await?;

        debug!("mpc-tls setup complete");

        Ok(Prover {
            config: self.config,
            span: self.span,
            state: state::CommitAccepted {
                verifier_io: None,
                mux_ctrl,
                mux_fut,
                mpc_tls,
                keys,
                vm,
            },
        })
    }
}

impl Prover<state::CommitAccepted> {
    /// Sets up the prover with the client configuration.
    ///
    /// Returns a set up prover, and a [`TlsConnection`] which can be used to
    /// read and write bytes from/to the server.
    ///
    /// # Arguments
    ///
    /// * `config` - The TLS client configuration.
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub fn setup(
        self,
        config: TlsClientConfig,
    ) -> Result<(TlsConnection, Prover<state::Setup>), ProverError> {
        let state::CommitAccepted {
            verifier_io,
            mux_ctrl,
            mux_fut,
            mpc_tls,
            keys,
            vm,
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
                        .map_err(ProverError::config)
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
                .map_err(ProverError::config)?
        } else {
            rustls_config.with_no_client_auth()
        };

        let client = ClientConnection::new(
            Arc::new(rustls_config),
            Box::new(mpc_ctrl.clone()),
            server_name,
        )
        .map_err(ProverError::config)?;

        let span = self.span.clone();

        let mpc_tls = MpcTlsClient::new(
            Box::new(mpc_fut.map_err(ProverError::from)),
            keys,
            vm,
            span,
            mpc_ctrl,
            client,
            decrypt,
        );

        let (duplex_a, duplex_b) = futures_plex::duplex(BUF_CAP);
        let prover = Prover {
            config: self.config,
            span: self.span,
            state: state::Setup {
                mux_ctrl,
                mux_fut,
                server_name: config.server_name().clone(),
                tls_client: Box::new(mpc_tls),
                client_io: duplex_a,
                verifier_io,
            },
        };

        let conn = TlsConnection::new(duplex_b);
        Ok((conn, prover))
    }
}

impl Prover<state::Setup> {
    /// Returns a handle to control the prover.
    pub fn handle(&self) -> ProverControl {
        let handle = self.state.tls_client.handle();
        ProverControl { handle }
    }

    /// Attaches IO to the prover.
    ///
    /// # Arguments
    ///
    /// * `server_io` - The IO to the server.
    /// * `verifier_io` - The IO to the TLS verifier.
    pub fn connect<S, T>(self, server_io: S, verifier_io: T) -> Prover<state::Connected<S, T>>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin,
        T: AsyncRead + AsyncWrite + Send + Unpin,
    {
        let (client_to_server, server_to_client) = futures_plex::duplex(BUF_CAP);

        Prover {
            config: self.config,
            span: self.span,
            state: state::Connected {
                verifier_io: self.state.verifier_io,
                mux_ctrl: self.state.mux_ctrl,
                mux_fut: self.state.mux_fut,
                server_name: self.state.server_name,
                tls_client: self.state.tls_client,
                client_io: self.state.client_io,
                output: None,
                server_socket: server_io,
                verifier_socket: verifier_io,
                tls_client_to_server_buf: client_to_server,
                server_to_tls_client_buf: server_to_client,
                client_closed: false,
                server_closed: false,
            },
        }
    }

    /// This is a convenience method which attaches IO, runs the prover and
    /// returns a committed prover together with the IO.
    ///
    /// # Arguments
    ///
    /// * `server_io` - The IO to the server.
    /// * `verifier_io` - The IO to the TLS verifier.
    pub async fn run<S, T>(
        self,
        mut server_io: S,
        mut verifier_io: T,
    ) -> Result<(Prover<state::Committed>, S, T), ProverError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let mut prover = self.connect(&mut server_io, &mut verifier_io);
        (&mut prover).await?;

        let prover = prover.finish()?;
        Ok((prover, server_io, verifier_io))
    }
}

impl<S, T> Future for Prover<state::Connected<S, T>>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
    T: AsyncRead + AsyncWrite + Send + Unpin,
{
    type Output = Result<(), ProverError>;

    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = Pin::new(&mut self.state).project();

        loop {
            let mut progress = false;

            if state.output.is_none()
                && let Poll::Ready(output) = state.tls_client.poll(cx)?
            {
                *state.output = Some(output);
            }

            progress |= Self::io_client_conn(&mut state, cx)?;
            progress |= Self::io_client_server(&mut state, cx)?;
            progress |= Self::io_client_verifier(&mut state, cx)?;

            _ = state.mux_fut.poll_unpin(cx)?;

            if *state.server_closed && state.output.is_some() {
                ready!(state.client_io.poll_close(cx))?;
                ready!(state.server_socket.poll_close(cx))?;

                return Poll::Ready(Ok(()));
            } else if !progress {
                return Poll::Pending;
            }
        }
    }
}

impl<S, T> Prover<state::Connected<S, T>>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
    T: AsyncRead + AsyncWrite + Send + Unpin,
{
    fn io_client_conn(
        state: &mut ConnectedProj<S, T>,
        cx: &mut Context,
    ) -> Result<bool, ProverError> {
        let mut progress = false;

        // tls_conn -> tls_client
        if state.tls_client.wants_write()
            && let Poll::Ready(mut simplex) = state.client_io.as_mut().poll_lock_read(cx)
            && let Poll::Ready(buf) = simplex.poll_get(cx)?
        {
            if !buf.is_empty() {
                let write = state.tls_client.write(buf)?;
                if write > 0 {
                    progress = true;
                    simplex.advance(write);
                }
            } else if !*state.client_closed && !*state.server_closed {
                progress = true;
                *state.client_closed = true;
                state.tls_client.client_close()?;
            }
        }

        // tls_client -> tls_conn
        if state.tls_client.wants_read()
            && let Poll::Ready(mut simplex) = state.client_io.as_mut().poll_lock_write(cx)
            && let Poll::Ready(buf) = simplex.poll_mut(cx)?
            && let read = state.tls_client.read(buf)?
            && read > 0
        {
            progress = true;
            simplex.advance_mut(read);
        }
        Ok(progress)
    }

    fn io_client_server(
        state: &mut ConnectedProj<S, T>,
        cx: &mut Context,
    ) -> Result<bool, ProverError> {
        let mut progress = false;

        // server_socket -> buf
        if let Poll::Ready(write) = state
            .server_to_tls_client_buf
            .poll_write_from(cx, state.server_socket.as_mut())?
        {
            if write > 0 {
                progress = true;
            } else if !*state.server_closed {
                progress = true;
                *state.server_closed = true;
                state.tls_client.server_close()?;
            }
        }

        // buf -> tls_client
        if state.tls_client.wants_read_tls()
            && let Poll::Ready(mut simplex) =
                state.tls_client_to_server_buf.as_mut().poll_lock_read(cx)
            && let Poll::Ready(buf) = simplex.poll_get(cx)?
            && let read = state.tls_client.read_tls(buf)?
            && read > 0
        {
            progress = true;
            simplex.advance(read);
        }

        // tls_client -> buf
        if state.tls_client.wants_write_tls()
            && let Poll::Ready(mut simplex) =
                state.tls_client_to_server_buf.as_mut().poll_lock_write(cx)
            && let Poll::Ready(buf) = simplex.poll_mut(cx)?
            && let write = state.tls_client.write_tls(buf)?
            && write > 0
        {
            progress = true;
            simplex.advance_mut(write);
        }

        // buf -> server_socket
        if let Poll::Ready(read) = state
            .server_to_tls_client_buf
            .poll_read_to(cx, state.server_socket.as_mut())?
            && read > 0
        {
            progress = true;
        }

        Ok(progress)
    }

    fn io_client_verifier(
        state: &mut ConnectedProj<S, T>,
        cx: &mut Context,
    ) -> Result<bool, ProverError> {
        let mut progress = false;

        let verifier_io = Pin::new(
            (*state.verifier_io)
                .as_mut()
                .expect("verifier io should be available"),
        );

        // mux -> verifier_socket
        if let Poll::Ready(read) = verifier_io.poll_read_to(cx, state.verifier_socket.as_mut())?
            && read > 0
        {
            progress = true;
        }

        // verifier_socket -> mux
        if let Poll::Ready(write) =
            verifier_io.poll_write_from(cx, state.verifier_socket.as_mut())?
            && write > 0
        {
            progress = true;
        }

        Ok(progress)
    }

    /// Returns a committed prover after the TLS session has completed.
    pub fn finish(self) -> Result<Prover<state::Committed>, ProverError> {
        let TlsOutput {
            ctx,
            vm,
            keys,
            tls_transcript,
            transcript,
        } = self.state.output.ok_or(ProverError::state(
            "prover has not yet closed the connection",
        ))?;

        let prover = Prover {
            config: self.config,
            span: self.span,
            state: state::Committed {
                verifier_io: self.state.verifier_io,
                mux_ctrl: self.state.mux_ctrl,
                mux_fut: self.state.mux_fut,
                ctx,
                vm,
                server_name: self.state.server_name,
                keys,
                tls_transcript,
                transcript,
            },
        };

        Ok(prover)
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
    /// * `verifier_io` - The IO to the TLS verifier.
    pub async fn prove<S>(
        &mut self,
        config: &ProveConfig,
        verifier_io: S,
    ) -> Result<ProverOutput, ProverError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin,
    {
        let mut duplex = self
            .state
            .verifier_io
            .take()
            .expect("duplex should be available");

        let fut = Box::pin(self.prove_inner(config).fuse());
        let output = await_with_copy_io(fut, verifier_io, &mut duplex).await?;

        self.state.verifier_io = Some(duplex);
        Ok(output)
    }

    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    async fn prove_inner(&mut self, config: &ProveConfig) -> Result<ProverOutput, ProverError> {
        let state::Committed {
            mux_fut,
            ctx,
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

        let output = mux_fut
            .poll_with(async {
                ctx.io_mut().send(msg).await.map_err(ProverError::from)?;

                ctx.io_mut().expect_next::<Response>().await?.result?;

                prove::prove(ctx, vm, keys, transcript, tls_transcript, config).await
            })
            .await?;

        Ok(output)
    }

    /// Closes the connection with the verifier.
    ///
    /// # Arguments
    ///
    /// * `verifier_io` - The IO to the TLS verifier.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn close<S>(mut self, mut verifier_io: S) -> Result<(), ProverError>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin,
    {
        let state::Committed {
            mux_ctrl, mux_fut, ..
        } = self.state;

        let mut duplex = self
            .state
            .verifier_io
            .take()
            .expect("duplex should be available");

        mux_ctrl.close();
        let copy = CopyIo::new(&mut verifier_io, &mut duplex).map_err(ProverError::from);
        futures::try_join!(mux_fut.map_err(ProverError::from), copy)?;

        // Wait for the verifier to finish closing.
        verifier_io.read_exact(&mut [0_u8; 5]).await?;
        Ok(())
    }
}
