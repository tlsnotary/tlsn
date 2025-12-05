//! Prover.

mod client;
mod control;
mod error;
mod prove;
pub mod state;

pub use control::ProverControl;
pub use error::ProverError;
pub use tlsn_core::ProverOutput;

use crate::{
    BUF_CAP, Role,
    conn::{
        ConnectionFuture,
        mpc::{MpcConnection, MpcSetup},
        tls::TlsConnection,
    },
    context::build_mt_context,
    mpz::{ProverDeps, build_prover_deps, translate_keys},
    msg::{ProveRequestMsg, Response, TlsCommitRequestMsg},
    mux::attach_mux,
    prover::client::{MpcTlsClient, TlsOutput},
};

use futures::{AsyncRead, AsyncReadExt, AsyncWrite, FutureExt, TryFutureExt};
use rustls_pki_types::CertificateDer;
use serio::{SinkExt, stream::IoStreamExt};
use std::{
    sync::{Arc, Mutex},
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
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub fn commit(
        self,
        config: TlsCommitConfig,
    ) -> Result<MpcSetup<Prover<state::CommitAccepted>, ProverError>, ProverError> {
        let (duplex_a, duplex_b) = futures_plex::duplex(BUF_CAP);

        let setup = self.commit_inner(config, duplex_a);
        let mpc_conn = MpcSetup::new(duplex_b, Box::new(setup));

        Ok(mpc_conn)
    }

    /// Starts the TLS commitment protocol and attaches a socket.
    ///
    /// This is a convenience method for [`Self::commit`];
    ///
    /// # Arguments
    ///
    /// * `config` - The TLS commitment configuration.
    /// * `socket` - The socket.
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub async fn commit_with<S: AsyncWrite + AsyncRead + Send>(
        self,
        config: TlsCommitConfig,
        socket: S,
    ) -> Result<(MpcConnection, Prover<state::CommitAccepted>), ProverError> {
        let (duplex_a, mut duplex_b) = futures_plex::duplex(BUF_CAP);
        let mut setup = Box::pin(self.commit_inner(config, duplex_a).fuse());

        let prover = {
            let (mut duplex_read, mut duplex_write) = (&mut duplex_b).split();
            let (mut socket_read, mut socket_write) = socket.split();

            let mut read = futures::io::copy(&mut socket_read, &mut duplex_write).fuse();
            let mut write = futures::io::copy(&mut duplex_read, &mut socket_write).fuse();

            loop {
                futures::select! {
                    _ = read => (),
                    _ = write => (),
                    prover = setup =>  break prover?
                }
            }
        };

        let mpc_conn = MpcConnection::new(duplex_b);
        Ok((mpc_conn, prover))
    }

    async fn commit_inner<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
        self,
        config: TlsCommitConfig,
        transport: S,
    ) -> Result<Prover<state::CommitAccepted>, ProverError> {
        let (mut mux_fut, mux_ctrl) = attach_mux(transport, Role::Prover);
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

        let prover = Prover {
            config: self.config,
            span: self.span,
            state: state::CommitAccepted {
                mux_ctrl,
                mux_fut,
                mpc_tls,
                keys,
                vm,
            },
        };

        Ok(prover)
    }
}

impl Prover<state::CommitAccepted> {
    /// Connects the prover.
    ///
    /// Returns a connected prover, which can be used to read and write from/to
    /// the active TLS connection.
    ///
    /// # Arguments
    ///
    /// * `config` - The TLS client configuration.
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub async fn connect(
        self,
        config: TlsClientConfig,
    ) -> Result<Prover<state::Connected>, ProverError> {
        let state::CommitAccepted {
            mux_ctrl,
            mux_fut,
            mpc_tls,
            keys,
            vm,
            ..
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

        let prover = Prover {
            config: self.config,
            span: self.span,
            state: state::Connected {
                mux_ctrl,
                mux_fut,
                server_name: config.server_name().clone(),
                tls_client: Box::new(mpc_tls),
                output: None,
            },
        };
        Ok(prover)
    }

    /// Connects the prover and attaches a socket.
    ///
    /// This is a convenience function which returns
    ///   - [`TlsConnection`] for reading and writing traffic.
    ///   - [`ConnectionFuture`] which has to be polled for driving the
    ///     connection forward.
    ///
    /// # Arguments
    ///
    /// * `config` - The TLS client configuration.
    /// * `socket` - The socket for IO.
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub async fn connect_with<S>(
        self,
        config: TlsClientConfig,
        socket: S,
    ) -> Result<(TlsConnection, ConnectionFuture<S>), ProverError>
    where
        S: AsyncRead + AsyncWrite + Send,
    {
        let prover = self.connect(config).await?;

        let prover = Arc::new(Mutex::new(prover));
        let conn_waker = Arc::new(Mutex::new(None));
        let fut_waker = Arc::new(Mutex::new(None));

        let conn = TlsConnection::new(
            Arc::downgrade(&prover),
            conn_waker.clone(),
            fut_waker.clone(),
        );
        let fut = ConnectionFuture::new(socket, prover, conn_waker, fut_waker);

        Ok((conn, fut))
    }
}

impl Prover<state::Connected> {
    /// Returns `true` if the prover wants to read TLS data from the server.
    pub fn wants_read_tls(&self) -> bool {
        self.state.tls_client.wants_read_tls()
    }

    /// Returns `true` if the prover wants to write TLS data to the server.
    pub fn wants_write_tls(&self) -> bool {
        self.state.tls_client.wants_write_tls()
    }

    /// Reads TLS data from the server.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer to read the TLS data from.
    pub fn read_tls(&mut self, buf: &[u8]) -> Result<usize, ProverError> {
        self.state.tls_client.read_tls(buf)
    }

    /// Writes TLS data for the server into the provided buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer to write the TLS data to.
    pub fn write_tls(&mut self, buf: &mut [u8]) -> Result<usize, ProverError> {
        self.state.tls_client.write_tls(buf)
    }

    /// Returns `true` if the prover wants to read plaintext data.
    pub fn wants_read(&self) -> bool {
        self.state.tls_client.wants_read()
    }

    /// Returns `true` if the prover wants to write plaintext data.
    pub fn wants_write(&self) -> bool {
        self.state.tls_client.wants_write()
    }

    /// Reads plaintext data from the server into the provided buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer where the plaintext data gets written to.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<usize, ProverError> {
        self.state.tls_client.read(buf)
    }

    /// Writes plaintext data to be sent to the server.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer to read the plaintext data from.
    pub fn write(&mut self, buf: &[u8]) -> Result<usize, ProverError> {
        self.state.tls_client.write(buf)
    }

    /// Closes the connection from the client side.
    pub fn client_close(&mut self) -> Result<(), ProverError> {
        self.state.tls_client.client_close()
    }

    /// Closes the connection from the server side.
    pub fn server_close(&mut self) -> Result<(), ProverError> {
        self.state.tls_client.server_close()
    }

    /// Enables or disables the decryption of data from the server until the
    /// server has closed the connection.
    ///
    /// # Arguments
    ///
    /// * `enable` - Whether to enable or disable decryption.
    pub fn enable_decryption(&mut self, enable: bool) -> Result<(), ProverError> {
        self.state.tls_client.enable_decryption(enable)
    }

    /// Returns `true` if decryption of TLS traffic from the server is active.
    pub fn is_decrypting(&self) -> bool {
        self.state.tls_client.is_decrypting()
    }

    /// Polls the prover to make progress.
    ///
    /// # Arguments
    ///
    /// * `cx` - The async context.
    pub fn poll(&mut self, cx: &mut Context) -> Poll<Result<(), ProverError>> {
        let _ = self.state.mux_fut.poll_unpin(cx)?;

        match self.state.tls_client.poll(cx)? {
            Poll::Ready(output) => {
                let _ = self.state.mux_fut.poll_unpin(cx)?;
                self.state.output = Some(output);
                Poll::Ready(Ok(()))
            }
            Poll::Pending => Poll::Pending,
        }
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
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn prove(&mut self, config: &ProveConfig) -> Result<ProverOutput, ProverError> {
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
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn close(self) -> Result<(), ProverError> {
        let state::Committed {
            mux_ctrl, mux_fut, ..
        } = self.state;

        // Wait for the verifier to correctly close the connection.
        if !mux_fut.is_complete() {
            mux_ctrl.close();
            mux_fut.await?;
        }

        Ok(())
    }
}
