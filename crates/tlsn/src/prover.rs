//! Prover.

mod client;
mod error;
mod prove;
pub mod state;

pub use error::ProverError;
pub use tlsn_core::ProverOutput;

use crate::{
    BUF_CAP, Role,
    context::build_mt_context,
    mpz::{ProverDeps, build_prover_deps, translate_keys},
    msg::{ProveRequestMsg, Response, TlsCommitRequestMsg},
    mux::attach_mux,
    prover::client::{MpcTlsClient, TlsOutput},
};

use futures::{FutureExt, TryFutureExt};
use rustls_pki_types::CertificateDer;
use serio::{SinkExt, stream::IoStreamExt};
use std::{
    io::{Read, Write},
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
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub async fn commit(
        self,
        config: TlsCommitConfig,
    ) -> Result<Prover<state::CommitAccepted>, ProverError> {
        let (duplex_a, duplex_b) = futures_plex::duplex(BUF_CAP);

        let (mut mux_fut, mux_ctrl) = attach_mux(duplex_b, Role::Prover);
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
                mpc_duplex: duplex_a,
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
            mpc_duplex,
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
                mpc_duplex,
                mux_ctrl,
                mux_fut,
                server_name: config.server_name().clone(),
                tls_client: Box::new(mpc_tls),
                output: None,
            },
        };
        Ok(prover)
    }

    /// Writes bytes for the verifier into a buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer.
    pub fn write_mpc(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.state.mpc_duplex.read(buf)
    }

    /// Reads bytes for the prover from a buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer.
    pub fn read_mpc(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.state.mpc_duplex.write(buf)
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

    /// Writes bytes for the verifier into a buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer.
    pub fn write_mpc(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.state.mpc_duplex.read(buf)
    }

    /// Reads bytes for the prover from a buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer.
    pub fn read_mpc(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.state.mpc_duplex.write(buf)
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
                mpc_duplex: self.state.mpc_duplex,
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

    /// Writes bytes for the verifier into a buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer.
    pub fn write_mpc(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.state.mpc_duplex.read(buf)
    }

    /// Reads bytes for the prover from a buffer.
    ///
    /// # Arguments
    ///
    /// * `buf` - The buffer.
    pub fn read_mpc(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.state.mpc_duplex.write(buf)
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
            mut mpc_duplex,
            mux_ctrl,
            mux_fut,
            ..
        } = self.state;

        // Wait for the verifier to correctly close the connection.
        if !mux_fut.is_complete() {
            mux_ctrl.close();
            mux_fut.await?;
            futures::AsyncWriteExt::close(&mut mpc_duplex).await?;
        }

        Ok(())
    }
}
