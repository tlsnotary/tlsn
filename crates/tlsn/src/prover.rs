//! Prover.

mod future;
mod prove;
pub mod state;

pub use future::ProverFuture;
use mpz_common::Context;
pub use tlsn_core::ProverOutput;

use crate::{
    Error, Result,
    mpz::{ProverDeps, build_prover_deps, translate_keys},
    msg::{ProveRequestMsg, Response, TlsCommitRequestMsg},
    tag::verify_tags,
};

use futures::{AsyncRead, AsyncWrite, TryFutureExt};
use mpc_tls::LeaderCtrl;
use mpz_vm_core::prelude::*;
use rustls_pki_types::CertificateDer;
use serio::{SinkExt, stream::IoStreamExt};
use std::sync::Arc;
use tls_client::{ClientConnection, ServerName as TlsServerName};
use tls_client_async::{TlsConnection, bind_client};
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
use webpki::anchor_from_trusted_cert;

use tracing::{Instrument, Span, debug, info, info_span, instrument};

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
    pub async fn connect<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
        self,
        config: TlsClientConfig,
        socket: S,
    ) -> Result<(TlsConnection, ProverFuture)> {
        let state::CommitAccepted {
            mpc_tls, keys, vm, ..
        } = self.state;

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

        let (conn, conn_fut) = bind_client(socket, client);

        let fut = Box::pin({
            let span = self.span.clone();
            let mpc_ctrl = mpc_ctrl.clone();
            async move {
                let conn_fut = async {
                    conn_fut.await.map_err(|e| {
                        Error::io().with_msg("tls connection failed").with_source(e)
                    })?;
                    mpc_ctrl.stop().await.map_err(|e| {
                        Error::internal()
                            .with_msg("mpc-tls failed to stop")
                            .with_source(e)
                    })?;

                    Ok::<_, crate::Error>(())
                };

                info!("starting MPC-TLS");

                let (_, (mut ctx, tls_transcript)) = futures::try_join!(
                    conn_fut,
                    mpc_fut.in_current_span().map_err(|e| {
                        Error::internal()
                            .with_msg("mpc-tls execution failed")
                            .with_source(e)
                    })
                )?;

                info!("finished MPC-TLS");

                {
                    let mut vm = vm.try_lock().expect("VM should not be locked");

                    debug!("finalizing mpc");

                    // Finalize DEAP.
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

                // Prove tag verification of received records.
                // The prover drops the proof output.
                let _ = verify_tags(
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
                        .with_msg("executing the zkVM failed during tag verification")
                        .with_source(e)
                })?;

                let transcript = tls_transcript
                    .to_transcript()
                    .expect("transcript is complete");

                Ok(Prover {
                    config: self.config,
                    span: self.span,
                    ctx: Some(ctx),
                    state: state::Committed {
                        vm,
                        server_name: config.server_name().clone(),
                        keys,
                        tls_transcript,
                        transcript,
                    },
                })
            }
            .instrument(span)
        });

        Ok((
            conn,
            ProverFuture {
                fut,
                ctrl: ProverControl { mpc_ctrl },
            },
        ))
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

/// A controller for the prover.
#[derive(Clone)]
pub struct ProverControl {
    mpc_ctrl: LeaderCtrl,
}

impl ProverControl {
    /// Defers decryption of data from the server until the server has closed
    /// the connection.
    ///
    /// This is a performance optimization which will significantly reduce the
    /// amount of upload bandwidth used by the prover.
    ///
    /// # Notes
    ///
    /// * The prover may need to close the connection to the server in order for
    ///   it to close the connection on its end. If neither the prover or server
    ///   close the connection this will cause a deadlock.
    pub async fn defer_decryption(&self) -> Result<()> {
        self.mpc_ctrl.defer_decryption().await.map_err(|e| {
            Error::internal()
                .with_msg("failed to defer decryption")
                .with_source(e)
        })
    }
}
