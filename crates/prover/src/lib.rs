//! TLSNotary prover library.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod config;
mod error;
mod future;
mod notarize;
mod prove;
pub mod state;

pub use config::{ProverConfig, ProverConfigBuilder, ProverConfigBuilderError};
pub use error::ProverError;
pub use future::ProverFuture;
use state::{Notarize, Prove};

use futures::{AsyncRead, AsyncWrite, TryFutureExt};
use mpz_common::Allocate;
use mpz_garble::config::Role as DEAPRole;
use mpz_ot::{chou_orlandi, kos};
use rand::Rng;
use serio::{SinkExt, StreamExt};
use std::sync::Arc;
use tls_client::{ClientConnection, ServerName as TlsServerName};
use tls_client_async::{bind_client, ClosedConnection, TlsConnection};
use tls_mpc::{build_components, LeaderCtrl, MpcTlsLeader, TlsRole};
use tlsn_common::{
    mux::{attach_mux, MuxControl},
    DEAPThread, Executor, OTReceiver, OTSender, Role,
};
use tlsn_core::{
    connection::{
        ConnectionInfo, HandshakeData, HandshakeDataV1_2, ServerCertData, ServerSignature,
        TranscriptLength,
    },
    transcript::Transcript,
};
use uid_mux::FramedUidMux as _;

use tracing::{debug, info_span, instrument, Instrument, Span};

/// A prover instance.
#[derive(Debug)]
pub struct Prover<T: state::ProverState> {
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

    /// Sets up the prover.
    ///
    /// This performs all MPC setup prior to establishing the connection to the
    /// application server.
    ///
    /// # Arguments
    ///
    /// * `socket` - The socket to the TLS verifier.
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub async fn setup<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
        self,
        socket: S,
    ) -> Result<Prover<state::Setup>, ProverError> {
        let (mut mux_fut, mux_ctrl) = attach_mux(socket, Role::Prover);

        let mut io = mux_fut
            .poll_with(mux_ctrl.open_framed(b"tlsnotary"))
            .await?;

        // Sends protocol configuration to verifier for compatibility check.
        mux_fut
            .poll_with(io.send(self.config.protocol_config().clone()))
            .await?;

        // Maximum thread forking concurrency of 8.
        // TODO: Determine the optimal number of threads.
        let mut exec = Executor::new(mux_ctrl.clone(), 8);

        let (mpc_tls, vm, ot_recv) = mux_fut
            .poll_with(setup_mpc_backend(&self.config, &mux_ctrl, &mut exec))
            .await?;

        let ctx = mux_fut.poll_with(exec.new_thread()).await?;

        Ok(Prover {
            config: self.config,
            span: self.span,
            state: state::Setup {
                io,
                mux_ctrl,
                mux_fut,
                mpc_tls,
                vm,
                ot_recv,
                ctx,
            },
        })
    }
}

impl Prover<state::Setup> {
    /// Connects to the server using the provided socket.
    ///
    /// Returns a handle to the TLS connection, a future which returns the
    /// prover once the connection is closed.
    ///
    /// # Arguments
    ///
    /// * `socket` - The socket to the server.
    #[instrument(parent = &self.span, level = "debug", skip_all, err)]
    pub async fn connect<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
        self,
        socket: S,
    ) -> Result<(TlsConnection, ProverFuture), ProverError> {
        let state::Setup {
            io,
            mux_ctrl,
            mut mux_fut,
            mpc_tls,
            vm,
            ot_recv,
            ctx,
        } = self.state;

        let (mpc_ctrl, mpc_fut) = mpc_tls.run();

        let server_name =
            TlsServerName::try_from(self.config.server_name().as_str()).map_err(|_| {
                ProverError::config(format!(
                    "invalid server name: {}",
                    self.config.server_name()
                ))
            })?;

        let config = tls_client::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(self.config.crypto_provider().cert.root_store().clone())
            .with_no_client_auth();
        let client =
            ClientConnection::new(Arc::new(config), Box::new(mpc_ctrl.clone()), server_name)
                .map_err(ProverError::config)?;

        let (conn, conn_fut) = bind_client(socket, client);

        let start_time = web_time::UNIX_EPOCH.elapsed().unwrap().as_secs();

        let fut = Box::pin({
            let span = self.span.clone();
            let mpc_ctrl = mpc_ctrl.clone();
            async move {
                let conn_fut = async {
                    let ClosedConnection { sent, recv, .. } = mux_fut
                        .poll_with(conn_fut.map_err(ProverError::from))
                        .await?;

                    mpc_ctrl.close_connection().await?;

                    Ok::<_, ProverError>((sent, recv))
                };

                let ((sent, recv), mpc_tls_data) = futures::try_join!(
                    conn_fut,
                    mpc_fut.in_current_span().map_err(ProverError::from)
                )?;

                let connection_info = ConnectionInfo {
                    time: start_time,
                    version: mpc_tls_data
                        .protocol_version
                        .try_into()
                        .expect("only supported version should have been accepted"),
                    transcript_length: TranscriptLength {
                        sent: sent.len() as u32,
                        received: recv.len() as u32,
                    },
                };

                let server_cert_data = ServerCertData {
                    certs: mpc_tls_data
                        .server_cert_details
                        .cert_chain()
                        .iter()
                        .cloned()
                        .map(|c| c.into())
                        .collect(),
                    sig: ServerSignature {
                        scheme: mpc_tls_data
                            .server_kx_details
                            .kx_sig()
                            .scheme
                            .try_into()
                            .expect("only supported signature scheme should have been accepted"),
                        sig: mpc_tls_data.server_kx_details.kx_sig().sig.0.clone(),
                    },
                    handshake: HandshakeData::V1_2(HandshakeDataV1_2 {
                        client_random: mpc_tls_data.client_random.0,
                        server_random: mpc_tls_data.server_random.0,
                        server_ephemeral_key: mpc_tls_data
                            .server_public_key
                            .try_into()
                            .expect("only supported key scheme should have been accepted"),
                    }),
                };

                Ok(Prover {
                    config: self.config,
                    span: self.span,
                    state: state::Closed {
                        io,
                        mux_ctrl,
                        mux_fut,
                        vm,
                        ot_recv,
                        ctx,
                        connection_info,
                        server_cert_data,
                        transcript: Transcript::new(sent, recv),
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

impl Prover<state::Closed> {
    /// Returns the transcript.
    pub fn transcript(&self) -> &Transcript {
        &self.state.transcript
    }

    /// Starts notarization of the TLS session.
    ///
    /// Used when the TLS verifier is a Notary to transition the prover to the
    /// next state where it can generate commitments to the transcript prior
    /// to finalization.
    pub fn start_notarize(self) -> Prover<Notarize> {
        Prover {
            config: self.config,
            span: self.span,
            state: self.state.into(),
        }
    }

    /// Starts proving the TLS session.
    ///
    /// This function transitions the prover into a state where it can prove
    /// content of the transcript.
    pub fn start_prove(self) -> Prover<Prove> {
        Prover {
            config: self.config,
            span: self.span,
            state: self.state.into(),
        }
    }
}

/// Performs a setup of the various MPC subprotocols.
#[instrument(level = "debug", skip_all, err)]
async fn setup_mpc_backend(
    config: &ProverConfig,
    mux: &MuxControl,
    exec: &mut Executor,
) -> Result<(MpcTlsLeader, DEAPThread, OTReceiver), ProverError> {
    debug!("starting MPC backend setup");

    let mut ot_sender = kos::Sender::new(
        config.build_ot_sender_config(),
        chou_orlandi::Receiver::new(config.build_base_ot_receiver_config()),
    );
    ot_sender.alloc(config.protocol_config().ot_sender_setup_count(Role::Prover));

    let mut ot_receiver = kos::Receiver::new(
        config.build_ot_receiver_config(),
        chou_orlandi::Sender::new(config.build_base_ot_sender_config()),
    );
    ot_receiver.alloc(
        config
            .protocol_config()
            .ot_receiver_setup_count(Role::Prover),
    );

    let ot_sender = OTSender::new(ot_sender);
    let ot_receiver = OTReceiver::new(ot_receiver);

    let (
        ctx_vm,
        ctx_ke_0,
        ctx_ke_1,
        ctx_prf_0,
        ctx_prf_1,
        ctx_encrypter_block_cipher,
        ctx_encrypter_stream_cipher,
        ctx_encrypter_ghash,
        ctx_encrypter,
        ctx_decrypter_block_cipher,
        ctx_decrypter_stream_cipher,
        ctx_decrypter_ghash,
        ctx_decrypter,
    ) = futures::try_join!(
        exec.new_thread(),
        exec.new_thread(),
        exec.new_thread(),
        exec.new_thread(),
        exec.new_thread(),
        exec.new_thread(),
        exec.new_thread(),
        exec.new_thread(),
        exec.new_thread(),
        exec.new_thread(),
        exec.new_thread(),
        exec.new_thread(),
        exec.new_thread(),
    )?;

    let vm = DEAPThread::new(
        DEAPRole::Leader,
        rand::rngs::OsRng.gen(),
        ctx_vm,
        ot_sender.clone(),
        ot_receiver.clone(),
    );

    let mpc_tls_config = config.build_mpc_tls_config();
    let (ke, prf, encrypter, decrypter) = build_components(
        TlsRole::Leader,
        mpc_tls_config.common(),
        ctx_ke_0,
        ctx_encrypter,
        ctx_decrypter,
        ctx_encrypter_ghash,
        ctx_decrypter_ghash,
        vm.new_thread(ctx_ke_1, ot_sender.clone(), ot_receiver.clone())?,
        vm.new_thread(ctx_prf_0, ot_sender.clone(), ot_receiver.clone())?,
        vm.new_thread(ctx_prf_1, ot_sender.clone(), ot_receiver.clone())?,
        vm.new_thread(
            ctx_encrypter_block_cipher,
            ot_sender.clone(),
            ot_receiver.clone(),
        )?,
        vm.new_thread(
            ctx_decrypter_block_cipher,
            ot_sender.clone(),
            ot_receiver.clone(),
        )?,
        vm.new_thread(
            ctx_encrypter_stream_cipher,
            ot_sender.clone(),
            ot_receiver.clone(),
        )?,
        vm.new_thread(
            ctx_decrypter_stream_cipher,
            ot_sender.clone(),
            ot_receiver.clone(),
        )?,
        ot_sender.clone(),
        ot_receiver.clone(),
    );

    let channel = mux.open_framed(b"mpc_tls").await?;
    let mut mpc_tls = MpcTlsLeader::new(
        mpc_tls_config,
        Box::new(StreamExt::compat_stream(channel)),
        ke,
        prf,
        encrypter,
        decrypter,
    );

    mpc_tls.setup().await?;

    debug!("MPC backend setup complete");

    Ok((mpc_tls, vm, ot_receiver))
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
    pub async fn defer_decryption(&self) -> Result<(), ProverError> {
        self.mpc_ctrl
            .defer_decryption()
            .await
            .map_err(ProverError::from)
    }
}
