//! TLS prover.
//!
//! This module provides the TLS prover, which is used with a TLS verifier to prove a transcript of
//! communications with a server.
//!
//! The TLS prover provides a low-level API, see the [`HTTP prover`](crate::http) which provides
//! abstractions for working with HTTP sessions.

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
use serio::StreamExt;
use std::sync::Arc;
use tls_client::{ClientConnection, ServerName as TlsServerName};
use tls_client_async::{bind_client, ClosedConnection, TlsConnection};
use tls_mpc::{build_components, LeaderCtrl, MpcTlsLeader, TlsRole};
use tlsn_common::{
    mux::{attach_mux, MuxControl},
    DEAPThread, Executor, OTReceiver, OTSender, Role,
};
use tlsn_core::transcript::Transcript;
use uid_mux::FramedUidMux as _;

#[cfg(feature = "formats")]
use crate::http::{state as http_state, HttpProver, HttpProverError};

use tracing::{debug, debug_span, instrument, Instrument};

/// A prover instance.
#[derive(Debug)]
pub struct Prover<T: state::ProverState> {
    config: ProverConfig,
    state: T,
}

impl Prover<state::Initialized> {
    /// Creates a new prover.
    ///
    /// # Arguments
    ///
    /// * `config` - The configuration for the prover.
    pub fn new(config: ProverConfig) -> Self {
        Self {
            config,
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
    #[instrument(level = "debug", skip_all, err)]
    pub async fn setup<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
        self,
        socket: S,
    ) -> Result<Prover<state::Setup>, ProverError> {
        let (mut mux_fut, mux_ctrl) = attach_mux(socket, Role::Prover);

        // Maximum thread forking concurrency of 8.
        // TODO: Determine the optimal number of threads.
        let mut exec = Executor::new(mux_ctrl.clone(), 8);

        let (mpc_tls, vm, ot_recv) = mux_fut
            .poll_with(setup_mpc_backend(&self.config, &mux_ctrl, &mut exec))
            .await?;

        let io = mux_fut
            .poll_with(
                mux_ctrl
                    .open_framed(b"tlsnotary")
                    .map_err(ProverError::from),
            )
            .await?;

        let ctx = mux_fut
            .poll_with(exec.new_thread().map_err(ProverError::from))
            .await?;

        Ok(Prover {
            config: self.config,
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
    /// Returns a handle to the TLS connection, a future which returns the prover once the connection is
    /// closed.
    ///
    /// # Arguments
    ///
    /// * `socket` - The socket to the server.
    #[instrument(level = "debug", skip_all, err)]
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

        let server_name = TlsServerName::try_from(self.config.server_dns())?;
        let config = tls_client::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(self.config.root_cert_store.clone())
            .with_no_client_auth();
        let client =
            ClientConnection::new(Arc::new(config), Box::new(mpc_ctrl.clone()), server_name)?;

        let (conn, conn_fut) = bind_client(socket, client);

        let start_time = web_time::UNIX_EPOCH.elapsed().unwrap().as_secs();

        let fut = Box::pin({
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

                Ok(Prover {
                    config: self.config,
                    state: state::Closed {
                        io,
                        mux_ctrl,
                        mux_fut,
                        vm,
                        ot_recv,
                        ctx,
                        start_time,
                        handshake_decommitment: mpc_tls_data
                            .handshake_decommitment
                            .expect("handshake was committed"),
                        server_public_key: mpc_tls_data.server_public_key,
                        transcript_tx: Transcript::new(sent),
                        transcript_rx: Transcript::new(recv),
                    },
                })
            }
            .instrument(debug_span!("prover"))
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
    /// Returns the transcript of the sent requests
    pub fn sent_transcript(&self) -> &Transcript {
        &self.state.transcript_tx
    }

    /// Returns the transcript of the received responses
    pub fn recv_transcript(&self) -> &Transcript {
        &self.state.transcript_rx
    }

    /// Creates an HTTP prover.
    #[cfg(feature = "formats")]
    pub fn to_http(self) -> Result<HttpProver<http_state::Closed>, HttpProverError> {
        HttpProver::new(self)
    }

    /// Starts notarization of the TLS session.
    ///
    /// Used when the TLS verifier is a Notary to transition the prover to the next state
    /// where it can generate commitments to the transcript prior to finalization.
    pub fn start_notarize(self) -> Prover<Notarize> {
        Prover {
            config: self.config,
            state: self.state.into(),
        }
    }

    /// Starts proving the TLS session.
    ///
    /// This function transitions the prover into a state where it can prove content of the
    /// transcript.
    pub fn start_prove(self) -> Prover<Prove> {
        Prover {
            config: self.config,
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
    let mut ot_sender = kos::Sender::new(
        config.build_ot_sender_config(),
        chou_orlandi::Receiver::new(config.build_base_ot_receiver_config()),
    );
    ot_sender.alloc(config.ot_sender_setup_count());

    let mut ot_receiver = kos::Receiver::new(
        config.build_ot_receiver_config(),
        chou_orlandi::Sender::new(config.build_base_ot_sender_config()),
    );
    ot_receiver.alloc(config.ot_receiver_setup_count());

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
    /// Defers decryption of data from the server until the server has closed the connection.
    ///
    /// This is a performance optimization which will significantly reduce the amount of upload bandwidth
    /// used by the prover.
    ///
    /// # Notes
    ///
    /// * The prover may need to close the connection to the server in order for it to close the connection
    ///   on its end. If neither the prover or server close the connection this will cause a deadlock.
    pub async fn defer_decryption(&self) -> Result<(), ProverError> {
        self.mpc_ctrl
            .defer_decryption()
            .await
            .map_err(ProverError::from)
    }
}
