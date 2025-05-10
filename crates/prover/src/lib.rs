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
use mpz_common::Context;
use mpz_core::Block;
use mpz_garble_core::Delta;
use state::{Notarize, Prove};

use futures::{AsyncRead, AsyncWrite, TryFutureExt};
use mpc_tls::{LeaderCtrl, MpcTlsLeader};
use rand::Rng;
use serio::SinkExt;
use std::sync::Arc;
use tls_client::{ClientConnection, ServerName as TlsServerName};
use tls_client_async::{bind_client, TlsConnection};
use tls_core::msgs::enums::ContentType;
use tlsn_common::{
    commit::commit_records, context::build_mt_context, mux::attach_mux, zk_aes::ZkAesCtr, Role,
};
use tlsn_core::{
    connection::{
        ConnectionInfo, HandshakeData, HandshakeDataV1_2, ServerCertData, ServerSignature,
        TranscriptLength,
    },
    transcript::Transcript,
};
use tlsn_deap::Deap;
use tokio::sync::Mutex;

use tracing::{debug, info_span, instrument, Instrument, Span};

pub(crate) type RCOTSender = mpz_ot::rcot::shared::SharedRCOTSender<
    mpz_ot::kos::Sender<mpz_ot::chou_orlandi::Receiver>,
    mpz_core::Block,
>;
pub(crate) type RCOTReceiver = mpz_ot::rcot::shared::SharedRCOTReceiver<
    mpz_ot::ferret::Receiver<mpz_ot::kos::Receiver<mpz_ot::chou_orlandi::Sender>>,
    bool,
    mpz_core::Block,
>;
pub(crate) type Mpc =
    mpz_garble::protocol::semihonest::Garbler<mpz_ot::cot::DerandCOTSender<RCOTSender>>;
pub(crate) type Zk = mpz_zk::Prover<RCOTReceiver>;

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
        let mut mt = build_mt_context(mux_ctrl.clone());
        let mut ctx = mux_fut.poll_with(mt.new_context()).await?;

        // Sends protocol configuration to verifier for compatibility check.
        mux_fut
            .poll_with(ctx.io_mut().send(self.config.protocol_config().clone()))
            .await?;

        let (vm, mut mpc_tls) = build_mpc_tls(&self.config, ctx);

        // Allocate resources for MPC-TLS in VM.
        let keys = mpc_tls.alloc()?;
        // Allocate for committing to plaintext.
        let mut zk_aes = ZkAesCtr::new(Role::Prover);
        zk_aes.set_key(keys.server_write_key, keys.server_write_iv);
        zk_aes.alloc(
            &mut (*vm.try_lock().expect("VM is not locked").zk()),
            self.config.protocol_config().max_recv_data(),
        )?;

        debug!("setting up mpc-tls");

        mux_fut.poll_with(mpc_tls.preprocess()).await?;

        debug!("mpc-tls setup complete");

        Ok(Prover {
            config: self.config,
            span: self.span,
            state: state::Setup {
                mux_ctrl,
                mux_fut,
                mt,
                mpc_tls,
                zk_aes,
                keys,
                vm,
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
            mux_ctrl,
            mut mux_fut,
            mt,
            mpc_tls,
            mut zk_aes,
            keys,
            vm,
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

        let start_time = web_time::UNIX_EPOCH
            .elapsed()
            .expect("system time is available")
            .as_secs();

        let fut = Box::pin({
            let span = self.span.clone();
            let mpc_ctrl = mpc_ctrl.clone();
            async move {
                let conn_fut = async {
                    mux_fut
                        .poll_with(conn_fut.map_err(ProverError::from))
                        .await?;

                    mpc_ctrl.stop().await?;

                    Ok::<_, ProverError>(())
                };

                let (_, (mut ctx, mut data)) = futures::try_join!(
                    conn_fut,
                    mpc_fut.in_current_span().map_err(ProverError::from)
                )?;

                {
                    let mut vm = vm.try_lock().expect("VM should not be locked");

                    // Prove received plaintext. Prover drops the proof output, as they trust
                    // themselves.
                    _ = commit_records(
                        &mut (*vm.zk()),
                        &mut zk_aes,
                        data.transcript
                            .recv
                            .iter_mut()
                            .filter(|record| record.typ == ContentType::ApplicationData),
                    )
                    .map_err(ProverError::zk)?;

                    debug!("finalizing mpc");

                    // Finalize DEAP and execute the plaintext proofs.
                    mux_fut
                        .poll_with(vm.finalize(&mut ctx))
                        .await
                        .map_err(ProverError::mpc)?;

                    debug!("mpc finalized");
                }

                let transcript = data
                    .transcript
                    .to_transcript()
                    .expect("transcript is complete");
                let transcript_refs = data
                    .transcript
                    .to_transcript_refs()
                    .expect("transcript is complete");

                let connection_info = ConnectionInfo {
                    time: start_time,
                    version: data
                        .protocol_version
                        .try_into()
                        .expect("only supported version should have been accepted"),
                    transcript_length: TranscriptLength {
                        sent: transcript.sent().len() as u32,
                        received: transcript.received().len() as u32,
                    },
                };

                let server_cert_data =
                    ServerCertData {
                        certs: data
                            .server_cert_details
                            .cert_chain()
                            .iter()
                            .cloned()
                            .map(|c| c.into())
                            .collect(),
                        sig: ServerSignature {
                            scheme: data.server_kx_details.kx_sig().scheme.try_into().expect(
                                "only supported signature scheme should have been accepted",
                            ),
                            sig: data.server_kx_details.kx_sig().sig.0.clone(),
                        },
                        handshake: HandshakeData::V1_2(HandshakeDataV1_2 {
                            client_random: data.client_random.0,
                            server_random: data.server_random.0,
                            server_ephemeral_key: data
                                .server_key
                                .try_into()
                                .expect("only supported key scheme should have been accepted"),
                        }),
                    };

                // Pull out ZK VM.
                let (_, vm) = Arc::into_inner(vm)
                    .expect("vm should have only 1 reference")
                    .into_inner()
                    .into_inner();

                Ok(Prover {
                    config: self.config,
                    span: self.span,
                    state: state::Closed {
                        mux_ctrl,
                        mux_fut,
                        mt,
                        ctx,
                        _keys: keys,
                        vm,
                        connection_info,
                        server_cert_data,
                        transcript,
                        transcript_refs,
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

fn build_mpc_tls(config: &ProverConfig, ctx: Context) -> (Arc<Mutex<Deap<Mpc, Zk>>>, MpcTlsLeader) {
    let mut rng = rand::rng();
    let delta = Delta::new(Block::random(&mut rng));

    let base_ot_send = mpz_ot::chou_orlandi::Sender::default();
    let base_ot_recv = mpz_ot::chou_orlandi::Receiver::default();
    let rcot_send = mpz_ot::kos::Sender::new(
        mpz_ot::kos::SenderConfig::default(),
        delta.into_inner(),
        base_ot_recv,
    );
    let rcot_recv =
        mpz_ot::kos::Receiver::new(mpz_ot::kos::ReceiverConfig::default(), base_ot_send);
    let rcot_recv = mpz_ot::ferret::Receiver::new(
        mpz_ot::ferret::FerretConfig::builder()
            .lpn_type(mpz_ot::ferret::LpnType::Regular)
            .build()
            .expect("ferret config is valid"),
        Block::random(&mut rng),
        rcot_recv,
    );

    let rcot_send = mpz_ot::rcot::shared::SharedRCOTSender::new(rcot_send);
    let rcot_recv = mpz_ot::rcot::shared::SharedRCOTReceiver::new(rcot_recv);

    let mpc = Mpc::new(
        mpz_ot::cot::DerandCOTSender::new(rcot_send.clone()),
        rng.random(),
        delta,
    );

    let zk = Zk::new(rcot_recv.clone());

    let vm = Arc::new(Mutex::new(Deap::new(tlsn_deap::Role::Leader, mpc, zk)));

    (
        vm.clone(),
        MpcTlsLeader::new(
            config.build_mpc_tls_config(),
            ctx,
            vm,
            (rcot_send.clone(), rcot_send.clone(), rcot_send),
            rcot_recv,
        ),
    )
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
