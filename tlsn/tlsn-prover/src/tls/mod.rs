//! TLS prover.
//!
//! This module provides the TLS prover, which is used with a TLS verifier to prove a transcript of communications with a server.
//!
//! The TLS prover provides a low-level API, see the [`HTTP prover`](crate::http) which provides abstractions for working
//! with HTTP sessions.

mod config;
mod error;
mod future;
mod notarize;
mod prove;
pub mod state;

pub use config::{ProverConfig, ProverConfigBuilder, ProverConfigBuilderError};
pub use error::ProverError;
pub use future::ProverFuture;

use crate::Mux;
use error::OTShutdownError;
use future::{MuxFuture, OTFuture};
use futures::{AsyncRead, AsyncWrite, FutureExt, StreamExt, TryFutureExt};
use mpz_garble::{config::Role as DEAPRole, protocol::deap::DEAPVm};
use mpz_ot::{
    actor::kos::{ReceiverActor, SenderActor, SharedReceiver, SharedSender},
    chou_orlandi, kos,
};
use mpz_share_conversion as ff;
use rand::Rng;
use state::{Notarize, Prove};
use std::sync::Arc;
use tls_client::{ClientConnection, ServerName as TlsServerName};
use tls_client_async::{bind_client, ClosedConnection, TlsConnection};
use tls_mpc::{setup_components, LeaderCtrl, MpcTlsLeader, TlsRole};
use tlsn_core::transcript::Transcript;
use uid_mux::{yamux, UidYamux};
use utils_aio::{codec::BincodeMux, mux::MuxChannel};

#[cfg(feature = "formats")]
use http::{state as http_state, HttpProver, HttpProverError};

#[cfg(feature = "tracing")]
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

    /// Set up the prover.
    ///
    /// This performs all MPC setup prior to establishing the connection to the
    /// application server.
    ///
    /// # Arguments
    ///
    /// * `socket` - The socket to the notary.
    pub async fn setup<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
        self,
        socket: S,
    ) -> Result<Prover<state::Setup>, ProverError> {
        let mut mux = UidYamux::new(yamux::Config::default(), socket, yamux::Mode::Client);
        let notary_mux = BincodeMux::new(mux.control());

        let mut mux_fut = MuxFuture {
            fut: Box::pin(async move { mux.run().await.map_err(ProverError::from) }.fuse()),
        };

        let mpc_setup_fut = setup_mpc_backend(&self.config, notary_mux.clone());
        let (mpc_tls, vm, _, gf2, ot_fut) = futures::select! {
            res = mpc_setup_fut.fuse() => res?,
            _ = (&mut mux_fut).fuse() => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?,
        };

        Ok(Prover {
            config: self.config,
            state: state::Setup {
                notary_mux,
                mux_fut,
                mpc_tls,
                vm,
                ot_fut,
                gf2,
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
    #[cfg_attr(
        feature = "tracing",
        instrument(level = "debug", skip(self, socket), err)
    )]
    pub async fn connect<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
        self,
        socket: S,
    ) -> Result<(TlsConnection, ProverFuture), ProverError> {
        let state::Setup {
            notary_mux,
            mut mux_fut,
            mpc_tls,
            vm,
            mut ot_fut,
            gf2,
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
            #[allow(clippy::let_and_return)]
            let fut = async move {
                let conn_fut = async {
                    let ClosedConnection { sent, recv, .. } = futures::select! {
                        res = conn_fut.fuse() => res?,
                        _ = ot_fut => return Err(OTShutdownError)?,
                        _ = mux_fut => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?,
                    };

                    mpc_ctrl.close_connection().await?;

                    Ok::<_, ProverError>((sent, recv))
                };

                let ((sent, recv), mpc_tls_data) =
                    futures::try_join!(conn_fut, mpc_fut.map_err(ProverError::from))?;

                Ok(Prover {
                    config: self.config,
                    state: state::Closed {
                        notary_mux,
                        mux_fut,
                        vm,
                        ot_fut,
                        gf2,
                        start_time,
                        handshake_decommitment: mpc_tls_data
                            .handshake_decommitment
                            .expect("handshake was committed"),
                        server_public_key: mpc_tls_data.server_public_key,
                        transcript_tx: Transcript::new(sent),
                        transcript_rx: Transcript::new(recv),
                    },
                })
            };
            #[cfg(feature = "tracing")]
            let fut = fut.instrument(debug_span!("prover_tls_connection"));
            fut
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
    /// If the verifier is a Notary, this function will transition the prover to the next state
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
#[cfg_attr(feature = "tracing", instrument(level = "debug", skip_all, err))]
#[allow(clippy::type_complexity)]
async fn setup_mpc_backend(
    config: &ProverConfig,
    mut mux: Mux,
) -> Result<
    (
        MpcTlsLeader,
        DEAPVm<SharedSender, SharedReceiver>,
        SharedReceiver,
        ff::ConverterSender<ff::Gf2_128, SharedSender>,
        OTFuture,
    ),
    ProverError,
> {
    let (ot_send_sink, ot_send_stream) = mux.get_channel("ot/0").await?.split();
    let (ot_recv_sink, ot_recv_stream) = mux.get_channel("ot/1").await?.split();

    let mut ot_sender_actor = SenderActor::new(
        kos::Sender::new(
            config.build_ot_sender_config(),
            chou_orlandi::Receiver::new(config.build_base_ot_receiver_config()),
        ),
        ot_send_sink,
        ot_send_stream,
    );

    let mut ot_receiver_actor = ReceiverActor::new(
        kos::Receiver::new(
            config.build_ot_receiver_config(),
            chou_orlandi::Sender::new(config.build_base_ot_sender_config()),
        ),
        ot_recv_sink,
        ot_recv_stream,
    );

    let ot_send = ot_sender_actor.sender();
    let ot_recv = ot_receiver_actor.receiver();

    #[cfg(feature = "tracing")]
    debug!("Starting OT setup");

    futures::try_join!(
        ot_sender_actor
            .setup(config.ot_count())
            .map_err(ProverError::from),
        ot_receiver_actor
            .setup(config.ot_count())
            .map_err(ProverError::from)
    )?;

    #[cfg(feature = "tracing")]
    debug!("OT setup complete");

    let ot_fut = OTFuture {
        fut: Box::pin(
            async move {
                futures::try_join!(
                    ot_sender_actor.run().map_err(ProverError::from),
                    ot_receiver_actor.run().map_err(ProverError::from)
                )?;

                Ok(())
            }
            .fuse(),
        ),
    };

    let mut vm = DEAPVm::new(
        "vm",
        DEAPRole::Leader,
        rand::rngs::OsRng.gen(),
        mux.get_channel("vm").await?,
        Box::new(mux.clone()),
        ot_send.clone(),
        ot_recv.clone(),
    );

    let p256_sender_config = config.build_p256_sender_config();
    let channel = mux.get_channel(p256_sender_config.id()).await?;
    let p256_send =
        ff::ConverterSender::<ff::P256, _>::new(p256_sender_config, ot_send.clone(), channel);

    let p256_receiver_config = config.build_p256_receiver_config();
    let channel = mux.get_channel(p256_receiver_config.id()).await?;
    let p256_recv =
        ff::ConverterReceiver::<ff::P256, _>::new(p256_receiver_config, ot_recv.clone(), channel);

    let gf2_config = config.build_gf2_config();
    let channel = mux.get_channel(gf2_config.id()).await?;
    let gf2 = ff::ConverterSender::<ff::Gf2_128, _>::new(gf2_config, ot_send.clone(), channel);

    let mpc_tls_config = config.build_mpc_tls_config();

    let (ke, prf, encrypter, decrypter) = setup_components(
        mpc_tls_config.common(),
        TlsRole::Leader,
        &mut mux,
        &mut vm,
        p256_send,
        p256_recv,
        gf2.handle()
            .map_err(|e| ProverError::MpcError(Box::new(e)))?,
    )
    .await
    .map_err(|e| ProverError::MpcError(Box::new(e)))?;

    let channel = mux.get_channel(mpc_tls_config.common().id()).await?;
    let mut mpc_tls = MpcTlsLeader::new(mpc_tls_config, channel, ke, prf, encrypter, decrypter);

    mpc_tls.setup().await?;

    #[cfg(feature = "tracing")]
    debug!("MPC backend setup complete");

    Ok((mpc_tls, vm, ot_recv, gf2, ot_fut))
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
