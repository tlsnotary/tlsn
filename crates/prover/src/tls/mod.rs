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
use serio::StreamExt;
use std::sync::Arc;
use tls_client::{ClientConnection, ServerName as TlsServerName};
use tls_client_async::{bind_client, ClosedConnection, TlsConnection};
use tls_tee::{TeeLeaderCtrl, TeeTlsLeader, TeeTlsRole};
use tlsn_common::{
    mux::{attach_mux, MuxControl},
    DEAPThread, Executor, OTReceiver, OTSender, Role,
};
use tlsn_core::transcript::Transcript;
use uid_mux::FramedUidMux as _;

#[cfg(feature = "formats")]
use crate::http::{state as http_state, HttpProver, HttpProverError};

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
        let span = info_span!("prover", id = config.id());
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

        // Maximum thread forking concurrency of 8.
        // TODO: Determine the optimal number of threads.
        let mut exec = Executor::new(mux_ctrl.clone(), 8);

        let (mpc_tls) = mux_fut
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
            span: self.span,
            state: state::Setup {
                io,
                mux_ctrl,
                mux_fut,
                ctx,
                mpc_tls,
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

                Ok(Prover {
                    config: self.config,
                    span: self.span,
                    state: state::Closed {
                        io,
                        mux_ctrl,
                        mux_fut,
                        ctx,
                        start_time,
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
    /// Creates an HTTP prover.
    // #[cfg(feature = "formats")]
    // pub fn to_http(self) -> Result<HttpProver<http_state::Closed>, HttpProverError> {
    //     HttpProver::new(self)
    // }

    /// Starts notarization of the TLS session.
    ///
    /// Used when the TLS verifier is a Notary to transition the prover to the next state
    /// where it can generate commitments to the transcript prior to finalization.
    pub fn start_notarize(self) -> Prover<Notarize> {
        Prover {
            config: self.config,
            span: self.span,
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
) -> Result<(TeeTlsLeader), ProverError> {
    debug!("starting MPC backend setup");

    let mpc_tls_config = config.build_mpc_tls_config();

    let channel = mux.open_framed(b"mpc_tls").await?;
    let mut mpc_tls = TeeTlsLeader::new(Box::new(StreamExt::compat_stream(channel)));

    mpc_tls.setup().await?;

    debug!("MPC backend setup complete");

    Ok((mpc_tls))
}

/// A controller for the prover.
#[derive(Clone)]
pub struct ProverControl {
    mpc_ctrl: TeeLeaderCtrl,
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
