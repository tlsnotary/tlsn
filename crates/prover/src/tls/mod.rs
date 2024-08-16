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
use tls_tee::TeeTlsLeader;
use tlsn_common::{
    mux::{attach_mux, MuxControl},
    Role,
};
use uid_mux::FramedUidMux as _;

#[cfg(feature = "formats")]
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
    /// This performs all TEE setup prior to establishing the connection to the
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

        let tee_tls = mux_fut
            .poll_with(setup_tee_backend(&self.config, &mux_ctrl))
            .await?;

        let io = mux_fut
            .poll_with(
                mux_ctrl
                    .open_framed(b"tlsnotary")
                    .map_err(ProverError::from),
            )
            .await?;

        Ok(Prover {
            config: self.config,
            span: self.span,
            state: state::Setup {
                io,
                mux_ctrl,
                mux_fut,
                tee_tls,
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
            tee_tls,
            ..
        } = self.state;

        let (tee_ctrl, tee_fut) = tee_tls.run();

        let server_name = TlsServerName::try_from(self.config.server_dns())?;
        let config = tls_client::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(self.config.root_cert_store.clone())
            .with_no_client_auth();
        let client =
            ClientConnection::new(Arc::new(config), Box::new(tee_ctrl.clone()), server_name)?;

        let (conn, conn_fut) = bind_client(socket, client);

        let _start_time = web_time::UNIX_EPOCH.elapsed().unwrap().as_secs();

        let fut = Box::pin({
            let span = self.span.clone();
            let tee_ctrl = tee_ctrl.clone();
            async move {
                let conn_fut = async {
                    let ClosedConnection { sent, recv, .. } = mux_fut
                        .poll_with(conn_fut.map_err(ProverError::from))
                        .await?;

                    tee_ctrl.close_connection().await?;

                    Ok::<_, ProverError>((sent, recv))
                };

                let ((_, _), tls_data) = futures::try_join!(
                    conn_fut,
                    tee_fut.in_current_span().map_err(ProverError::from)
                )?;

                debug!("TLS connection closed {:?}", tls_data);

                Ok(Prover {
                    config: self.config,
                    span: self.span,
                    state: state::Closed {
                        application_data: tls_data.application_data,
                        io,
                        mux_ctrl,
                        mux_fut,
                    },
                })
            }
            .instrument(span)
        });

        Ok((
            conn,
            ProverFuture {
                fut,
                ctrl: ProverControl {},
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

/// Performs a setup of the various Tee subprotocols.
#[instrument(level = "debug", skip_all, err)]
async fn setup_tee_backend(
    config: &ProverConfig,
    mux: &MuxControl,
) -> Result<TeeTlsLeader, ProverError> {
    debug!("starting TEE backend setup");

    let _tee_tls_config = config.build_tee_tls_config();

    let channel = mux.open_framed(b"tee_tls").await?;
    let mut tee_tls = TeeTlsLeader::new(Box::new(StreamExt::compat_stream(channel)));

    tee_tls.setup().await?;

    debug!("TEE backend setup complete");

    Ok(tee_tls)
}

/// A controller for the prover.
#[derive(Clone)]
pub struct ProverControl {}

impl ProverControl {}
