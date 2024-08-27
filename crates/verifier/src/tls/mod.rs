//! TLS Verifier.

pub(crate) mod config;
mod error;
mod notarize;
pub mod state;
mod verify;
/// This module provides functionality for X.
pub mod x;

pub use config::{VerifierConfig, VerifierConfigBuilder, VerifierConfigBuilderError};
pub use error::VerifierError;
use prometheus::{register_histogram, Histogram};
use serio::StreamExt;
use uid_mux::FramedUidMux;

use futures::{AsyncRead, AsyncWrite, TryFutureExt};
use signature::Signer;
use state::{Notarize, Verify};
use tls_tee::{TeeTlsFollower, TeeTlsFollowerData};
use tlsn_common::{
    mux::{attach_mux, MuxControl},
    Role,
};
use tlsn_core::{msg::SignedSession, Signature};

use lazy_static::lazy_static;
use tracing::{debug, info, info_span, instrument, Span};

lazy_static! {
    static ref TLS_SESSION_HISTOGRAM: Histogram = register_histogram!(
        "tls_session_duration_seconds",
        "The duration of tls session in seconds"
    )
    .unwrap();
static ref VERIFIER_SETUP_HISTOGRAM: Histogram = register_histogram!(
        "verifier_setup_duration_seconds",
        "The duration of verifier setup in seconds"
    )
    .unwrap();
}
/// A Verifier instance.
pub struct Verifier<T: state::VerifierState> {
    config: VerifierConfig,
    span: Span,
    state: T,
}

impl Verifier<state::Initialized> {
    /// Creates a new verifier.
    pub fn new(config: VerifierConfig) -> Self {
        let span = info_span!("verifier", id = config.id());
        Self {
            config,
            span,
            state: state::Initialized,
        }
    }

    /// Sets up the verifier.
    ///
    /// This performs all TEE setup.
    ///
    /// # Arguments
    ///
    /// * `socket` - The socket to the prover.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn setup<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
        self,
        socket: S,
    ) -> Result<Verifier<state::Setup>, VerifierError> {
        let timer = VERIFIER_SETUP_HISTOGRAM.start_timer();
        let (mut mux_fut, mux_ctrl) = attach_mux(socket, Role::Verifier);

        let tee_tls = mux_fut
            .poll_with(setup_tee_backend(&self.config, &mux_ctrl))
            .await?;

        let io = mux_fut
            .poll_with(
                mux_ctrl
                    .open_framed(b"tlsnotary")
                    .map_err(VerifierError::from),
            )
            .await?;

        timer.stop_and_record();

        Ok(Verifier {
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

    /// Runs the TLS verifier to completion, notarizing the TLS session.
    ///
    /// This is a convenience method which runs all the steps needed for notarization.
    ///
    /// # Arguments
    ///
    /// * `socket` - The socket to the prover.
    /// * `signer` - The signer used to sign the notarization result.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn notarize<S: AsyncWrite + AsyncRead + Send + Unpin + 'static, T>(
        self,
        socket: S,
        signer: &impl Signer<T>,
    ) -> Result<SignedSession, VerifierError>
    where
        T: Into<Signature>,
    {
        self.setup(socket)
            .await?
            .run()
            .await?
            .start_notarize()
            .finalize(signer)
            .await
    }

    /// Runs the TLS verifier to completion, verifying the TLS session.
    ///
    /// This is a convenience method which runs all the steps needed for verification.
    ///
    /// # Arguments
    ///
    /// * `socket` - The socket to the prover.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn verify<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
        self,
        socket: S,
    ) -> Result<(), VerifierError> {
        let _verifier = self.setup(socket).await?.run().await?.start_verify();
        // let (redacted_sent, redacted_received) = verifier.receive().await?;

        // let session_info = verifier.finalize().await?;
        Ok(())
    }
}

impl Verifier<state::Setup> {
    /// Runs the verifier until the TLS connection is closed.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn run(self) -> Result<Verifier<state::Closed>, VerifierError> {
        let state::Setup {
            io,
            mux_ctrl,
            mut mux_fut,
            tee_tls,
        } = self.state;

        info!("Starting TLS session");
        let timer = TLS_SESSION_HISTOGRAM.start_timer();

        let TeeTlsFollowerData {
            response_data,
            request_data,
        } = mux_fut
            .poll_with(tee_tls.run().1.map_err(VerifierError::from))
            .await?;

        timer.stop_and_record();
        info!(
            "Finished TLS session\r\nrequest:\r\n{}\r\nresponse:\r\n{}",
            request_data, response_data
        );

        Ok(Verifier {
            config: self.config,
            span: self.span,
            state: state::Closed {
                io,
                mux_ctrl,
                mux_fut,
                response_data,
                request_data,
            },
        })
    }
}

impl Verifier<state::Closed> {
    /// Starts notarization of the TLS session.
    ///
    /// If the verifier is a Notary, this function will transition the verifier to the next state
    /// where it can sign the prover's commitments to the transcript.
    pub fn start_notarize(self) -> Verifier<Notarize> {
        Verifier {
            config: self.config,
            span: self.span,
            state: self.state.into(),
        }
    }

    /// Starts verification of the TLS session.
    ///
    /// This function transitions the verifier into a state where it can verify content of the
    /// transcript.
    pub fn start_verify(self) -> Verifier<Verify> {
        Verifier {
            config: self.config,
            span: self.span,
            state: self.state.into(),
        }
    }
}

/// Performs a setup of the various TEE subprotocols.
#[instrument(level = "debug", skip_all, err)]
async fn setup_tee_backend(
    config: &VerifierConfig,
    mux: &MuxControl,
) -> Result<TeeTlsFollower, VerifierError> {
    debug!("starting TEE backend setup");

    let _tee_tls_config = config.build_tee_tls_config();

    let channel = mux.open_framed(b"tee_tls").await?;
    let mut tee_tls = TeeTlsFollower::new(Box::new(StreamExt::compat_stream(channel)));

    tee_tls.setup().await?;

    debug!("TEE backend setup complete");

    Ok(tee_tls)
}
