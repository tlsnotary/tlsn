//! TLS Verifier.

pub(crate) mod config;
mod error;
mod notarize;
pub mod state;
mod verify;

pub use config::{VerifierConfig, VerifierConfigBuilder, VerifierConfigBuilderError};
pub use error::VerifierError;
use serio::StreamExt;
use uid_mux::FramedUidMux;

use web_time::{SystemTime, UNIX_EPOCH};

use futures::{AsyncRead, AsyncWrite, TryFutureExt};
use signature::Signer;
use state::{Notarize, Verify};
use tls_tee::TeeTlsFollower;
use tlsn_common::{
    mux::{attach_mux, MuxControl},
    Executor, Role,
};
use tlsn_core::Signature;

use tracing::{debug, info, info_span, instrument, Span};

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
        let (mut mux_fut, mux_ctrl) = attach_mux(socket, Role::Verifier);

        // Maximum thread forking concurrency of 8.
        // TODO: Determine the optimal number of threads.
        let mut exec = Executor::new(mux_ctrl.clone(), 8);

        let tee_tls = mux_fut
            .poll_with(setup_tee_backend(&self.config, &mux_ctrl, &mut exec))
            .await?;

        let _io = mux_fut
            .poll_with(
                mux_ctrl
                    .open_framed(b"tlsnotary")
                    .map_err(VerifierError::from),
            )
            .await?;

        let _ctx = mux_fut
            .poll_with(exec.new_thread().map_err(VerifierError::from))
            .await?;

        Ok(Verifier {
            config: self.config,
            span: self.span,
            state: state::Setup {
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
    ) -> Result<(), VerifierError>
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
            mux_ctrl,
            mut mux_fut,
            tee_tls,
        } = self.state;

        let _start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        mux_fut
            .poll_with(tee_tls.run().1.map_err(VerifierError::from))
            .await?;

        info!("Finished TLS session");

        Ok(Verifier {
            config: self.config,
            span: self.span,
            state: state::Closed {
                mux_ctrl,
                mux_fut,
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
    _exec: &mut Executor,
) -> Result<TeeTlsFollower, VerifierError> {
    debug!("starting TEE backend setup");

    let _tee_tls_config = config.build_tee_tls_config();

    let channel = mux.open_framed(b"tee_tls").await?;
    let mut tee_tls = TeeTlsFollower::new(Box::new(StreamExt::compat_stream(channel)));

    tee_tls.setup().await?;

    debug!("TEE backend setup complete");

    Ok(tee_tls)
}
