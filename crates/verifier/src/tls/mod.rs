//! TLS Verifier.

pub(crate) mod config;
mod error;
mod notarize;
pub mod state;
mod verify;

pub use config::{VerifierConfig, VerifierConfigBuilder, VerifierConfigBuilderError};
pub use error::VerifierError;
use mpz_common::Allocate;
use serio::StreamExt;
use uid_mux::FramedUidMux;

use web_time::{SystemTime, UNIX_EPOCH};

use futures::{AsyncRead, AsyncWrite, TryFutureExt};
use mpz_garble::config::Role as DEAPRole;
use mpz_ot::{chou_orlandi, kos};
use rand::Rng;
use signature::Signer;
use state::{Notarize, Verify};
use tls_tee::{TeeTlsFollower, TeeTlsRole};
use tlsn_common::{
    mux::{attach_mux, MuxControl},
    DEAPThread, Executor, OTReceiver, OTSender, Role,
};
use tlsn_core::{proof::SessionInfo, RedactedTranscript, SessionHeader, Signature};

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
    /// This performs all MPC setup.
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

        let encoder_seed: [u8; 32] = rand::rngs::OsRng.gen();
        let (mpc_tls) = mux_fut
            .poll_with(setup_mpc_backend(
                &self.config,
                &mux_ctrl,
                &mut exec,
                encoder_seed,
            ))
            .await?;

        let io = mux_fut
            .poll_with(
                mux_ctrl
                    .open_framed(b"tlsnotary")
                    .map_err(VerifierError::from),
            )
            .await?;

        let ctx = mux_fut
            .poll_with(exec.new_thread().map_err(VerifierError::from))
            .await?;

        Ok(Verifier {
            config: self.config,
            span: self.span,
            state: state::Setup {
                io,
                mux_ctrl,
                mux_fut,
                mpc_tls,
                ctx,
                encoder_seed,
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
    ) -> Result<(()), VerifierError> {
        let mut verifier = self.setup(socket).await?.run().await?.start_verify();
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
            mpc_tls,
            ctx,
            encoder_seed,
        } = self.state;

        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        mux_fut
            .poll_with(mpc_tls.run().1.map_err(VerifierError::from))
            .await?;

        info!("Finished TLS session");

        Ok(Verifier {
            config: self.config,
            span: self.span,
            state: state::Closed {
                io,
                mux_ctrl,
                mux_fut,
                ctx,
                encoder_seed,
                start_time,
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

/// Performs a setup of the various MPC subprotocols.
#[instrument(level = "debug", skip_all, err)]
async fn setup_mpc_backend(
    config: &VerifierConfig,
    mux: &MuxControl,
    exec: &mut Executor,
    encoder_seed: [u8; 32],
) -> Result<(TeeTlsFollower), VerifierError> {
    debug!("starting MPC backend setup");

    let mpc_tls_config = config.build_mpc_tls_config();

    let channel = mux.open_framed(b"mpc_tls").await?;
    let mut mpc_tls = TeeTlsFollower::new(
        Box::new(StreamExt::compat_stream(channel)),
    );

    mpc_tls.setup().await?;

    debug!("MPC backend setup complete");

    Ok((mpc_tls))
}
