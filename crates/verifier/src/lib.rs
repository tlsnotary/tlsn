//! TLSNotary verifier library.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

pub(crate) mod config;
mod error;
mod notarize;
pub mod state;
mod verify;

pub use config::{VerifierConfig, VerifierConfigBuilder, VerifierConfigBuilderError};
pub use error::VerifierError;
use mpz_common::Allocate;
use serio::{stream::IoStreamExt, StreamExt};
use uid_mux::FramedUidMux;

use web_time::{SystemTime, UNIX_EPOCH};

use futures::{AsyncRead, AsyncWrite};
use mpz_garble::config::Role as DEAPRole;
use mpz_ot::{chou_orlandi, kos};
use rand::Rng;
use state::{Notarize, Verify};
use tls_mpc::{build_components, MpcTlsFollower, MpcTlsFollowerData, TlsRole};
use tlsn_common::{
    config::ProtocolConfig,
    mux::{attach_mux, MuxControl},
    DEAPThread, Executor, OTReceiver, OTSender, Role,
};
use tlsn_core::{
    attestation::{Attestation, AttestationConfig},
    connection::{ConnectionInfo, ServerName, TlsVersion, TranscriptLength},
    transcript::PartialTranscript,
};

use tracing::{debug, info, info_span, instrument, Span};

/// Information about the TLS session.
#[derive(Debug)]
pub struct SessionInfo {
    /// Server's name.
    pub server_name: ServerName,
    /// Connection information.
    pub connection_info: ConnectionInfo,
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
        let span = info_span!("verifier");
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

        let mut io = mux_fut
            .poll_with(mux_ctrl.open_framed(b"tlsnotary"))
            .await?;

        // Receives protocol configuration from prover to perform compatibility check.
        let protocol_config = mux_fut
            .poll_with(async {
                let peer_configuration: ProtocolConfig = io.expect_next().await?;
                self.config
                    .protocol_config_validator()
                    .validate(&peer_configuration)?;

                Ok::<_, VerifierError>(peer_configuration)
            })
            .await?;

        let encoder_seed: [u8; 32] = rand::rngs::OsRng.gen();
        let (mpc_tls, vm, ot_send) = mux_fut
            .poll_with(setup_mpc_backend(
                &self.config,
                protocol_config,
                &mux_ctrl,
                &mut exec,
                encoder_seed,
            ))
            .await?;

        let ctx = mux_fut.poll_with(exec.new_thread()).await?;

        Ok(Verifier {
            config: self.config,
            span: self.span,
            state: state::Setup {
                io,
                mux_ctrl,
                mux_fut,
                mpc_tls,
                vm,
                ot_send,
                ctx,
                encoder_seed,
            },
        })
    }

    /// Runs the TLS verifier to completion, notarizing the TLS session.
    ///
    /// This is a convenience method which runs all the steps needed for
    /// notarization.
    ///
    /// # Arguments
    ///
    /// * `socket` - The socket to the prover.
    /// * `signer` - The signer used to sign the notarization result.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn notarize<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
        self,
        socket: S,
        config: &AttestationConfig,
    ) -> Result<Attestation, VerifierError> {
        self.setup(socket)
            .await?
            .run()
            .await?
            .start_notarize()
            .finalize(config)
            .await
    }

    /// Runs the TLS verifier to completion, verifying the TLS session.
    ///
    /// This is a convenience method which runs all the steps needed for
    /// verification.
    ///
    /// # Arguments
    ///
    /// * `socket` - The socket to the prover.
    #[instrument(parent = &self.span, level = "info", skip_all, err)]
    pub async fn verify<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
        self,
        socket: S,
    ) -> Result<(PartialTranscript, SessionInfo), VerifierError> {
        let mut verifier = self.setup(socket).await?.run().await?.start_verify();
        let transcript = verifier.receive().await?;

        let session_info = verifier.finalize().await?;
        Ok((transcript, session_info))
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
            vm,
            ot_send,
            ctx,
            encoder_seed,
        } = self.state;

        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let MpcTlsFollowerData {
            server_key,
            bytes_sent,
            bytes_recv,
            ..
        } = mux_fut.poll_with(mpc_tls.run().1).await?;

        info!("Finished TLS session");

        let connection_info = ConnectionInfo {
            time: start_time,
            version: TlsVersion::V1_2,
            transcript_length: TranscriptLength {
                sent: bytes_sent as u32,
                received: bytes_recv as u32,
            },
        };

        Ok(Verifier {
            config: self.config,
            span: self.span,
            state: state::Closed {
                io,
                mux_ctrl,
                mux_fut,
                vm,
                ot_send,
                ctx,
                encoder_seed,
                server_ephemeral_key: server_key
                    .try_into()
                    .expect("only supported key type should have been accepted"),
                connection_info,
            },
        })
    }
}

impl Verifier<state::Closed> {
    /// Starts notarization of the TLS session.
    ///
    /// If the verifier is a Notary, this function will transition the verifier
    /// to the next state where it can sign the prover's commitments to the
    /// transcript.
    pub fn start_notarize(self) -> Verifier<Notarize> {
        Verifier {
            config: self.config,
            span: self.span,
            state: self.state.into(),
        }
    }

    /// Starts verification of the TLS session.
    ///
    /// This function transitions the verifier into a state where it can verify
    /// content of the transcript.
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
    protocol_config: ProtocolConfig,
    mux: &MuxControl,
    exec: &mut Executor,
    encoder_seed: [u8; 32],
) -> Result<(MpcTlsFollower, DEAPThread, OTSender), VerifierError> {
    debug!("starting MPC backend setup");

    let mut ot_sender = kos::Sender::new(
        config.build_ot_sender_config(),
        chou_orlandi::Receiver::new(config.build_base_ot_receiver_config()),
    );
    ot_sender.alloc(protocol_config.ot_sender_setup_count(Role::Verifier));

    let mut ot_receiver = kos::Receiver::new(
        config.build_ot_receiver_config(),
        chou_orlandi::Sender::new(config.build_base_ot_sender_config()),
    );
    ot_receiver.alloc(protocol_config.ot_receiver_setup_count(Role::Verifier));

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
        DEAPRole::Follower,
        encoder_seed,
        ctx_vm,
        ot_sender.clone(),
        ot_receiver.clone(),
    );

    let mpc_tls_config = config.build_mpc_tls_config(&protocol_config);
    let (ke, prf, encrypter, decrypter) = build_components(
        TlsRole::Follower,
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
    let mut mpc_tls = MpcTlsFollower::new(
        mpc_tls_config,
        Box::new(StreamExt::compat_stream(channel)),
        ke,
        prf,
        encrypter,
        decrypter,
    );

    mpc_tls.setup().await?;

    debug!("MPC backend setup complete");

    Ok((mpc_tls, vm, ot_sender))
}
