//! TLSNotary verifier library.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

pub(crate) mod config;
mod error;
mod notarize;
pub mod state;
mod verify;

use std::sync::Arc;

pub use config::{VerifierConfig, VerifierConfigBuilder, VerifierConfigBuilderError};
pub use error::VerifierError;

use futures::{AsyncRead, AsyncWrite};
use mpc_tls::{FollowerData, MpcTlsFollower};
use mpz_common::Context;
use mpz_garble_core::Delta;
use rand::{thread_rng, Rng};
use serio::stream::IoStreamExt;
use state::{Notarize, Verify};
use tls_core::msgs::enums::ContentType;
use tlsn_common::{
    commit::commit_records, config::ProtocolConfig, context::build_mt_context, mux::attach_mux,
    zk_aes::ZkAesCtr, Role,
};
use tlsn_core::{
    attestation::{Attestation, AttestationConfig},
    connection::{ConnectionInfo, ServerName, TlsVersion, TranscriptLength},
    transcript::PartialTranscript,
};
use tlsn_deap::Deap;
use tokio::sync::Mutex;
use web_time::{SystemTime, UNIX_EPOCH};

use tracing::{debug, info, info_span, instrument, Span};

pub(crate) type RCOTSender = mpz_ot::rcot::shared::SharedRCOTSender<
    mpz_ot::ferret::Sender<mpz_ot::kos::Sender<mpz_ot::chou_orlandi::Receiver>>,
    mpz_core::Block,
>;
pub(crate) type RCOTReceiver = mpz_ot::rcot::shared::SharedRCOTReceiver<
    mpz_ot::kos::Receiver<mpz_ot::chou_orlandi::Sender>,
    bool,
    mpz_core::Block,
>;
pub(crate) type Mpc =
    mpz_garble::protocol::semihonest::Evaluator<mpz_ot::cot::DerandCOTReceiver<RCOTReceiver>>;
pub(crate) type Zk = mpz_zk::Verifier<RCOTSender>;

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
        let mut mt = build_mt_context(mux_ctrl.clone());
        let mut ctx = mux_fut.poll_with(mt.new_context()).await?;

        // Receives protocol configuration from prover to perform compatibility check.
        let protocol_config = mux_fut
            .poll_with(async {
                let peer_configuration: ProtocolConfig = ctx.io_mut().expect_next().await?;
                self.config
                    .protocol_config_validator()
                    .validate(&peer_configuration)?;

                Ok::<_, VerifierError>(peer_configuration)
            })
            .await?;

        let delta = Delta::random(&mut thread_rng());
        let (vm, mut mpc_tls) = build_mpc_tls(&self.config, &protocol_config, delta, ctx);

        // Allocate resources for MPC-TLS in VM.
        let keys = mpc_tls.alloc()?;
        // Allocate for committing to plaintext.
        let mut zk_aes = ZkAesCtr::new(Role::Verifier);
        zk_aes.set_key(keys.server_write_key, keys.server_write_iv);
        zk_aes.alloc(
            &mut (*vm.try_lock().expect("VM is not locked").zk()),
            protocol_config.max_recv_data(),
        )?;

        debug!("setting up mpc-tls");

        mux_fut.poll_with(mpc_tls.preprocess()).await?;

        debug!("mpc-tls setup complete");

        Ok(Verifier {
            config: self.config,
            span: self.span,
            state: state::Setup {
                mux_ctrl,
                mux_fut,
                mt,
                delta,
                mpc_tls,
                zk_aes,
                _keys: keys,
                vm,
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
    /// * `config` - The attestation configuration.
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
            mux_ctrl,
            mut mux_fut,
            mt,
            delta,
            mpc_tls,
            mut zk_aes,
            vm,
            ..
        } = self.state;

        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be available")
            .as_secs();

        info!("starting MPC-TLS");

        let (
            mut ctx,
            FollowerData {
                server_key,
                mut transcript,
                keys,
            },
        ) = mux_fut.poll_with(mpc_tls.run()).await?;

        info!("finished MPC-TLS");

        {
            let mut vm = vm.try_lock().expect("VM should not be locked");

            // Prove received plaintext. Prover drops the proof output, as they trust
            // themselves.
            let proof = commit_records(
                &mut (*vm.zk()),
                &mut zk_aes,
                transcript
                    .recv
                    .iter_mut()
                    .filter(|record| record.typ == ContentType::ApplicationData),
            )
            .map_err(VerifierError::zk)?;

            debug!("finalizing mpc");

            // Finalize DEAP and execute the plaintext proofs.
            mux_fut
                .poll_with(vm.finalize(&mut ctx))
                .await
                .map_err(VerifierError::mpc)?;

            debug!("mpc finalized");

            // Verify the plaintext proofs.
            proof.verify().map_err(VerifierError::zk)?;
        }

        let sent = transcript
            .sent
            .iter()
            .filter(|record| record.typ == ContentType::ApplicationData)
            .map(|record| record.ciphertext.len())
            .sum::<usize>() as u32;
        let received = transcript
            .recv
            .iter()
            .filter(|record| record.typ == ContentType::ApplicationData)
            .map(|record| record.ciphertext.len())
            .sum::<usize>() as u32;

        let transcript_refs = transcript
            .to_transcript_refs()
            .expect("transcript should be complete");

        let connection_info = ConnectionInfo {
            time: start_time,
            version: TlsVersion::V1_2,
            transcript_length: TranscriptLength { sent, received },
        };

        // Pull out ZK VM
        let (_, vm) = Arc::into_inner(vm)
            .expect("vm should have only 1 reference")
            .into_inner()
            .into_inner();

        Ok(Verifier {
            config: self.config,
            span: self.span,
            state: state::Closed {
                mux_ctrl,
                mux_fut,
                mt,
                delta,
                ctx,
                keys,
                vm,
                server_ephemeral_key: server_key
                    .try_into()
                    .expect("only supported key type should have been accepted"),
                connection_info,
                transcript_refs,
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
    /// the contents of the transcript.
    pub fn start_verify(self) -> Verifier<Verify> {
        Verifier {
            config: self.config,
            span: self.span,
            state: self.state.into(),
        }
    }
}

fn build_mpc_tls(
    config: &VerifierConfig,
    protocol_config: &ProtocolConfig,
    delta: Delta,
    ctx: Context,
) -> (Arc<Mutex<Deap<Mpc, Zk>>>, MpcTlsFollower) {
    let mut rng = thread_rng();

    let base_ot_send = mpz_ot::chou_orlandi::Sender::default();
    let base_ot_recv = mpz_ot::chou_orlandi::Receiver::default();
    let rcot_send = mpz_ot::kos::Sender::new(
        mpz_ot::kos::SenderConfig::default(),
        delta.into_inner(),
        base_ot_recv,
    );
    let rcot_send = mpz_ot::ferret::Sender::new(
        mpz_ot::ferret::FerretConfig::builder()
            .lpn_type(mpz_ot::ferret::LpnType::Regular)
            .build()
            .expect("ferret config is valid"),
        rng.gen(),
        rcot_send,
    );
    let rcot_recv =
        mpz_ot::kos::Receiver::new(mpz_ot::kos::ReceiverConfig::default(), base_ot_send);

    let mut rcot_send = mpz_ot::rcot::shared::SharedRCOTSender::new(2, rcot_send);
    let mut rcot_recv = mpz_ot::rcot::shared::SharedRCOTReceiver::new(4, rcot_recv);

    let mpc = Mpc::new(mpz_ot::cot::DerandCOTReceiver::new(
        rcot_recv.next().expect("receivers should be available"),
    ));

    let zk = Zk::new(
        delta,
        rcot_send.next().expect("senders should be available"),
    );

    let vm = Arc::new(Mutex::new(Deap::new(tlsn_deap::Role::Follower, mpc, zk)));

    (
        vm.clone(),
        MpcTlsFollower::new(
            config.build_mpc_tls_config(protocol_config),
            ctx,
            vm,
            rcot_send.next().expect("senders should be available"),
            (
                rcot_recv.next().expect("receivers should be available"),
                rcot_recv.next().expect("receivers should be available"),
                rcot_recv.next().expect("receivers should be available"),
            ),
        ),
    )
}
