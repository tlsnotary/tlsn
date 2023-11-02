//! TLS Verifier

pub(crate) mod config;
mod error;
mod future;
mod notarize;
pub mod state;
mod verify;

pub use config::{VerifierConfig, VerifierConfigBuilder, VerifierConfigBuilderError};
pub use error::VerifierError;

use crate::{tls::future::OTFuture, Mux};
use future::MuxFuture;
use futures::{
    stream::{SplitSink, SplitStream},
    AsyncRead, AsyncWrite, FutureExt, StreamExt, TryFutureExt,
};
use mpz_garble::{config::Role as GarbleRole, protocol::deap::DEAPVm};
use mpz_ot::{
    actor::kos::{
        msgs::Message as ActorMessage, ReceiverActor, SenderActor, SharedReceiver, SharedSender,
    },
    chou_orlandi, kos,
};
use mpz_share_conversion as ff;
use rand::Rng;
use signature::Signer;
use state::{Notarize, Verify};
use std::time::{SystemTime, UNIX_EPOCH};
use tls_mpc::{setup_components, MpcTlsFollower, TlsRole};
use tlsn_core::{proof::SessionInfo, RedactedTranscript, SessionHeader, Signature};
use uid_mux::{yamux, UidYamux};
use utils_aio::{codec::BincodeMux, duplex::Duplex, mux::MuxChannel};

#[cfg(feature = "tracing")]
use tracing::{debug, info, instrument};

type OTSenderActor = SenderActor<
    chou_orlandi::Receiver,
    SplitSink<
        Box<dyn Duplex<ActorMessage<chou_orlandi::msgs::Message>>>,
        ActorMessage<chou_orlandi::msgs::Message>,
    >,
    SplitStream<Box<dyn Duplex<ActorMessage<chou_orlandi::msgs::Message>>>>,
>;

/// A Verifier instance.
pub struct Verifier<T: state::VerifierState> {
    config: VerifierConfig,
    state: T,
}

impl Verifier<state::Initialized> {
    /// Create a new verifier.
    pub fn new(config: VerifierConfig) -> Self {
        Self {
            config,
            state: state::Initialized,
        }
    }

    /// Set up the verifier.
    ///
    /// This performs all MPC setup.
    ///
    /// # Arguments
    ///
    /// * `socket` - The socket to the prover.
    pub async fn setup<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
        self,
        socket: S,
    ) -> Result<Verifier<state::Setup>, VerifierError> {
        let mut mux = UidYamux::new(yamux::Config::default(), socket, yamux::Mode::Server);
        let mux_control = BincodeMux::new(mux.control());

        let mut mux_fut = MuxFuture {
            fut: Box::pin(async move { mux.run().await.map_err(VerifierError::from) }.fuse()),
        };

        let encoder_seed: [u8; 32] = rand::rngs::OsRng.gen();
        let mpc_setup_fut = setup_mpc_backend(&self.config, mux_control.clone(), encoder_seed);
        let (mpc_tls, vm, ot_send, ot_recv, gf2, ot_fut) = futures::select! {
            res = mpc_setup_fut.fuse() => res?,
            _ = &mut mux_fut => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?,
        };

        Ok(Verifier {
            config: self.config,
            state: state::Setup {
                mux: mux_control,
                mux_fut,
                mpc_tls,
                vm,
                ot_send,
                ot_recv,
                ot_fut,
                gf2,
                encoder_seed,
            },
        })
    }

    /// Runs the TLS verifier to completion, notarizing the TLS session.
    ///
    /// This is a convenience method which runs all the steps needed for notarization.
    pub async fn notarize<S: AsyncWrite + AsyncRead + Send + Unpin + 'static, T>(
        self,
        socket: S,
        signer: &impl Signer<T>,
    ) -> Result<SessionHeader, VerifierError>
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
    pub async fn verify<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
        self,
        socket: S,
    ) -> Result<(RedactedTranscript, RedactedTranscript, SessionInfo), VerifierError> {
        let mut verifier = self.setup(socket).await?.run().await?.start_verify();
        let (redacted_sent, redacted_received) = verifier.receive().await?;

        let session_info = verifier.finalize().await?;
        Ok((redacted_sent, redacted_received, session_info))
    }
}

impl Verifier<state::Setup> {
    /// Runs the verifier until the TLS connection is closed.
    pub async fn run(self) -> Result<Verifier<state::Closed>, VerifierError> {
        let state::Setup {
            mux,
            mut mux_fut,
            mut mpc_tls,
            vm,
            ot_send,
            ot_recv,
            mut ot_fut,
            gf2,
            encoder_seed,
        } = self.state;

        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        futures::select! {
            res = mpc_tls.run().fuse() => res?,
            _ = &mut mux_fut => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?,
            res = ot_fut => return Err(res.map(|_| ()).expect_err("future will not return Ok here"))
        };

        #[cfg(feature = "tracing")]
        info!("Finished TLS session");

        let server_ephemeral_key = mpc_tls.server_key().expect("server key is set");
        // TODO: We should be able to skip this commitment and verify the handshake directly.
        let handshake_commitment = mpc_tls
            .handshake_commitment()
            .expect("handshake commitment is set");
        let (sent_len, recv_len) = mpc_tls.bytes_transferred();

        Ok(Verifier {
            config: self.config,
            state: state::Closed {
                mux,
                mux_fut,
                vm,
                ot_send,
                ot_recv,
                ot_fut,
                gf2,
                encoder_seed,
                start_time,
                server_ephemeral_key,
                handshake_commitment,
                sent_len,
                recv_len,
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
            state: self.state.into(),
        }
    }
}

/// Performs a setup of the various MPC subprotocols.
#[cfg_attr(feature = "tracing", instrument(level = "debug", skip_all, err))]
#[allow(clippy::type_complexity)]
async fn setup_mpc_backend(
    config: &VerifierConfig,
    mut mux: Mux,
    encoder_seed: [u8; 32],
) -> Result<
    (
        MpcTlsFollower,
        DEAPVm<SharedSender, SharedReceiver>,
        SharedSender,
        SharedReceiver,
        ff::ConverterReceiver<ff::Gf2_128, SharedReceiver>,
        OTFuture,
    ),
    VerifierError,
> {
    let (ot_send_sink, ot_send_stream) = mux.get_channel("ot/1").await?.split();
    let (ot_recv_sink, ot_recv_stream) = mux.get_channel("ot/0").await?.split();

    let mut ot_sender_actor = OTSenderActor::new(
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
            .map_err(VerifierError::from),
        ot_receiver_actor
            .setup(config.ot_count())
            .map_err(VerifierError::from)
    )?;

    #[cfg(feature = "tracing")]
    debug!("OT setup complete");

    let ot_fut = OTFuture {
        fut: Box::pin(
            async move {
                futures::try_join!(
                    ot_sender_actor.run().map_err(VerifierError::from),
                    ot_receiver_actor.run().map_err(VerifierError::from)
                )?;

                Ok(ot_sender_actor)
            }
            .fuse(),
        ),
    };

    let mut vm = DEAPVm::new(
        "vm",
        GarbleRole::Follower,
        encoder_seed,
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
    let gf2 = ff::ConverterReceiver::<ff::Gf2_128, _>::new(gf2_config, ot_recv.clone(), channel);

    let mpc_tls_config = config.build_mpc_tls_config();

    let (ke, prf, encrypter, decrypter) = setup_components(
        mpc_tls_config.common(),
        TlsRole::Follower,
        &mut mux,
        &mut vm,
        p256_send,
        p256_recv,
        gf2.handle()
            .map_err(|e| VerifierError::MpcError(Box::new(e)))?,
    )
    .await
    .map_err(|e| VerifierError::MpcError(Box::new(e)))?;

    let channel = mux.get_channel(mpc_tls_config.common().id()).await?;
    let mut mpc_tls = MpcTlsFollower::new(mpc_tls_config, channel, ke, prf, encrypter, decrypter);

    mpc_tls.setup().await?;

    #[cfg(feature = "tracing")]
    debug!("MPC backend setup complete");

    Ok((mpc_tls, vm, ot_send, ot_recv, gf2, ot_fut))
}
