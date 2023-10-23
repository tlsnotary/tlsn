//! TLS Verifier

pub(crate) mod config;
mod error;
pub mod state;

pub use config::{VerifierConfig, VerifierConfigBuilder, VerifierConfigBuilderError};
pub use error::VerifierError;

use std::{
    pin::Pin,
    time::{SystemTime, UNIX_EPOCH},
};

use futures::{
    future::FusedFuture,
    stream::{SplitSink, SplitStream},
    AsyncRead, AsyncWrite, Future, FutureExt, SinkExt, StreamExt, TryFutureExt,
};

use mpz_core::serialize::CanonicalSerialize;
use mpz_garble::{config::Role as GarbleRole, protocol::deap::DEAPVm};
use mpz_ot::{
    actor::kos::{
        msgs::Message as ActorMessage, ReceiverActor, SenderActor, SharedReceiver, SharedSender,
    },
    chou_orlandi, kos,
};
use mpz_share_conversion as ff;
use mpz_share_conversion::ShareConversionVerify;
use rand::Rng;
use signature::Signer;
use tls_mpc::{setup_components, MpcTlsFollower, TlsRole};
use tlsn_core::{
    msg::{SignedSessionHeader, TlsnMessage},
    HandshakeSummary, SessionHeader, Signature,
};
use uid_mux::{yamux, UidYamux};
use utils_aio::{codec::BincodeMux, duplex::Duplex, expect_msg_or_err, mux::MuxChannel};

use crate::Mux;

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
            .notarize(signer)
            .await
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
    /// Notarizes the TLS session.
    pub async fn notarize<T>(self, signer: &impl Signer<T>) -> Result<SessionHeader, VerifierError>
    where
        T: Into<Signature>,
    {
        let state::Closed {
            mut mux,
            mut mux_fut,
            mut vm,
            ot_send,
            ot_recv,
            ot_fut,
            mut gf2,
            encoder_seed,
            start_time,
            server_ephemeral_key,
            handshake_commitment,
            sent_len,
            recv_len,
        } = self.state;

        let notarize_fut = async {
            let mut notarize_channel = mux.get_channel("notarize").await?;

            let merkle_root =
                expect_msg_or_err!(notarize_channel, TlsnMessage::TranscriptCommitmentRoot)?;

            // Finalize all MPC before signing the session header
            let (mut ot_sender_actor, _, _) = futures::try_join!(
                ot_fut,
                ot_send.shutdown().map_err(VerifierError::from),
                ot_recv.shutdown().map_err(VerifierError::from)
            )?;

            ot_sender_actor.reveal().await?;

            vm.finalize()
                .await
                .map_err(|e| VerifierError::MpcError(Box::new(e)))?;

            gf2.verify()
                .await
                .map_err(|e| VerifierError::MpcError(Box::new(e)))?;

            #[cfg(feature = "tracing")]
            info!("Finalized all MPC");

            let handshake_summary =
                HandshakeSummary::new(start_time, server_ephemeral_key, handshake_commitment);

            let session_header = SessionHeader::new(
                encoder_seed,
                merkle_root,
                sent_len,
                recv_len,
                handshake_summary,
            );

            let signature = signer.sign(&session_header.to_bytes());

            #[cfg(feature = "tracing")]
            info!("Signed session header");

            notarize_channel
                .send(TlsnMessage::SignedSessionHeader(SignedSessionHeader {
                    header: session_header.clone(),
                    signature: signature.into(),
                }))
                .await?;

            #[cfg(feature = "tracing")]
            info!("Sent session header");

            Ok::<_, VerifierError>(session_header)
        };

        let session_header = futures::select! {
            res = notarize_fut.fuse() => res?,
            _ = &mut mux_fut => Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?,
        };

        let mut mux = mux.into_inner();

        futures::try_join!(mux.close().map_err(VerifierError::from), mux_fut)?;

        Ok(session_header)
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

/// A future which must be polled for the muxer to make progress.
pub(crate) struct MuxFuture {
    fut: Pin<Box<dyn FusedFuture<Output = Result<(), VerifierError>> + Send + 'static>>,
}

impl Future for MuxFuture {
    type Output = Result<(), VerifierError>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.fut.as_mut().poll(cx)
    }
}

impl FusedFuture for MuxFuture {
    fn is_terminated(&self) -> bool {
        self.fut.is_terminated()
    }
}

/// A future which must be polled for the Oblivious Transfer protocol to make progress.
pub(crate) struct OTFuture {
    fut: Pin<Box<dyn FusedFuture<Output = Result<OTSenderActor, VerifierError>> + Send + 'static>>,
}

impl Future for OTFuture {
    type Output = Result<OTSenderActor, VerifierError>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.fut.as_mut().poll(cx)
    }
}

impl FusedFuture for OTFuture {
    fn is_terminated(&self) -> bool {
        self.fut.is_terminated()
    }
}
