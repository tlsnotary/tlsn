//! The notary library
//!
//! This library provides the [Notary] type for notarizing TLS sessions

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

pub(crate) mod config;
mod error;

use std::{
    pin::Pin,
    time::{SystemTime, UNIX_EPOCH},
};

use futures::{AsyncRead, AsyncWrite, Future, FutureExt, SinkExt, StreamExt};

use actor_ot::{
    create_ot_receiver, create_ot_sender, OTActorReceiverConfig, OTActorSenderConfig,
    ObliviousReveal,
};
use mpz_core::serialize::CanonicalSerialize;
use mpz_garble::{config::Role as GarbleRole, protocol::deap::DEAPVm};
use mpz_share_conversion as ff;
use rand::Rng;
use signature::Signer;
use tls_mpc::{
    setup_components, MpcTlsCommonConfig, MpcTlsFollower, MpcTlsFollowerConfig, TlsRole,
};
use tlsn_core::{
    msg::{SignedSessionHeader, TlsnMessage},
    signature::Signature,
    HandshakeSummary, SessionHeader,
};
use uid_mux::{yamux, UidYamux, UidYamuxControl};
use utils_aio::{codec::BincodeMux, expect_msg_or_err, mux::MuxChannelSerde};

pub use config::{NotaryConfig, NotaryConfigBuilder, NotaryConfigBuilderError};
pub use error::NotaryError;

#[cfg(feature = "tracing")]
use tracing::{info, instrument};

/// A future that performs background processing for the notary.
///
/// This is a future intended to run in the background. It must be polled in order to make progress.
///
/// Typically it will be spawned on an executor.
pub struct NotaryBackgroundFut {
    fut: Pin<Box<dyn Future<Output = Result<(), NotaryError>> + Send + 'static>>,
}

impl Future for NotaryBackgroundFut {
    type Output = Result<(), NotaryError>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.fut.poll_unpin(cx)
    }
}

/// Helper function to bind a new notary to the given socket.
///
/// # Arguments
///
/// * `config` - The configuration for the notary.
/// * `socket` - The socket to the prover.
#[cfg_attr(feature = "tracing", instrument(level = "debug", skip(socket), err))]
pub fn bind_notary<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    config: NotaryConfig,
    socket: T,
) -> Result<(Notary<BincodeMux<UidYamuxControl>>, NotaryBackgroundFut), NotaryError> {
    let mut mux = UidYamux::new(yamux::Config::default(), socket, yamux::Mode::Server);
    let mux_control = BincodeMux::new(mux.control());

    let fut = NotaryBackgroundFut {
        fut: Box::pin(async move { mux.run().await.map_err(NotaryError::from) }),
    };

    let notary = Notary::new(config, mux_control);

    Ok((notary, fut))
}

/// A Notary instance.
pub struct Notary<M> {
    config: NotaryConfig,
    mux: M,
}

impl<M> Notary<M>
where
    M: MuxChannelSerde + Clone + Send + 'static,
{
    /// Create a new `Notary`.
    pub fn new(config: NotaryConfig, mux: M) -> Self {
        Self { config, mux }
    }

    /// Runs the notary instance.
    pub async fn notarize<T>(self, signer: &impl Signer<T>) -> Result<SessionHeader, NotaryError>
    where
        T: Into<Signature>,
    {
        let Notary { config, mut mux } = self;

        // TODO: calculate number of OTs more accurately
        let ot_send_config = OTActorSenderConfig::builder()
            .id("ot/1")
            .initial_count(config.max_transcript_size() * 8)
            .committed()
            .build()
            .unwrap();
        let ot_recv_config = OTActorReceiverConfig::builder()
            .id("ot/0")
            .initial_count(config.max_transcript_size() * 8)
            .build()
            .unwrap();

        let ((mut ot_send, ot_send_fut), (mut ot_recv, ot_recv_fut)) = futures::try_join!(
            create_ot_sender(mux.clone(), ot_send_config),
            create_ot_receiver(mux.clone(), ot_recv_config)
        )
        .unwrap();

        #[cfg(feature = "tracing")]
        info!("Created OT senders and receivers");

        let notarize_fut = async {
            let encoder_seed: [u8; 32] = rand::rngs::OsRng.gen();

            futures::try_join!(ot_send.setup(), ot_recv.setup())
                .map_err(|e| NotaryError::MpcError(Box::new(e)))?;

            let mut vm = DEAPVm::new(
                "vm",
                GarbleRole::Follower,
                encoder_seed,
                mux.get_channel("vm").await?,
                Box::new(mux.clone()),
                ot_send.clone(),
                ot_recv.clone(),
            );

            #[cfg(feature = "tracing")]
            info!("Created DEAPVm");

            let p256_send = ff::ConverterSender::<ff::P256, _>::new(
                ff::SenderConfig::builder().id("p256/1").build().unwrap(),
                ot_send.clone(),
                mux.get_channel("p256/1").await?,
            );

            let p256_recv = ff::ConverterReceiver::<ff::P256, _>::new(
                ff::ReceiverConfig::builder().id("p256/0").build().unwrap(),
                ot_recv.clone(),
                mux.get_channel("p256/0").await?,
            );

            let mut gf2 = ff::ConverterReceiver::<ff::Gf2_128, _>::new(
                ff::ReceiverConfig::builder()
                    .id("gf2")
                    .record()
                    .build()
                    .unwrap(),
                ot_recv.clone(),
                mux.get_channel("gf2").await?,
            );

            #[cfg(feature = "tracing")]
            info!("Created point addition senders and receivers");

            let common_config = MpcTlsCommonConfig::builder()
                .id(format!("{}/mpc_tls", &config.id()))
                .handshake_commit(true)
                .build()
                .unwrap();
            let (ke, prf, encrypter, decrypter) = setup_components(
                &common_config,
                TlsRole::Follower,
                &mut mux,
                &mut vm,
                p256_send,
                p256_recv,
                gf2.handle()
                    .map_err(|e| NotaryError::MpcError(Box::new(e)))?,
            )
            .await
            .map_err(|e| NotaryError::MpcError(Box::new(e)))?;

            let channel = mux.get_channel(common_config.id()).await?;
            let mut mpc_tls = MpcTlsFollower::new(
                MpcTlsFollowerConfig::builder()
                    .common(common_config)
                    .build()
                    .unwrap(),
                channel,
                ke,
                prf,
                encrypter,
                decrypter,
            );

            #[cfg(feature = "tracing")]
            info!("Finished setting up notary components");

            let start_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            mpc_tls.run().await?;

            #[cfg(feature = "tracing")]
            info!("Finished TLS session");

            let mut notarize_channel = mux.get_channel("notarize").await?;

            let merkle_root =
                expect_msg_or_err!(notarize_channel, TlsnMessage::TranscriptCommitmentRoot)?;

            // Finalize all MPC before signing the session header
            ot_send
                .reveal()
                .await
                .map_err(|e| NotaryError::MpcError(Box::new(e)))?;

            vm.finalize()
                .await
                .map_err(|e| NotaryError::MpcError(Box::new(e)))?;

            gf2.verify()
                .await
                .map_err(|e| NotaryError::MpcError(Box::new(e)))?;

            #[cfg(feature = "tracing")]
            info!("Finalized all MPC");

            // Create, sign and send the session header
            let (sent_len, recv_len) = mpc_tls.bytes_transferred();

            let handshake_summary = HandshakeSummary::new(
                start_time,
                mpc_tls
                    .server_key()
                    .expect("server key is set after session"),
                mpc_tls
                    .handshake_commitment()
                    .expect("handshake commitment is set after session"),
            );

            let session_header = SessionHeader::new(
                encoder_seed,
                merkle_root,
                sent_len as u32,
                recv_len as u32,
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

            Ok::<_, NotaryError>(session_header)
        };

        let mut ot_send_fut = Box::pin(ot_send_fut.fuse());
        let mut ot_recv_fut = Box::pin(ot_recv_fut.fuse());
        let mut notarize_fut = Box::pin(notarize_fut.fuse());

        // Run the notarization protocol
        loop {
            futures::select! {
                _ = ot_send_fut => {},
                _ = ot_recv_fut => {},
                res = notarize_fut => return res
            }
        }
    }
}
