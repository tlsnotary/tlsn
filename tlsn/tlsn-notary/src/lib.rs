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

use futures::{AsyncRead, AsyncWrite, Future, FutureExt, SinkExt, StreamExt, TryFutureExt};

use mpz_core::serialize::CanonicalSerialize;
use mpz_garble::{config::Role as GarbleRole, protocol::deap::DEAPVm};
use mpz_ot::{
    actor::kos::{ReceiverActor, SenderActor},
    chou_orlandi, kos,
};
use mpz_share_conversion as ff;
use rand::Rng;
use signature::Signer;
use tls_mpc::{setup_components, MpcTlsFollower, TlsRole};
use tlsn_core::{
    msg::{SignedSessionHeader, TlsnMessage},
    HandshakeSummary, SessionHeader, Signature,
};
use uid_mux::{yamux, UidYamux, UidYamuxControl};
use utils_aio::{codec::BincodeMux, expect_msg_or_err, mux::MuxChannel};

pub use config::{NotaryConfig, NotaryConfigBuilder, NotaryConfigBuilderError};
pub use error::NotaryError;

#[cfg(feature = "tracing")]
use tracing::{debug, info, instrument};

/// Bincode for serialization, multiplexing with Yamux.
type Mux = BincodeMux<UidYamuxControl>;

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
) -> Result<(Notary, NotaryBackgroundFut), NotaryError> {
    let mut mux = UidYamux::new(yamux::Config::default(), socket, yamux::Mode::Server);
    let mux_control = BincodeMux::new(mux.control());

    let fut = NotaryBackgroundFut {
        fut: Box::pin(async move { mux.run().await.map_err(NotaryError::from) }),
    };

    let notary = Notary::new(config, mux_control);

    Ok((notary, fut))
}

/// A Notary instance.
pub struct Notary {
    config: NotaryConfig,
    mux: Mux,
}

impl Notary {
    /// Create a new `Notary`.
    pub fn new(config: NotaryConfig, mux: Mux) -> Self {
        Self { config, mux }
    }

    /// Runs the notary instance.
    pub async fn notarize<T>(self, signer: &impl Signer<T>) -> Result<SessionHeader, NotaryError>
    where
        T: Into<Signature>,
    {
        let Notary { config, mut mux } = self;

        // TODO: calculate number of OTs more accurately
        let (ot_send_sink, ot_send_stream) = mux.get_channel("ot/1").await?.split();
        let (ot_recv_sink, ot_recv_stream) = mux.get_channel("ot/0").await?.split();

        let mut ot_sender_actor = SenderActor::new(
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

        let encoder_seed: [u8; 32] = rand::rngs::OsRng.gen();

        #[cfg(feature = "tracing")]
        debug!("Starting OT setup");

        futures::try_join!(
            ot_sender_actor
                .setup(config.ot_count())
                .map_err(NotaryError::from),
            ot_receiver_actor
                .setup(config.ot_count())
                .map_err(NotaryError::from)
        )?;

        #[cfg(feature = "tracing")]
        debug!("OT setup complete");

        let mut ot_fut = Box::pin(
            async move {
                futures::try_join!(
                    ot_sender_actor.run().map_err(NotaryError::from),
                    ot_receiver_actor.run().map_err(NotaryError::from)
                )?;

                Ok::<_, NotaryError>(ot_sender_actor)
            }
            .fuse(),
        );

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

        let mpc_config = config.build_tls_mpc_config();
        let (ke, prf, encrypter, decrypter) = setup_components(
            mpc_config.common(),
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

        let channel = mux.get_channel(mpc_config.common().id()).await?;
        let mut mpc_tls = MpcTlsFollower::new(mpc_config, channel, ke, prf, encrypter, decrypter);

        #[cfg(feature = "tracing")]
        info!("Finished setting up notary components");

        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        futures::select! {
            res = mpc_tls.run().fuse() => res?,
            res = ot_fut => return Err(res.err().expect("future will not return Ok here"))
        };

        #[cfg(feature = "tracing")]
        info!("Finished TLS session");

        let mut notarize_channel = mux.get_channel("notarize").await?;

        let merkle_root =
            expect_msg_or_err!(notarize_channel, TlsnMessage::TranscriptCommitmentRoot)?;

        // Finalize all MPC before signing the session header
        let (mut ot_sender_actor, _, _) = futures::try_join!(
            ot_fut,
            ot_send.shutdown().map_err(NotaryError::from),
            ot_recv.shutdown().map_err(NotaryError::from)
        )?;

        ot_sender_actor.reveal().await?;

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

        Ok(session_header)
    }
}
