//! The prover library
//!
//! This library provides the [Prover] type. It can be used for creating TLS connections with a
//! server which can be notarized with the help of a notary.

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

mod config;
mod error;
mod state;

pub use config::ProverConfig;
pub use error::ProverError;
use state::Setup;
pub use state::{Initialized, Notarize, ProverState};

use futures::{
    future::FusedFuture, AsyncRead, AsyncWrite, Future, FutureExt, SinkExt, StreamExt, TryFutureExt,
};
use rand::Rng;
use std::{ops::Range, pin::Pin, sync::Arc};
use tls_client_async::{bind_client, ClosedConnection, TlsConnection};
use tls_mpc::{setup_components, MpcTlsLeader, TlsRole};

use mpz_core::commit::HashCommit;
use mpz_garble::{
    config::Role as GarbleRole,
    protocol::deap::{DEAPVm, PeerEncodings},
};
use mpz_ot::{
    actor::kos::{ReceiverActor, SenderActor, SharedReceiver, SharedSender},
    chou_orlandi, kos,
};
use mpz_share_conversion as ff;
use tls_client::{ClientConnection, ServerName};
use tlsn_core::{
    commitment::Blake3,
    merkle::MerkleTree,
    msg::{SignedSessionHeader, TlsnMessage},
    transcript::Transcript,
    Direction, NotarizedSession, SessionData, SubstringsCommitment, SubstringsCommitmentSet,
};
use uid_mux::{yamux, UidYamux, UidYamuxControl};
use utils_aio::{codec::BincodeMux, expect_msg_or_err, mux::MuxChannel};

use crate::error::OTShutdownError;

#[cfg(feature = "tracing")]
use tracing::{debug, debug_span, instrument, Instrument};

/// Bincode for serialization, multiplexing with Yamux.
type Mux = BincodeMux<UidYamuxControl>;

/// Prover future which must be polled for the connection to make progress.
pub struct ProverFuture {
    #[allow(clippy::type_complexity)]
    fut: Pin<Box<dyn Future<Output = Result<Prover<Notarize>, ProverError>> + Send + 'static>>,
}

impl Future for ProverFuture {
    type Output = Result<Prover<Notarize>, ProverError>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.fut.as_mut().poll(cx)
    }
}

/// A prover instance.
#[derive(Debug)]
pub struct Prover<T: ProverState> {
    config: ProverConfig,
    state: T,
}

impl Prover<Initialized> {
    /// Creates a new prover.
    ///
    /// # Arguments
    ///
    /// * `config` - The configuration for the prover.
    pub fn new(config: ProverConfig) -> Self {
        Self {
            config,
            state: Initialized,
        }
    }

    /// Set up the prover.
    ///
    /// This performs all MPC setup prior to establishing the connection to the
    /// application server.
    ///
    /// # Arguments
    ///
    /// * `socket` - The socket to the notary.
    pub async fn setup<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
        self,
        socket: S,
    ) -> Result<Prover<Setup>, ProverError> {
        let mut mux = UidYamux::new(yamux::Config::default(), socket, yamux::Mode::Client);
        let notary_mux = BincodeMux::new(mux.control());

        let mut mux_fut = MuxFuture {
            fut: Box::pin(async move { mux.run().await.map_err(ProverError::from) }.fuse()),
        };

        let mpc_setup_fut = setup_mpc_backend(&self.config, notary_mux.clone());
        let (mpc_tls, vm, _, gf2, ot_fut) = futures::select! {
            res = mpc_setup_fut.fuse() => res?,
            _ = (&mut mux_fut).fuse() => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?,
        };

        Ok(Prover {
            config: self.config,
            state: Setup {
                notary_mux,
                mux_fut,
                mpc_tls,
                vm,
                ot_fut,
                gf2,
            },
        })
    }
}

impl Prover<Setup> {
    /// Connects to the server using the provided socket.
    ///
    /// Returns a handle to the TLS connection, a future which returns the prover once the connection is
    /// closed.
    ///
    /// # Arguments
    ///
    /// * `socket` - The socket to the server.
    #[cfg_attr(
        feature = "tracing",
        instrument(level = "debug", skip(self, socket), err)
    )]
    pub async fn connect<S: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
        self,
        socket: S,
    ) -> Result<(TlsConnection, ProverFuture), ProverError> {
        let Setup {
            notary_mux,
            mut mux_fut,
            mpc_tls,
            vm,
            mut ot_fut,
            gf2,
        } = self.state;

        let server_name = ServerName::try_from(self.config.server_dns())?;
        let config = tls_client::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(self.config.root_cert_store.clone())
            .with_no_client_auth();
        let client = ClientConnection::new(Arc::new(config), Box::new(mpc_tls), server_name)?;

        let (conn, conn_fut) = bind_client(socket, client);

        let start_time = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs();

        let fut = Box::pin({
            #[allow(clippy::let_and_return)]
            let fut = async move {
                let ClosedConnection {
                    mut client,
                    sent,
                    recv,
                } = futures::select! {
                    res = conn_fut.fuse() => res?,
                    _ = ot_fut => return Err(OTShutdownError)?,
                    _ = mux_fut => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?,
                };

                // Extra guard to guarantee that the server sent a close_notify.
                //
                // DO NOT REMOVE!
                //
                // This is necessary, as our protocol reveals the MAC key to the Notary afterwards
                // which could be used to authenticate modified TLS records if the Notary is
                // in the middle of the connection.
                if !client.received_close_notify() {
                    return Err(ProverError::ServerNoCloseNotify);
                }

                let backend = client
                    .backend_mut()
                    .as_any_mut()
                    .downcast_mut::<MpcTlsLeader>()
                    .unwrap();

                let handshake_decommitment = backend
                    .handshake_decommitment_mut()
                    .take()
                    .expect("handshake decommitment is set");
                let server_public_key = backend
                    .server_public_key()
                    .cloned()
                    .expect("server public key is set");

                Ok(Prover {
                    config: self.config,
                    state: Notarize {
                        notary_mux,
                        mux_fut,
                        vm,
                        ot_fut,
                        gf2,
                        start_time,
                        handshake_decommitment,
                        server_public_key,
                        transcript_tx: Transcript::new("tx", sent),
                        transcript_rx: Transcript::new("rx", recv),
                        commitments: Vec::default(),
                        substring_commitments: Vec::default(),
                    },
                })
            };
            #[cfg(feature = "tracing")]
            let fut = fut.instrument(debug_span!("prover_tls_connection"));
            fut
        });

        Ok((conn, ProverFuture { fut }))
    }
}

impl Prover<Notarize> {
    /// Returns the transcript of the sent requests
    pub fn sent_transcript(&self) -> &Transcript {
        &self.state.transcript_tx
    }

    /// Returns the transcript of the received responses
    pub fn recv_transcript(&self) -> &Transcript {
        &self.state.transcript_rx
    }

    /// Add a commitment to the sent requests
    pub fn add_commitment_sent(&mut self, range: Range<u32>) -> Result<(), ProverError> {
        self.add_commitment(range, Direction::Sent)
    }

    /// Add a commitment to the received responses
    pub fn add_commitment_recv(&mut self, range: Range<u32>) -> Result<(), ProverError> {
        self.add_commitment(range, Direction::Received)
    }

    #[cfg_attr(
        feature = "tracing",
        instrument(level = "debug", skip(self, range), err)
    )]
    fn add_commitment(
        &mut self,
        range: Range<u32>,
        direction: Direction,
    ) -> Result<(), ProverError> {
        let ids = match direction {
            Direction::Sent => self.state.transcript_tx.get_ids(&range),
            Direction::Received => self.state.transcript_rx.get_ids(&range),
        };

        let id_refs: Vec<_> = ids.iter().map(|id| id.as_str()).collect();

        let encodings = self
            .state
            .vm
            .get_peer_encodings(&id_refs)
            .map_err(|e| ProverError::MpcError(Box::new(e)))?;

        let (decommitment, commitment) = encodings.hash_commit();

        self.state.commitments.push(commitment);

        let commitment = Blake3::new(commitment).into();

        let commitment = SubstringsCommitment::new(
            self.state.substring_commitments.len() as u32,
            commitment,
            vec![range],
            direction,
            *decommitment.nonce(),
        );

        self.state.substring_commitments.push(commitment);

        Ok(())
    }

    /// Finalize the notarization returning a [`NotarizedSession`]
    #[cfg_attr(feature = "tracing", instrument(level = "info", skip(self), err))]
    pub async fn finalize(self) -> Result<NotarizedSession, ProverError> {
        let Notarize {
            mut notary_mux,
            mut mux_fut,
            mut vm,
            mut ot_fut,
            mut gf2,
            start_time,
            handshake_decommitment,
            server_public_key,
            transcript_tx,
            transcript_rx,
            commitments,
            substring_commitments,
        } = self.state;

        let merkle_tree = MerkleTree::from_leaves(&commitments)?;
        let merkle_root = merkle_tree.root();

        let notarize_fut = async move {
            let mut channel = notary_mux.get_channel("notarize").await?;

            channel
                .send(TlsnMessage::TranscriptCommitmentRoot(merkle_root))
                .await?;

            let notary_encoder_seed = vm
                .finalize()
                .await
                .map_err(|e| ProverError::MpcError(Box::new(e)))?
                .expect("encoder seed returned");

            gf2.reveal()
                .await
                .map_err(|e| ProverError::MpcError(Box::new(e)))?;

            let signed_header = expect_msg_or_err!(channel, TlsnMessage::SignedSessionHeader)?;

            Ok::<_, ProverError>((notary_encoder_seed, signed_header))
        };

        let (notary_encoder_seed, SignedSessionHeader { header, signature }) = futures::select! {
            res = notarize_fut.fuse() => res?,
            _ = ot_fut => return Err(OTShutdownError)?,
            _ = mux_fut => return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?,
        };

        // Check the header is consistent with the Prover's view
        header.verify(
            start_time,
            &server_public_key,
            &merkle_tree.root(),
            &notary_encoder_seed,
            &handshake_decommitment,
        )?;

        let commitments = SubstringsCommitmentSet::new(substring_commitments);

        let data = SessionData::new(
            handshake_decommitment,
            transcript_tx,
            transcript_rx,
            merkle_tree,
            commitments,
        );

        Ok(NotarizedSession::new(header, Some(signature), data))
    }
}

#[cfg_attr(feature = "tracing", instrument(level = "debug", skip_all, err))]
#[allow(clippy::type_complexity)]
async fn setup_mpc_backend(
    config: &ProverConfig,
    mut mux: Mux,
) -> Result<
    (
        MpcTlsLeader,
        DEAPVm<SharedSender, SharedReceiver>,
        SharedReceiver,
        ff::ConverterSender<ff::Gf2_128, SharedSender>,
        OTFuture,
    ),
    ProverError,
> {
    let (ot_send_sink, ot_send_stream) = mux.get_channel("ot/0").await?.split();
    let (ot_recv_sink, ot_recv_stream) = mux.get_channel("ot/1").await?.split();

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

    #[cfg(feature = "tracing")]
    debug!("Starting OT setup");

    futures::try_join!(
        ot_sender_actor
            .setup(config.ot_count())
            .map_err(ProverError::from),
        ot_receiver_actor
            .setup(config.ot_count())
            .map_err(ProverError::from)
    )?;

    #[cfg(feature = "tracing")]
    debug!("OT setup complete");

    let ot_fut = OTFuture {
        fut: Box::pin(
            async move {
                futures::try_join!(
                    ot_sender_actor.run().map_err(ProverError::from),
                    ot_receiver_actor.run().map_err(ProverError::from)
                )?;

                Ok(())
            }
            .fuse(),
        ),
    };

    let mut vm = DEAPVm::new(
        "vm",
        GarbleRole::Leader,
        rand::rngs::OsRng.gen(),
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
    let gf2 = ff::ConverterSender::<ff::Gf2_128, _>::new(gf2_config, ot_send.clone(), channel);

    let mpc_tls_config = config.build_mpc_tls_config();

    let (ke, prf, encrypter, decrypter) = setup_components(
        mpc_tls_config.common(),
        TlsRole::Leader,
        &mut mux,
        &mut vm,
        p256_send,
        p256_recv,
        gf2.handle()
            .map_err(|e| ProverError::MpcError(Box::new(e)))?,
    )
    .await
    .map_err(|e| ProverError::MpcError(Box::new(e)))?;

    let channel = mux.get_channel(mpc_tls_config.common().id()).await?;
    let mut mpc_tls = MpcTlsLeader::new(mpc_tls_config, channel, ke, prf, encrypter, decrypter);

    mpc_tls.setup().await?;

    #[cfg(feature = "tracing")]
    debug!("MPC backend setup complete");

    Ok((mpc_tls, vm, ot_recv, gf2, ot_fut))
}

struct MuxFuture {
    fut: Pin<Box<dyn FusedFuture<Output = Result<(), ProverError>> + Send + 'static>>,
}

impl Future for MuxFuture {
    type Output = Result<(), ProverError>;

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

struct OTFuture {
    fut: Pin<Box<dyn FusedFuture<Output = Result<(), ProverError>> + Send + 'static>>,
}

impl Future for OTFuture {
    type Output = Result<(), ProverError>;

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
