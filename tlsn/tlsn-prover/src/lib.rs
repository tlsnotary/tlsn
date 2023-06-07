mod config;
mod conn;
mod error;
mod state;

pub use config::ProverConfig;
pub use conn::TlsConnection;
pub use error::ProverError;
pub use state::{Initialized, Notarizing, ProverState};

use bytes::Bytes;
use futures::{
    channel::{mpsc, oneshot},
    future::{join, try_join, FusedFuture},
    select_biased, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, Future, FutureExt, SinkExt,
    StreamExt,
};
use rand::Rng;
use std::{io::Read, ops::Range, pin::Pin, sync::Arc};
use tls_core::{handshake::HandshakeData, key::PublicKey};
use tlsn_tls_mpc::{setup_components, MpcTlsLeader, TlsRole};

use actor_ot::{create_ot_receiver, create_ot_sender, ReceiverActorControl, SenderActorControl};
use mpc_core::commit::{Decommitment, HashCommit};
use mpc_garble::{
    config::Role as GarbleRole,
    protocol::deap::{DEAPVm, PeerEncodings},
};
use mpc_share_conversion as ff;
use tls_client::{ClientConnection, ServerName};
use tlsn_core::{
    commitment::Blake3,
    merkle::MerkleTree,
    msg::{SignedSessionHeader, TlsnMessage},
    transcript::Transcript,
    Direction, NotarizedSession, SessionData, SubstringsCommitment, SubstringsCommitmentSet,
};
use uid_mux::{yamux, UidYamux, UidYamuxControl};
use utils_aio::{codec::BincodeMux, expect_msg_or_err, mux::MuxChannelSerde};

use crate::error::OTShutdownError;

const RX_TLS_BUF_SIZE: usize = 2 << 13; // 8 KiB
const RX_BUF_SIZE: usize = 2 << 13; // 8 KiB

/// A future that performs background processing for the prover.
///
/// This is a future intended to run in the background. It must be polled in order to make progress.
///
/// Typically it will be spawned on an executor.
pub struct ProverBackgroundFut {
    fut: Pin<Box<dyn Future<Output = Result<(), ProverError>> + Send + 'static>>,
}

impl Future for ProverBackgroundFut {
    type Output = Result<(), ProverError>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.fut.poll_unpin(cx)
    }
}

/// Helper function to attach a new prover to the given sockets.
///
/// # Arguments
///
/// * `config` - The configuration for the prover.
/// * `server_socket` - The socket to the server.
/// * `notary_socket` - The socket to the notary.
#[allow(clippy::type_complexity)]
pub fn attach_prover<
    S: AsyncWrite + AsyncRead + Send + Unpin + 'static,
    T: AsyncWrite + AsyncRead + Send + Unpin + 'static,
>(
    config: ProverConfig,
    server_socket: S,
    notary_socket: T,
) -> Result<
    (
        TlsConnection,
        Prover<Initialized<S, BincodeMux<UidYamuxControl>>>,
        ProverBackgroundFut,
    ),
    ProverError,
> {
    let mut mux = UidYamux::new(yamux::Config::default(), notary_socket, yamux::Mode::Client);
    let mux_control = BincodeMux::new(mux.control());

    let mux_fut = ProverBackgroundFut {
        fut: Box::pin(async move { mux.run().await.map_err(ProverError::from) }),
    };

    let (prover, tls_conn) = Prover::new(config, server_socket, mux_control)?;

    Ok((tls_conn, prover, mux_fut))
}

/// A prover instance.
#[derive(Debug)]
pub struct Prover<T: ProverState> {
    config: ProverConfig,
    state: T,
}

impl<S, T> Prover<Initialized<S, T>>
where
    S: AsyncWrite + AsyncRead + Send + Unpin + 'static,
    T: MuxChannelSerde + Clone + Send + Sync + Unpin + 'static,
{
    /// Creates a new prover.
    ///
    /// # Arguments
    ///
    /// * `config` - The configuration for the prover.
    /// * `server_socket` - The socket to the server.
    /// * `notary_mux` - The multiplexed connection to the notary.
    pub fn new(
        config: ProverConfig,
        server_socket: S,
        notary_mux: T,
    ) -> Result<(Self, TlsConnection), ProverError> {
        let (tx_sender, tx_receiver) = mpsc::channel::<Bytes>(10);
        let (rx_sender, rx_receiver) = mpsc::channel::<Result<Bytes, std::io::Error>>(10);
        let (close_send, close_recv) = oneshot::channel::<oneshot::Sender<()>>();

        let tls_conn = TlsConnection::new(tx_sender, rx_receiver, close_send);

        let server_name = ServerName::try_from(config.server_dns())?;

        Ok((
            Self {
                config,
                state: Initialized {
                    server_name,
                    server_socket,
                    notary_mux,
                    tx_receiver,
                    rx_sender,
                    close_recv,
                    transcript_tx: Transcript::new("tx", vec![]),
                    transcript_rx: Transcript::new("rx", vec![]),
                },
            },
            tls_conn,
        ))
    }

    /// Runs the prover, returning the next state when the TLS connection is closed.
    pub async fn run_tls(self) -> Result<Prover<Notarizing<T>>, ProverError> {
        let Initialized {
            server_name,
            server_socket,
            notary_mux: mux,
            tx_receiver,
            rx_sender,
            close_recv: close_tls_receiver,
            mut transcript_tx,
            mut transcript_rx,
        } = self.state;

        let (mpc_tls, vm, _, gf2, mut ot_fut) =
            setup_mpc_backend(&self.config, mux.clone()).await?;

        let mut root_store = tls_client::RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            tls_client::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
        let config = tls_client::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let client = ClientConnection::new(Arc::new(config), Box::new(mpc_tls), server_name)?;

        let start_time = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs();

        let (handshake_decommitment, server_public_key) = futures::select! {
            _ = &mut ot_fut => return Err(OTShutdownError)?,
            res = run_client(
                client,
                server_socket,
                &mut transcript_tx,
                &mut transcript_rx,
                tx_receiver,
                rx_sender,
                close_tls_receiver,
            ).fuse() => res?,
        };

        Ok(Prover {
            config: self.config,
            state: Notarizing {
                notary_mux: mux,
                vm,
                ot_fut,
                gf2,
                start_time,
                handshake_decommitment,
                server_public_key,
                transcript_tx,
                transcript_rx,
                commitments: vec![],
                substring_commitments: vec![],
            },
        })
    }
}

impl<T> Prover<Notarizing<T>>
where
    T: MuxChannelSerde + Clone + Send + Sync + Unpin + 'static,
{
    pub fn sent_transcript(&self) -> &Transcript {
        &self.state.transcript_tx
    }

    pub fn recv_transcript(&self) -> &Transcript {
        &self.state.transcript_rx
    }

    pub fn add_commitment_sent(&mut self, range: Range<u32>) -> Result<(), ProverError> {
        self.add_commitment(range, Direction::Sent)
    }

    pub fn add_commitment_recv(&mut self, range: Range<u32>) -> Result<(), ProverError> {
        self.add_commitment(range, Direction::Received)
    }

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

    pub async fn finalize(self) -> Result<NotarizedSession, ProverError> {
        let Notarizing {
            notary_mux: mut mux,
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
            let mut channel = mux.get_channel("notarize").await?;

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
            _ = ot_fut => return Err(OTShutdownError)?,
            res = notarize_fut.fuse() => res?,
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

async fn setup_mpc_backend<M: MuxChannelSerde + Clone + Send + 'static>(
    config: &ProverConfig,
    mut mux: M,
) -> Result<
    (
        MpcTlsLeader,
        DEAPVm<SenderActorControl, ReceiverActorControl>,
        ReceiverActorControl,
        ff::ConverterSender<ff::Gf2_128, SenderActorControl>,
        Pin<Box<dyn FusedFuture<Output = ()> + Send + 'static>>,
    ),
    ProverError,
> {
    let ((mut ot_send, ot_send_fut), (mut ot_recv, ot_recv_fut)) = futures::try_join!(
        create_ot_sender(mux.clone(), config.build_ot_sender_config()),
        create_ot_receiver(mux.clone(), config.build_ot_receiver_config())
    )
    .map_err(|e| ProverError::MpcError(Box::new(e)))?;

    // Join the OT background futures so they can be polled together
    let mut ot_fut = Box::pin(join(ot_send_fut, ot_recv_fut).map(|_| ()).fuse());

    futures::select! {
        _ = &mut ot_fut => return Err(OTShutdownError)?,
        res = try_join(ot_send.setup(), ot_recv.setup()).fuse() =>
            _ = res.map_err(|e| ProverError::MpcError(Box::new(e)))?,
    }

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
    let mpc_tls = MpcTlsLeader::new(mpc_tls_config, channel, ke, prf, encrypter, decrypter);

    Ok((mpc_tls, vm, ot_recv, gf2, ot_fut))
}

/// Runs the TLS session to completion, returning the session transcripts.
async fn run_client<T: AsyncWrite + AsyncRead + Unpin>(
    mut client: ClientConnection,
    server_socket: T,
    transcript_tx: &mut Transcript,
    transcript_rx: &mut Transcript,
    mut tx_receiver: mpsc::Receiver<Bytes>,
    mut rx_sender: mpsc::Sender<Result<Bytes, std::io::Error>>,
    mut close_recv: oneshot::Receiver<oneshot::Sender<()>>,
) -> Result<(Decommitment<HandshakeData>, PublicKey), ProverError> {
    client.start().await?;

    let (mut server_rx, mut server_tx) = server_socket.split();

    let mut rx_tls_buf = [0u8; RX_TLS_BUF_SIZE];
    let mut rx_buf = [0u8; RX_BUF_SIZE];

    let mut client_closed = false;
    let mut server_closed = false;

    let mut rx_tls_fut = server_rx.read(&mut rx_tls_buf).fuse();
    loop {
        select_biased! {
            read_res = &mut rx_tls_fut => {
                let received = read_res?;

                // Loop until we've processed all the data we received in this read.
                let mut processed = 0;
                while processed < received {
                    processed += client.read_tls(&mut &rx_tls_buf[processed..received])?;
                    match client.process_new_packets().await {
                        Ok(_) => {}
                        Err(e) => {
                            // In case we have an alert to send describing this error,
                            // try a last-gasp write -- but don't predate the primary
                            // error.
                            let _ignored = client.write_tls_async(&mut server_tx).await;

                            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                        }
                    }
                }

                if received == 0 {
                    server_closed = true;
                }

                // Reset the read future so next iteration we can read again.
                rx_tls_fut = server_rx.read(&mut rx_tls_buf).fuse();
            }
            data = tx_receiver.select_next_some() => {
                transcript_tx.extend(&data);
                client
                    .write_all_plaintext(&data)
                    .await?;
            },
            close_send = &mut close_recv => {
                client_closed = true;

                client.send_close_notify().await?;

                // Flush all remaining plaintext
                while client.wants_write() {
                    client.write_tls_async(&mut server_tx).await?;
                }
                server_tx.flush().await?;
                server_tx.close().await?;

                // Send the close signal to the TlsConnection
                if let Ok(close_send) = close_send {
                    _ = close_send.send(());
                }
            },
        }

        while client.wants_write() && !client_closed {
            client.write_tls_async(&mut server_tx).await?;
        }

        // Flush all remaining plaintext to the server
        // otherwise this loop could hang forever as the server
        // waits for more data before responding.
        server_tx.flush().await?;

        // Forward all plaintext to the TLSConnection
        loop {
            let n = match client.reader().read(&mut rx_buf) {
                Ok(n) => n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                // Some servers will not send a close_notify, in which case we need to
                // error because we can't reveal the MAC key to the Notary.
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Err(ProverError::ServerNoCloseNotify)
                }
                Err(e) => return Err(e)?,
            };

            if n > 0 {
                transcript_rx.extend(&rx_buf[..n]);
                // Ignore if the receiver has hung up.
                _ = rx_sender
                    .send(Ok(Bytes::copy_from_slice(&rx_buf[..n])))
                    .await;
            } else {
                break;
            }
        }

        if client_closed && server_closed {
            break;
        }
    }

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
        .expect("backend is MpcTlsLeader");

    let server_public_key = backend
        .server_public_key()
        .cloned()
        .expect("server key is set");

    let handshake_decommitment = backend
        .handshake_decommitment_mut()
        .take()
        .expect("handshake data was committed");

    Ok((handshake_decommitment, server_public_key))
}
