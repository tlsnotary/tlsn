use std::{collections::VecDeque, future::Future, mem};

use futures::{
    stream::{SplitSink, SplitStream},
    FutureExt, StreamExt,
};

use key_exchange as ke;
use ludi::{Address, FuturesAddress};
use mpz_core::hash::Hash;

use p256::elliptic_curve::sec1::ToEncodedPoint;

use aead::{aes_gcm::AesGcmError, Aead};
use hmac_sha256::Prf;
use ke::KeyExchange;
use tls_core::{
    key::PublicKey,
    msgs::{
        alert::AlertMessagePayload,
        base::Payload,
        codec::Codec,
        enums::{AlertDescription, ContentType, HandshakeType, NamedGroup, ProtocolVersion},
        handshake::{HandshakeMessagePayload, HandshakePayload},
        message::{OpaqueMessage, PlainMessage},
    },
};
use tracing::{debug, instrument, Instrument};

use crate::{
    error::Kind,
    msg::{CloseConnection, Commit, MpcTlsFollowerMsg, MpcTlsMessage},
    record_layer::{Decrypter, Encrypter},
    Direction, MpcTlsChannel, MpcTlsError, MpcTlsFollowerConfig,
};

/// Controller for MPC-TLS follower.
pub type FollowerCtrl = MpcTlsFollowerCtrl<FuturesAddress<MpcTlsFollowerMsg>>;

/// MPC-TLS follower.
#[derive(ludi::Controller)]
pub struct MpcTlsFollower {
    state: State,
    config: MpcTlsFollowerConfig,

    _sink: SplitSink<MpcTlsChannel, MpcTlsMessage>,
    stream: Option<SplitStream<MpcTlsChannel>>,

    ke: Box<dyn KeyExchange + Send>,
    prf: Box<dyn Prf + Send>,
    encrypter: Encrypter,
    decrypter: Decrypter,

    /// Whether the server has sent a CloseNotify alert.
    close_notify: bool,
    /// Whether the leader has committed to the transcript.
    committed: bool,
}

/// Data collected by the MPC-TLS follower.
#[derive(Debug)]
pub struct MpcTlsFollowerData {
    /// The prover's commitment to the handshake data
    pub handshake_commitment: Option<Hash>,
    /// The server's public key
    pub server_key: PublicKey,
    /// The total number of bytes sent
    pub bytes_sent: usize,
    /// The total number of bytes received
    pub bytes_recv: usize,
}

impl ludi::Actor for MpcTlsFollower {
    type Stop = MpcTlsFollowerData;
    type Error = MpcTlsError;

    async fn stopped(&mut self) -> Result<Self::Stop, Self::Error> {
        debug!("follower actor stopped");

        let Closed {
            handshake_commitment,
            server_key,
        } = self.state.take().try_into_closed()?;

        let bytes_sent = self.encrypter.sent_bytes();
        let bytes_recv = self.decrypter.recv_bytes();

        Ok(MpcTlsFollowerData {
            handshake_commitment,
            server_key,
            bytes_sent,
            bytes_recv,
        })
    }
}

impl MpcTlsFollower {
    /// Creates a new follower.
    pub fn new(
        config: MpcTlsFollowerConfig,
        channel: MpcTlsChannel,
        ke: Box<dyn KeyExchange + Send>,
        prf: Box<dyn Prf + Send>,
        encrypter: Box<dyn Aead<Error = AesGcmError> + Send>,
        decrypter: Box<dyn Aead<Error = AesGcmError> + Send>,
    ) -> Self {
        let encrypter = Encrypter::new(
            encrypter,
            config.common().tx_config().id().to_string(),
            config.common().tx_config().opaque_id().to_string(),
        );
        let decrypter = Decrypter::new(
            decrypter,
            config.common().rx_config().id().to_string(),
            config.common().rx_config().opaque_id().to_string(),
        );

        let (_sink, stream) = channel.split();

        Self {
            state: State::Init,
            config,
            _sink,
            stream: Some(stream),
            ke,
            prf,
            encrypter,
            decrypter,
            close_notify: false,
            committed: false,
        }
    }

    /// Performs any one-time setup operations.
    #[instrument(level = "trace", skip_all, err)]
    pub async fn setup(&mut self) -> Result<(), MpcTlsError> {
        let pms = self.ke.setup().await?;
        let session_keys = self.prf.setup(pms.into_value()).await?;
        futures::try_join!(self.encrypter.setup(), self.decrypter.setup())?;

        futures::try_join!(
            self.encrypter
                .set_key(session_keys.client_write_key, session_keys.client_iv),
            self.decrypter
                .set_key(session_keys.server_write_key, session_keys.server_iv)
        )?;

        self.ke.preprocess().await?;
        self.prf.preprocess().await?;

        futures::try_join!(
            self.encrypter
                .preprocess(self.config.common().tx_config().max_size()),
            // For now we just preprocess enough for the handshake
            self.decrypter.preprocess(256),
        )?;

        self.prf.set_client_random(None).await?;

        Ok(())
    }

    /// Runs the follower actor.
    ///
    /// Returns a control handle and a future that resolves when the actor is stopped.
    ///
    /// # Note
    ///
    /// The future must be polled continuously to make progress.
    pub fn run(
        mut self,
    ) -> (
        FollowerCtrl,
        impl Future<Output = Result<MpcTlsFollowerData, MpcTlsError>>,
    ) {
        let (mut mailbox, addr) = ludi::mailbox::<MpcTlsFollowerMsg>(100);
        let ctrl = FollowerCtrl::from(addr.clone());

        let mut stream = self
            .stream
            .take()
            .expect("stream should be present from constructor");

        let mut remote_fut = Box::pin(async move {
            while let Some(msg) = stream.next().await {
                let msg = MpcTlsFollowerMsg::try_from(msg?)?;
                addr.send_await(msg).await?;
            }

            Ok::<_, MpcTlsError>(())
        })
        .fuse();

        let mut actor_fut =
            Box::pin(async move { ludi::run(&mut self, &mut mailbox).await }).fuse();

        let fut = async move {
            loop {
                futures::select! {
                    res = &mut remote_fut => {
                        if let Err(e) = res {
                            return Err(e);
                        }
                    },
                    res = &mut actor_fut => return res,
                }
            }
        };

        (ctrl, fut.in_current_span())
    }

    fn check_transcript_length(&self, direction: Direction, len: usize) -> Result<(), MpcTlsError> {
        match direction {
            Direction::Sent => {
                let new_len = self.encrypter.sent_bytes() + len;
                let max_size = self.config.common().tx_config().max_size();
                if new_len > max_size {
                    return Err(MpcTlsError::new(
                        Kind::Config,
                        format!(
                            "max sent transcript size exceeded: {} > {}",
                            new_len, max_size
                        ),
                    ));
                }
            }
            Direction::Recv => {
                let new_len = self.decrypter.recv_bytes() + len;
                let max_size = self.config.common().rx_config().max_size();
                if new_len > max_size {
                    return Err(MpcTlsError::new(
                        Kind::Config,
                        format!(
                            "max received transcript size exceeded: {} > {}",
                            new_len, max_size
                        ),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Returns an error if the follower is not accepting new messages.
    ///
    /// This can happen if the follower has received a CloseNotify alert or if the leader has
    /// committed to the transcript.
    fn is_accepting_messages(&self) -> Result<(), MpcTlsError> {
        if self.close_notify {
            return Err(MpcTlsError::new(
                Kind::PeerMisbehaved,
                "attempted to commit a message after receiving CloseNotify",
            ));
        }

        if self.committed {
            return Err(MpcTlsError::new(
                Kind::PeerMisbehaved,
                "attempted to commit a new message after committing transcript",
            ));
        }

        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
    async fn compute_key_exchange(
        &mut self,
        handshake_commitment: Option<Hash>,
        server_random: [u8; 32],
    ) -> Result<(), MpcTlsError> {
        self.state.take().try_into_init()?;

        if self.config.common().handshake_commit() && handshake_commitment.is_none() {
            return Err(MpcTlsError::new(
                Kind::PeerMisbehaved,
                "handshake commitment missing",
            ));
        }

        // Key exchange
        self.ke.compute_pms().await?;

        let server_key = self
            .ke
            .server_key()
            .expect("server key should be set after computing pms");

        // PRF
        self.prf.compute_session_keys(server_random).await?;

        futures::try_join!(self.encrypter.start(), self.decrypter.start())?;

        self.state = State::Ke(Ke {
            handshake_commitment,
            server_key: PublicKey::new(
                NamedGroup::secp256r1,
                server_key.to_encoded_point(false).as_bytes(),
            ),
        });

        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
    async fn client_finished_vd(&mut self, handshake_hash: [u8; 32]) -> Result<(), MpcTlsError> {
        let Ke {
            handshake_commitment,
            server_key,
        } = self.state.take().try_into_ke()?;

        let client_finished = self.prf.compute_client_finished_vd(handshake_hash).await?;

        self.state = State::Cf(Cf {
            handshake_commitment,
            server_key,
            client_finished,
        });

        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
    async fn server_finished_vd(&mut self, handshake_hash: [u8; 32]) -> Result<(), MpcTlsError> {
        let Sf {
            handshake_commitment,
            server_key,
            server_finished,
        } = self.state.take().try_into_sf()?;

        let expected_server_finished = self.prf.compute_server_finished_vd(handshake_hash).await?;

        let Some(server_finished) = server_finished else {
            return Err(MpcTlsError::new(Kind::State, "server finished is not set"));
        };

        if server_finished != expected_server_finished {
            return Err(MpcTlsError::new(
                Kind::Prf,
                "server finished does not match",
            ));
        }

        self.state = State::Active(Active {
            handshake_commitment,
            server_key,
            buffer: Default::default(),
        });

        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
    async fn encrypt_client_finished(&mut self) -> Result<(), MpcTlsError> {
        let Cf {
            handshake_commitment,
            server_key,
            client_finished,
        } = self.state.take().try_into_cf()?;

        let msg = HandshakeMessagePayload {
            typ: HandshakeType::Finished,
            payload: HandshakePayload::Finished(Payload::new(client_finished)),
        };
        let mut payload = Vec::new();
        msg.encode(&mut payload);

        self.encrypter
            .encrypt_public(PlainMessage {
                typ: ContentType::Handshake,
                version: ProtocolVersion::TLSv1_2,
                payload: Payload(payload),
            })
            .await?;

        self.state = State::Sf(Sf {
            handshake_commitment,
            server_key,
            server_finished: None,
        });

        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
    async fn encrypt_alert(&mut self, msg: Vec<u8>) -> Result<(), MpcTlsError> {
        self.is_accepting_messages()?;
        if let Some(alert) = AlertMessagePayload::read_bytes(&msg) {
            // We only allow the leader to send a CloseNotify alert
            if alert.description != AlertDescription::CloseNotify {
                return Err(MpcTlsError::new(
                    Kind::PeerMisbehaved,
                    "attempted to send an alert other than CloseNotify",
                ));
            }
        } else {
            return Err(MpcTlsError::new(
                Kind::PeerMisbehaved,
                "invalid alert message",
            ));
        }

        self.encrypter
            .encrypt_public(PlainMessage {
                typ: ContentType::Alert,
                version: ProtocolVersion::TLSv1_2,
                payload: Payload::new(msg),
            })
            .await?;

        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
    async fn encrypt_message(&mut self, len: usize) -> Result<(), MpcTlsError> {
        self.is_accepting_messages()?;
        self.check_transcript_length(Direction::Sent, len)?;
        self.state.try_as_active()?;

        self.encrypter
            .encrypt_blind(ContentType::ApplicationData, ProtocolVersion::TLSv1_2, len)
            .await?;

        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
    fn commit_message(&mut self, payload: Vec<u8>) -> Result<(), MpcTlsError> {
        self.is_accepting_messages()?;
        self.check_transcript_length(Direction::Recv, payload.len())?;
        let Active { buffer, .. } = self.state.try_as_active_mut()?;

        buffer.push_back(OpaqueMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: Payload::new(payload),
        });

        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
    async fn decrypt_server_finished(&mut self, msg: Vec<u8>) -> Result<(), MpcTlsError> {
        let Sf {
            server_finished, ..
        } = self.state.try_as_sf_mut()?;

        let msg = self
            .decrypter
            .decrypt_public(OpaqueMessage {
                typ: ContentType::Handshake,
                version: ProtocolVersion::TLSv1_2,
                payload: Payload::new(msg),
            })
            .await?;

        let msg = msg.payload.0;
        if msg.len() != 16 {
            return Err(MpcTlsError::new(
                Kind::Decrypt,
                "server finished message is not 16 bytes",
            ));
        }

        let sf: [u8; 12] = msg[4..].try_into().expect("slice should be 12 bytes");

        server_finished.replace(sf);

        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
    async fn decrypt_alert(&mut self, msg: Vec<u8>) -> Result<(), MpcTlsError> {
        self.state.try_as_active()?;

        let alert = self
            .decrypter
            .decrypt_public(OpaqueMessage {
                typ: ContentType::Alert,
                version: ProtocolVersion::TLSv1_2,
                payload: Payload::new(msg),
            })
            .await?;

        let Some(alert) = AlertMessagePayload::read_bytes(&alert.payload.0) else {
            return Err(MpcTlsError::other("server sent an invalid alert"));
        };

        if alert.description != AlertDescription::CloseNotify {
            return Err(MpcTlsError::new(
                Kind::PeerMisbehaved,
                "server sent a fatal alert",
            ));
        }

        self.close_notify = true;

        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
    async fn decrypt_message(&mut self) -> Result<(), MpcTlsError> {
        let Active { buffer, .. } = self.state.try_as_active_mut()?;

        let msg = buffer.pop_front().ok_or(MpcTlsError::new(
            Kind::PeerMisbehaved,
            "attempted to decrypt message when no messages are committed",
        ))?;

        debug!("decrypting message");

        if self.committed {
            // At this point the AEAD key was revealed to the leader and the leader locally decrypted
            // the TLS message and now is proving to us that they know the plaintext which encrypts
            // to the ciphertext of this TLS message.
            self.decrypter.verify_plaintext(msg).await?;
        } else {
            self.decrypter.decrypt_blind(msg).await?;
        }

        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
    fn close_connection(&mut self) -> Result<(), MpcTlsError> {
        let Active {
            handshake_commitment,
            server_key,
            buffer,
        } = self.state.take().try_into_active()?;

        if !buffer.is_empty() {
            return Err(MpcTlsError::new(
                Kind::PeerMisbehaved,
                "attempted to close connection without decrypting all messages",
            ));
        }

        self.state = State::Closed(Closed {
            handshake_commitment,
            server_key,
        });

        Ok(())
    }

    async fn commit(&mut self) -> Result<(), MpcTlsError> {
        let Active { buffer, .. } = self.state.try_as_active()?;

        debug!("leader committed transcript");

        self.committed = true;

        // Reveal the AEAD key to the leader only if there are TLS messages which need to be decrypted.
        if !buffer.is_empty() {
            self.decrypter.decode_key_blind().await?;
        }

        Ok(())
    }
}

#[ludi::implement]
#[msg(name = "{name}")]
#[msg(attrs(derive(Debug, serde::Serialize, serde::Deserialize)))]
impl MpcTlsFollower {
    pub async fn compute_key_exchange(
        &mut self,
        handshake_commitment: Option<Hash>,
        server_random: [u8; 32],
    ) {
        ctx.try_or_stop(|_| self.compute_key_exchange(handshake_commitment, server_random))
            .await;
    }

    pub async fn client_finished_vd(&mut self, handshake_hash: [u8; 32]) {
        ctx.try_or_stop(|_| self.client_finished_vd(handshake_hash))
            .await;
    }

    pub async fn server_finished_vd(&mut self, handshake_hash: [u8; 32]) {
        ctx.try_or_stop(|_| self.server_finished_vd(handshake_hash))
            .await;
    }

    pub async fn encrypt_client_finished(&mut self) {
        ctx.try_or_stop(|_| self.encrypt_client_finished()).await;
    }

    pub async fn encrypt_alert(&mut self, msg: Vec<u8>) {
        ctx.try_or_stop(|_| self.encrypt_alert(msg)).await;
    }

    pub async fn encrypt_message(&mut self, len: usize) {
        ctx.try_or_stop(|_| self.encrypt_message(len)).await;
    }

    pub async fn decrypt_server_finished(&mut self, ciphertext: Vec<u8>) {
        ctx.try_or_stop(|_| self.decrypt_server_finished(ciphertext))
            .await;
    }

    pub async fn decrypt_alert(&mut self, ciphertext: Vec<u8>) {
        ctx.try_or_stop(|_| self.decrypt_alert(ciphertext)).await;
    }

    pub async fn commit_message(&mut self, msg: Vec<u8>) {
        ctx.try_or_stop(|_| async { self.commit_message(msg) })
            .await;
    }

    pub async fn decrypt_message(&mut self) {
        ctx.try_or_stop(|_| self.decrypt_message()).await;
    }

    #[msg(skip, name = "CloseConnection")]
    pub async fn close_connection(&mut self) -> Result<(), MpcTlsError> {
        ctx.try_or_stop(|_| async { self.close_connection() }).await;

        ctx.stop();

        Ok(())
    }

    #[msg(skip, name = "Commit")]
    pub async fn commit(&mut self) -> Result<(), MpcTlsError> {
        ctx.try_or_stop(|_| self.commit()).await;

        Ok(())
    }
}

mod state {
    use super::*;
    use enum_try_as_inner::EnumTryAsInner;

    #[derive(Debug, EnumTryAsInner)]
    #[derive_err(Debug)]
    pub(super) enum State {
        Init,
        Ke(Ke),
        Cf(Cf),
        Sf(Sf),
        Active(Active),
        Closed(Closed),
        Error,
    }

    impl State {
        pub(super) fn take(&mut self) -> Self {
            mem::replace(self, State::Error)
        }
    }

    impl From<StateError> for MpcTlsError {
        fn from(err: StateError) -> Self {
            MpcTlsError::new(Kind::State, err)
        }
    }

    #[derive(Debug)]
    pub(super) struct Ke {
        pub(super) handshake_commitment: Option<Hash>,
        pub(super) server_key: PublicKey,
    }

    #[derive(Debug)]
    pub(super) struct Cf {
        pub(super) handshake_commitment: Option<Hash>,
        pub(super) server_key: PublicKey,
        pub(super) client_finished: [u8; 12],
    }

    #[derive(Debug)]
    pub(super) struct Sf {
        pub(super) handshake_commitment: Option<Hash>,
        pub(super) server_key: PublicKey,
        pub(super) server_finished: Option<[u8; 12]>,
    }

    #[derive(Debug)]
    pub(super) struct Active {
        pub(super) handshake_commitment: Option<Hash>,
        pub(super) server_key: PublicKey,
        /// TLS messages purportedly received by the leader from the server.
        ///
        /// The follower must verify the authenticity of these messages with AEAD verification
        /// (i.e. by verifying the authentication tag).
        pub(super) buffer: VecDeque<OpaqueMessage>,
    }

    #[derive(Debug)]
    pub(super) struct Closed {
        pub(super) handshake_commitment: Option<Hash>,
        pub(super) server_key: PublicKey,
    }
}

use state::*;
