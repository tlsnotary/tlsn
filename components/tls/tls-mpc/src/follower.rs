use std::{collections::VecDeque, future::Future, mem};

use futures::{
    stream::{SplitSink, SplitStream},
    FutureExt, StreamExt,
};

use hmac_sha256 as prf;
use key_exchange as ke;
use ludi::{Address, FuturesAddress};
use mpz_core::hash::Hash;

use p256::elliptic_curve::sec1::ToEncodedPoint;
use prf::SessionKeys;

use aead::Aead;
use hmac_sha256::Prf;
use ke::KeyExchange;
use tls_core::{
    key::PublicKey,
    msgs::{
        alert::AlertMessagePayload,
        base::Payload,
        codec::Codec,
        enums::{AlertDescription, ContentType, NamedGroup, ProtocolVersion},
        message::{OpaqueMessage, PlainMessage},
    },
};

use crate::{
    error::Kind,
    msg::{CloseConnection, Commit, MpcTlsFollowerMsg, MpcTlsMessage},
    record_layer::{Decrypter, Encrypter},
    MpcTlsChannel, MpcTlsError, MpcTlsFollowerConfig,
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
        #[cfg(feature = "tracing")]
        tracing::debug!("follower actor stopped");

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
    /// Create a new follower instance
    pub fn new(
        config: MpcTlsFollowerConfig,
        channel: MpcTlsChannel,
        ke: Box<dyn KeyExchange + Send>,
        prf: Box<dyn Prf + Send>,
        encrypter: Box<dyn Aead + Send>,
        decrypter: Box<dyn Aead + Send>,
    ) -> Self {
        let encrypter = Encrypter::new(
            encrypter,
            config.common().tx_transcript_id().to_string(),
            config.common().opaque_tx_transcript_id().to_string(),
        );
        let decrypter = Decrypter::new(
            decrypter,
            config.common().rx_transcript_id().to_string(),
            config.common().opaque_rx_transcript_id().to_string(),
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
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    pub async fn setup(&mut self) -> Result<(), MpcTlsError> {
        let pms = self.ke.setup().await?;
        self.prf.setup(pms.into_value()).await?;

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

        (ctrl, fut)
    }

    /// Returns the total number of bytes sent and received.
    fn total_bytes_transferred(&self) -> usize {
        self.encrypter.sent_bytes() + self.decrypter.recv_bytes()
    }

    fn check_transcript_length(&self, len: usize) -> Result<(), MpcTlsError> {
        let new_len = self.total_bytes_transferred() + len;
        if new_len > self.config.common().max_transcript_size() {
            return Err(MpcTlsError::new(
                Kind::Config,
                format!(
                    "max transcript size exceeded: {} > {}",
                    new_len,
                    self.config.common().max_transcript_size()
                ),
            ));
        }

        Ok(())
    }

    fn accepting_messages(&self) -> Result<(), MpcTlsError> {
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

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    async fn compute_client_key(&mut self) -> Result<(), MpcTlsError> {
        self.state.take().try_into_init()?;

        _ = self
            .ke
            .compute_client_key(p256::SecretKey::random(&mut rand::rngs::OsRng))
            .await?;

        self.state = State::ClientKey;

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    async fn compute_key_exchange(
        &mut self,
        handshake_commitment: Option<Hash>,
    ) -> Result<(), MpcTlsError> {
        self.state.take().try_into_client_key()?;

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
        let SessionKeys {
            client_write_key,
            server_write_key,
            client_iv,
            server_iv,
        } = self.prf.compute_session_keys_blind().await?;

        self.encrypter.set_key(client_write_key, client_iv).await?;
        self.decrypter.set_key(server_write_key, server_iv).await?;

        self.state = State::Ke(Ke {
            handshake_commitment,
            server_key: PublicKey::new(
                NamedGroup::secp256r1,
                server_key.to_encoded_point(false).as_bytes(),
            ),
        });

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    async fn client_finished_vd(&mut self) -> Result<(), MpcTlsError> {
        let Ke {
            handshake_commitment,
            server_key,
        } = self.state.take().try_into_ke()?;

        self.prf.compute_client_finished_vd_blind().await?;

        self.state = State::Cf(Cf {
            handshake_commitment,
            server_key,
        });

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    async fn server_finished_vd(&mut self) -> Result<(), MpcTlsError> {
        let Sf {
            handshake_commitment,
            server_key,
        } = self.state.take().try_into_sf()?;

        self.prf.compute_server_finished_vd_blind().await?;

        self.state = State::Active(Active {
            handshake_commitment,
            server_key,
            buffer: Default::default(),
        });

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    async fn encrypt_client_finished(&mut self) -> Result<(), MpcTlsError> {
        let Cf {
            handshake_commitment,
            server_key,
        } = self.state.take().try_into_cf()?;

        self.encrypter
            .encrypt_blind(ContentType::Handshake, ProtocolVersion::TLSv1_2, 16)
            .await?;

        self.state = State::Sf(Sf {
            handshake_commitment,
            server_key,
        });

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    async fn encrypt_alert(&mut self, msg: Vec<u8>) -> Result<(), MpcTlsError> {
        self.accepting_messages()?;
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

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    async fn encrypt_message(&mut self, len: usize) -> Result<(), MpcTlsError> {
        self.accepting_messages()?;
        self.check_transcript_length(len)?;
        self.state.try_as_active()?;

        self.encrypter
            .encrypt_blind(ContentType::ApplicationData, ProtocolVersion::TLSv1_2, len)
            .await?;

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    fn commit_message(&mut self, payload: Vec<u8>) -> Result<(), MpcTlsError> {
        self.accepting_messages()?;
        self.check_transcript_length(payload.len())?;
        let Active { buffer, .. } = self.state.try_as_active_mut()?;

        buffer.push_back(OpaqueMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_2,
            payload: Payload::new(payload),
        });

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    async fn decrypt_server_finished(&mut self, msg: Vec<u8>) -> Result<(), MpcTlsError> {
        self.state.try_as_sf()?;

        self.decrypter
            .decrypt_blind(OpaqueMessage {
                typ: ContentType::Handshake,
                version: ProtocolVersion::TLSv1_2,
                payload: Payload::new(msg),
            })
            .await?;

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
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

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    async fn decrypt_message(&mut self) -> Result<(), MpcTlsError> {
        let Active { buffer, .. } = self.state.try_as_active_mut()?;

        let msg = buffer.pop_front().ok_or(MpcTlsError::new(
            Kind::PeerMisbehaved,
            "attempted to decrypt message when no messages are committed",
        ))?;

        #[cfg(feature = "tracing")]
        tracing::debug!("decrypting message");

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

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
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

        #[cfg(feature = "tracing")]
        tracing::debug!("leader committed transcript");

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
    pub async fn compute_client_key(&mut self) {
        ctx.try_or_stop(|_| self.compute_client_key()).await;
    }

    pub async fn compute_key_exchange(&mut self, handshake_commitment: Option<Hash>) {
        ctx.try_or_stop(|_| self.compute_key_exchange(handshake_commitment))
            .await;
    }

    pub async fn client_finished_vd(&mut self) {
        ctx.try_or_stop(|_| self.client_finished_vd()).await;
    }

    pub async fn server_finished_vd(&mut self) {
        ctx.try_or_stop(|_| self.server_finished_vd()).await;
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
        ClientKey,
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
    }

    #[derive(Debug)]
    pub(super) struct Sf {
        pub(super) handshake_commitment: Option<Hash>,
        pub(super) server_key: PublicKey,
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
