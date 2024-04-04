use std::{collections::VecDeque, future::Future};

use async_trait::async_trait;
use futures::SinkExt;

use hmac_sha256 as prf;
use key_exchange as ke;
use prf::SessionKeys;

use aead::Aead;
use hmac_sha256::Prf;
use ke::KeyExchange;

use p256::SecretKey;
use tls_backend::{
    Backend, BackendError, BackendNotifier, BackendNotify, DecryptMode, EncryptMode,
};
use tls_core::{
    cert::ServerCertDetails,
    handshake::HandshakeData,
    ke::ServerKxDetails,
    key::PublicKey,
    msgs::{
        alert::AlertMessagePayload,
        codec::Codec,
        enums::{AlertDescription, CipherSuite, ContentType, NamedGroup, ProtocolVersion},
        handshake::Random,
        message::{OpaqueMessage, PlainMessage},
    },
    suites::SupportedCipherSuite,
};

use crate::{
    error::Kind,
    follower::{
        ClientFinishedVd, CommitMessage, ComputeClientKey, ComputeKeyExchange, DecryptAlert,
        DecryptMessage, DecryptServerFinished, EncryptAlert, EncryptClientFinished, EncryptMessage,
        ServerFinishedVd,
    },
    msg::{CloseConnection, Commit, MpcTlsLeaderMsg, MpcTlsMessage},
    record_layer::{Decrypter, Encrypter},
    MpcTlsChannel, MpcTlsError, MpcTlsLeaderConfig,
};

/// Controller for MPC-TLS leader.
pub type LeaderCtrl = MpcTlsLeaderCtrl<ludi::FuturesAddress<MpcTlsLeaderMsg>>;

/// MPC-TLS leader.
#[derive(ludi::Controller)]
pub struct MpcTlsLeader {
    config: MpcTlsLeaderConfig,
    channel: MpcTlsChannel,

    state: State,

    ke: Box<dyn KeyExchange + Send>,
    prf: Box<dyn Prf + Send>,
    encrypter: Encrypter,
    decrypter: Decrypter,

    /// When set, notifies the backend that there are TLS messages which need to be decrypted.
    notifier: BackendNotifier,

    /// Whether the backend is ready to decrypt messages.
    is_decrypting: bool,
    /// Messages which have been committed but not yet decrypted.
    buffer: VecDeque<OpaqueMessage>,
    /// Whether we have already committed to the transcript.
    committed: bool,
}

impl ludi::Actor for MpcTlsLeader {
    type Stop = MpcTlsData;
    type Error = MpcTlsError;

    async fn stopped(&mut self) -> Result<Self::Stop, Self::Error> {
        #[cfg(feature = "tracing")]
        tracing::debug!("leader actor stopped");

        let state::Closed { data } = self.state.take().try_into_closed()?;

        Ok(data)
    }
}

impl MpcTlsLeader {
    /// Create a new leader instance
    pub fn new(
        config: MpcTlsLeaderConfig,
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

        Self {
            config,
            channel,
            state: State::default(),
            ke,
            prf,
            encrypter,
            decrypter,
            notifier: BackendNotifier::new(),
            is_decrypting: true,
            buffer: VecDeque::new(),
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

    /// Runs the leader actor.
    ///
    /// Returns a control handle and a future that resolves when the actor is stopped.
    ///
    /// # Note
    ///
    /// The future must be polled continuously to make progress.
    pub fn run(
        mut self,
    ) -> (
        LeaderCtrl,
        impl Future<Output = Result<MpcTlsData, MpcTlsError>>,
    ) {
        let (mut mailbox, addr) = ludi::mailbox(100);

        let ctrl = LeaderCtrl::from(addr);
        let fut = async move { ludi::run(&mut self, &mut mailbox).await };

        (ctrl, fut)
    }

    /// Returns the number of bytes sent and received.
    pub fn bytes_transferred(&self) -> (usize, usize) {
        (self.encrypter.sent_bytes(), self.decrypter.recv_bytes())
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
        } else {
            Ok(())
        }
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    async fn encrypt_client_finished(
        &mut self,
        msg: PlainMessage,
    ) -> Result<OpaqueMessage, MpcTlsError> {
        let Cf { data } = self.state.take().try_into_cf()?;

        self.channel
            .send(MpcTlsMessage::EncryptClientFinished(EncryptClientFinished))
            .await?;

        let msg = self.encrypter.encrypt_private(msg).await?;

        self.state = State::Sf(Sf { data });

        Ok(msg)
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    async fn encrypt_alert(&mut self, msg: PlainMessage) -> Result<OpaqueMessage, MpcTlsError> {
        if let Some(alert) = AlertMessagePayload::read_bytes(&msg.payload.0) {
            // We only allow CloseNotify alerts.
            if alert.description != AlertDescription::CloseNotify {
                return Err(MpcTlsError::other(
                    "attempted to send an alert other than CloseNotify",
                ));
            }
        } else {
            return Err(MpcTlsError::other(
                "attempted to send an alert other than CloseNotify",
            ));
        }

        self.channel
            .send(MpcTlsMessage::EncryptAlert(EncryptAlert {
                msg: msg.payload.0.clone(),
            }))
            .await?;

        let msg = self.encrypter.encrypt_public(msg).await?;

        Ok(msg)
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    async fn encrypt_application_data(
        &mut self,
        msg: PlainMessage,
    ) -> Result<OpaqueMessage, MpcTlsError> {
        self.state.try_as_active()?;
        self.check_transcript_length(msg.payload.0.len())?;

        self.channel
            .send(MpcTlsMessage::EncryptMessage(EncryptMessage {
                len: msg.payload.0.len(),
            }))
            .await?;

        let msg = self.encrypter.encrypt_private(msg).await?;

        Ok(msg)
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    async fn decrypt_server_finished(
        &mut self,
        msg: OpaqueMessage,
    ) -> Result<PlainMessage, MpcTlsError> {
        let Sf { data } = self.state.take().try_into_sf()?;

        self.channel
            .send(MpcTlsMessage::DecryptServerFinished(
                DecryptServerFinished {
                    ciphertext: msg.payload.0.clone(),
                },
            ))
            .await?;

        let msg = self.decrypter.decrypt_private(msg).await?;

        self.state = State::Active(Active { data });

        Ok(msg)
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    async fn decrypt_alert(&mut self, msg: OpaqueMessage) -> Result<PlainMessage, MpcTlsError> {
        self.state.try_as_active()?;

        self.channel
            .send(MpcTlsMessage::DecryptAlert(DecryptAlert {
                ciphertext: msg.payload.0.clone(),
            }))
            .await?;

        let msg = self.decrypter.decrypt_public(msg).await?;

        Ok(msg)
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    async fn decrypt_application_data(
        &mut self,
        msg: OpaqueMessage,
    ) -> Result<PlainMessage, MpcTlsError> {
        self.state.try_as_active()?;
        self.check_transcript_length(msg.payload.0.len())?;

        self.channel
            .send(MpcTlsMessage::DecryptMessage(DecryptMessage))
            .await?;

        let msg = if self.committed {
            // At this point the AEAD key was revealed to us. We will locally decrypt the TLS message
            // and will prove the knowledge of the plaintext to the follower.
            self.decrypter.prove_plaintext(msg).await?
        } else {
            self.decrypter.decrypt_private(msg).await?
        };

        Ok(msg)
    }

    async fn commit(&mut self) -> Result<(), MpcTlsError> {
        self.state.try_as_active()?;

        #[cfg(feature = "tracing")]
        tracing::debug!("committing to transcript");

        self.channel.send(MpcTlsMessage::Commit(Commit)).await?;

        self.committed = true;

        if !self.buffer.is_empty() {
            self.decrypter.decode_key_private().await?;
            self.is_decrypting = true;
            self.notifier.set();
        }

        Ok(())
    }
}

#[ludi::implement(msg(name = "{name}"), ctrl(err))]
impl MpcTlsLeader {
    /// Closes the connection.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "close_connection", level = "trace", skip_all, err)
    )]
    #[msg(skip, name = "CloseConnection")]
    pub async fn close_connection(&mut self) -> Result<(), MpcTlsError> {
        #[cfg(feature = "tracing")]
        tracing::debug!("closing connection");

        self.channel
            .send(MpcTlsMessage::CloseConnection(CloseConnection))
            .await?;

        let Active { data } = self.state.take().try_into_active()?;

        self.state = State::Closed(Closed { data });

        ctx.stop();

        Ok(())
    }

    /// Defers decryption of any incoming messages.
    pub async fn defer_decryption(&mut self) -> Result<(), MpcTlsError> {
        if self.committed {
            return Ok(());
        }

        self.is_decrypting = false;
        self.notifier.clear();

        Ok(())
    }

    /// Commits the leader to the current transcript.
    ///
    /// This reveals the AEAD key to the leader and disables sending or receiving
    /// any further messages.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "finalize", level = "trace", skip_all, err)
    )]
    #[msg(skip, name = "Commit")]
    pub async fn commit(&mut self) -> Result<(), MpcTlsError> {
        self.commit().await
    }
}

#[ludi::implement]
#[ctrl(err = "MpcTlsError::from")]
#[msg(foreign, wrap, vis = "pub")]
#[async_trait]
impl Backend for MpcTlsLeader {
    async fn set_protocol_version(&mut self, version: ProtocolVersion) -> Result<(), BackendError> {
        let Ke {
            protocol_version, ..
        } = self.state.try_as_ke_mut().map_err(MpcTlsError::from)?;

        *protocol_version = Some(version);

        Ok(())
    }

    async fn set_cipher_suite(&mut self, suite: SupportedCipherSuite) -> Result<(), BackendError> {
        let Ke { cipher_suite, .. } = self.state.try_as_ke_mut().map_err(MpcTlsError::from)?;

        *cipher_suite = Some(suite.suite());

        Ok(())
    }

    async fn get_suite(&mut self) -> Result<SupportedCipherSuite, BackendError> {
        unimplemented!()
    }

    async fn set_encrypt(&mut self, mode: EncryptMode) -> Result<(), BackendError> {
        unimplemented!()
    }

    async fn set_decrypt(&mut self, mode: DecryptMode) -> Result<(), BackendError> {
        unimplemented!()
    }

    async fn get_client_random(&mut self) -> Result<Random, BackendError> {
        let Ke { client_random, .. } = self.state.try_as_ke().map_err(MpcTlsError::from)?;

        Ok(*client_random)
    }

    async fn get_client_key_share(&mut self) -> Result<PublicKey, BackendError> {
        self.channel
            .send(MpcTlsMessage::ComputeClientKey(ComputeClientKey))
            .await
            .map_err(MpcTlsError::from)?;

        let pk = self
            .ke
            .compute_client_key(SecretKey::random(&mut rand::rngs::OsRng))
            .await
            .map_err(MpcTlsError::from)?
            .expect("client key is returned as leader");

        Ok(PublicKey::new(
            NamedGroup::secp256r1,
            &p256::EncodedPoint::from(pk).to_bytes(),
        ))
    }

    async fn set_server_random(&mut self, random: Random) -> Result<(), BackendError> {
        let Ke { server_random, .. } = self.state.try_as_ke_mut().map_err(MpcTlsError::from)?;

        *server_random = Some(random);

        Ok(())
    }

    async fn set_server_key_share(&mut self, key: PublicKey) -> Result<(), BackendError> {
        let Ke {
            server_public_key, ..
        } = self.state.try_as_ke_mut().map_err(MpcTlsError::from)?;

        if key.group != NamedGroup::secp256r1 {
            Err(MpcTlsError::new(
                Kind::KeyExchange,
                format!("unsupported key group: {:?}", key.group),
            )
            .into())
        } else {
            *server_public_key = Some(key);
            Ok(())
        }
    }

    async fn set_server_cert_details(
        &mut self,
        cert_details: ServerCertDetails,
    ) -> Result<(), BackendError> {
        let Ke {
            server_cert_details,
            ..
        } = self.state.try_as_ke_mut().map_err(MpcTlsError::from)?;

        *server_cert_details = Some(cert_details);

        Ok(())
    }

    async fn set_server_kx_details(
        &mut self,
        kx_details: ServerKxDetails,
    ) -> Result<(), BackendError> {
        let Ke {
            server_kx_details, ..
        } = self.state.try_as_ke_mut().map_err(MpcTlsError::from)?;

        *server_kx_details = Some(kx_details);

        Ok(())
    }

    async fn set_hs_hash_client_key_exchange(&mut self, hash: Vec<u8>) -> Result<(), BackendError> {
        Ok(())
    }

    async fn set_hs_hash_server_hello(&mut self, hash: Vec<u8>) -> Result<(), BackendError> {
        Ok(())
    }

    async fn get_server_finished_vd(&mut self, hash: Vec<u8>) -> Result<Vec<u8>, BackendError> {
        let hash: [u8; 32] = hash
            .try_into()
            .map_err(|_| MpcTlsError::other("server finished handshake hash is not 32 bytes"))?;

        self.channel
            .send(MpcTlsMessage::ServerFinishedVd(ServerFinishedVd))
            .await
            .map_err(|e| BackendError::InternalError(e.to_string()))?;

        let vd = self
            .prf
            .compute_server_finished_vd_private(hash)
            .await
            .map_err(MpcTlsError::from)?;

        Ok(vd.to_vec())
    }

    async fn get_client_finished_vd(&mut self, hash: Vec<u8>) -> Result<Vec<u8>, BackendError> {
        let hash: [u8; 32] = hash
            .try_into()
            .map_err(|_| MpcTlsError::other("client finished handshake hash is not 32 bytes"))?;

        self.channel
            .send(MpcTlsMessage::ClientFinishedVd(ClientFinishedVd))
            .await
            .map_err(|e| BackendError::InternalError(e.to_string()))?;

        let vd = self
            .prf
            .compute_client_finished_vd_private(hash)
            .await
            .map_err(MpcTlsError::from)?;

        Ok(vd.to_vec())
    }

    async fn prepare_encryption(&mut self) -> Result<(), BackendError> {
        let Ke {
            protocol_version,
            cipher_suite,
            client_random,
            server_random,
            server_cert_details,
            server_public_key,
            server_kx_details,
        } = self.state.take().try_into_ke().map_err(MpcTlsError::from)?;

        let protocol_version =
            protocol_version.ok_or(MpcTlsError::other("protocol version not set"))?;
        let cipher_suite = cipher_suite.ok_or(MpcTlsError::other("cipher suite not set"))?;
        let server_cert_details =
            server_cert_details.ok_or(MpcTlsError::other("server cert not set"))?;
        let server_kx_details =
            server_kx_details.ok_or(MpcTlsError::other("server kx details not set"))?;
        let server_public_key =
            server_public_key.ok_or(MpcTlsError::other("server public key not set"))?;
        let server_random = server_random.ok_or(MpcTlsError::other("server random not set"))?;

        let handshake_data = HandshakeData::new(
            server_cert_details.clone(),
            server_kx_details.clone(),
            client_random,
            server_random,
        );

        self.channel
            .send(MpcTlsMessage::ComputeKeyExchange(ComputeKeyExchange))
            .await
            .map_err(|e| BackendError::InternalError(e.to_string()))?;

        let server_key = p256::PublicKey::from_sec1_bytes(&server_public_key.key)
            .map_err(|_| MpcTlsError::other("server key is not valid sec1p256"))?;

        self.ke.set_server_key(server_key);

        self.ke.compute_pms().await.map_err(MpcTlsError::from)?;

        let SessionKeys {
            client_write_key,
            server_write_key,
            client_iv,
            server_iv,
        } = self
            .prf
            .compute_session_keys_private(client_random.0, server_random.0)
            .await
            .map_err(MpcTlsError::from)?;

        self.encrypter.set_key(client_write_key, client_iv).await?;
        self.decrypter.set_key(server_write_key, server_iv).await?;

        self.state = State::Cf(Cf {
            data: MpcTlsData {
                protocol_version,
                cipher_suite,
                client_random,
                server_random,
                server_cert_details,
                server_public_key,
                server_kx_details,
                handshake_data,
            },
        });

        Ok(())
    }

    async fn encrypt(
        &mut self,
        msg: PlainMessage,
        seq: u64,
    ) -> Result<OpaqueMessage, BackendError> {
        let msg = match msg.typ {
            ContentType::Handshake => self.encrypt_client_finished(msg).await,
            ContentType::ApplicationData => self.encrypt_application_data(msg).await,
            ContentType::Alert => self.encrypt_alert(msg).await,
            _ => {
                return Err(BackendError::EncryptionError(
                    "unexpected content type".to_string(),
                ))
            }
        }
        .map_err(BackendError::from)?;

        Ok(msg)
    }

    async fn decrypt(
        &mut self,
        msg: OpaqueMessage,
        seq: u64,
    ) -> Result<PlainMessage, BackendError> {
        let msg = match msg.typ {
            ContentType::Handshake => self.decrypt_server_finished(msg).await,
            ContentType::ApplicationData => self.decrypt_application_data(msg).await,
            ContentType::Alert => self.decrypt_alert(msg).await,
            _ => {
                return Err(BackendError::DecryptionError(
                    "unexpected content type".to_string(),
                ))
            }
        }
        .map_err(BackendError::from)?;

        Ok(msg)
    }

    async fn buffer_incoming(&mut self, msg: OpaqueMessage) -> Result<(), BackendError> {
        if self.committed {
            return Err(BackendError::InternalError(
                "cannot buffer messages after committing to transcript".to_string(),
            ));
        }

        if msg.typ == ContentType::ApplicationData {
            self.channel
                .send(MpcTlsMessage::CommitMessage(CommitMessage {
                    msg: msg.payload.0.clone(),
                }))
                .await
                .map_err(|e| BackendError::InternalError(e.to_string()))?;
        }

        self.buffer.push_back(msg);

        if self.is_decrypting {
            self.notifier.set();
        }

        Ok(())
    }

    async fn next_incoming(&mut self) -> Result<Option<OpaqueMessage>, BackendError> {
        if !self.is_decrypting && self.state.is_active() {
            return Ok(None);
        }

        if self.buffer.is_empty() {
            self.notifier.clear();
        }

        Ok(self.buffer.pop_front())
    }

    async fn get_notify(&mut self) -> Result<BackendNotify, BackendError> {
        Ok(self.notifier.get())
    }

    async fn buffer_len(&mut self) -> Result<usize, BackendError> {
        Ok(self.buffer.len())
    }

    async fn server_closed(&mut self) -> Result<(), BackendError> {
        self.commit().await.map_err(BackendError::from)
    }
}

/// Data collected by the MPC-TLS leader.
#[derive(Debug)]
pub struct MpcTlsData {
    /// TLS protocol version.
    pub protocol_version: ProtocolVersion,
    /// TLS cipher suite.
    pub cipher_suite: CipherSuite,
    /// Client random.
    pub client_random: Random,
    /// Server random.
    pub server_random: Random,
    /// Server certificate details.
    pub server_cert_details: ServerCertDetails,
    /// Server ephemeral public key.
    pub server_public_key: PublicKey,
    /// Server key exchange details, eg signature.
    pub server_kx_details: ServerKxDetails,
    /// Handshake data.
    pub handshake_data: HandshakeData,
}

mod state {
    use super::*;
    use enum_try_as_inner::EnumTryAsInner;

    #[derive(Debug, EnumTryAsInner)]
    #[derive_err(Debug)]
    pub(super) enum State {
        Ke(Ke),
        Cf(Cf),
        Sf(Sf),
        Active(Active),
        Closed(Closed),
        Error,
    }

    impl State {
        pub(super) fn take(&mut self) -> Self {
            std::mem::replace(self, State::Error)
        }
    }

    impl Default for State {
        fn default() -> Self {
            State::Ke(Ke {
                protocol_version: None,
                cipher_suite: None,
                client_random: Random::new().expect("rng is available"),
                server_random: None,
                server_cert_details: None,
                server_public_key: None,
                server_kx_details: None,
            })
        }
    }

    impl From<StateError> for MpcTlsError {
        fn from(e: StateError) -> Self {
            Self::new(Kind::State, e)
        }
    }

    #[derive(Debug)]
    pub(super) struct Ke {
        pub(super) protocol_version: Option<ProtocolVersion>,
        pub(super) cipher_suite: Option<CipherSuite>,
        pub(super) client_random: Random,
        pub(super) server_random: Option<Random>,
        pub(super) server_cert_details: Option<ServerCertDetails>,
        pub(super) server_public_key: Option<PublicKey>,
        pub(super) server_kx_details: Option<ServerKxDetails>,
    }

    #[derive(Debug)]
    pub(super) struct Cf {
        pub(super) data: MpcTlsData,
    }

    #[derive(Debug)]
    pub(super) struct Sf {
        pub(super) data: MpcTlsData,
    }

    #[derive(Debug)]
    pub(super) struct Active {
        pub(super) data: MpcTlsData,
    }

    #[derive(Debug)]
    pub(super) struct Closed {
        pub(super) data: MpcTlsData,
    }
}

use state::*;
