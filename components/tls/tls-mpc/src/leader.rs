use std::future::Future;

use async_trait::async_trait;
use futures::SinkExt;

use hmac_sha256 as prf;
use key_exchange as ke;
use mpz_core::commit::{Decommitment, HashCommit};
use prf::SessionKeys;

use aead::Aead;
use hmac_sha256::Prf;
use ke::KeyExchange;

use p256::SecretKey;
use tls_backend::{Backend, BackendError, DecryptMode, EncryptMode};
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
    msg::{CloseConnection, Finalize, MpcTlsLeaderMsg, MpcTlsMessage},
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
        let Active { data } = self.state.take().try_into_active()?;

        self.channel
            .send(MpcTlsMessage::DecryptAlert(DecryptAlert {
                ciphertext: msg.payload.0.clone(),
            }))
            .await?;

        let msg = self.decrypter.decrypt_public(msg).await?;

        self.state = State::Closed(Closed { data });

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
            .feed(MpcTlsMessage::CommitMessage(CommitMessage {
                msg: msg.payload.0.clone(),
            }))
            .await?;

        self.channel
            .send(MpcTlsMessage::DecryptMessage(DecryptMessage))
            .await?;

        let msg = self.decrypter.decrypt_private(msg).await?;

        Ok(msg)
    }
}

#[ludi::implement(ctrl(err))]
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

        if self.state.is_closed() {
            // Already closed from receiving CloseNotify.
            return Ok(());
        }

        let Active { data } = self.state.take().try_into_active()?;

        self.state = State::Closed(Closed { data });

        Ok(())
    }

    /// Finalizes the MPC-TLS protocol.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(name = "finalize", level = "trace", skip_all, err)
    )]
    #[msg(skip, name = "Finalize")]
    pub async fn finalize(&mut self) -> Result<(), MpcTlsError> {
        #[cfg(feature = "tracing")]
        tracing::debug!("finalizing MPC-TLS protocol");

        self.channel.send(MpcTlsMessage::Finalize(Finalize)).await?;

        ctx.stop();

        Ok(())
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

        let (handshake_decommitment, handshake_commitment) =
            if self.config.common().handshake_commit() {
                let (decommitment, commitment) = handshake_data.clone().hash_commit();

                (Some(decommitment), Some(commitment))
            } else {
                (None, None)
            };

        self.channel
            .send(MpcTlsMessage::ComputeKeyExchange(ComputeKeyExchange {
                handshake_commitment,
            }))
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
                handshake_decommitment,
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
    /// Server key exchange details, eg certificate.
    pub server_kx_details: ServerKxDetails,
    /// Handshake data.
    pub handshake_data: HandshakeData,
    /// Handshake data decommitment.
    pub handshake_decommitment: Option<Decommitment<HandshakeData>>,
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
