use crate::{
    error::MpcTlsError,
    msg::{
        ClientFinishedVd, CloseConnection, Commit, CommitMessage, ComputeKeyExchange, DecryptAlert,
        DecryptMessage, DecryptServerFinished, EncryptAlert, EncryptClientFinished, EncryptMessage,
        MpcTlsMessage, ServerFinishedVd,
    },
    Direction, MpcTlsChannel, MpcTlsLeaderConfig,
};
use async_trait::async_trait;
use cipher::{Cipher, CipherCircuit};
use futures::{SinkExt, TryFutureExt};
use hmac_sha256::Prf;
use ke::KeyExchange;
use key_exchange as ke;
use ludi::Context as LudiContext;
use mpz_common::Context;
use mpz_memory_core::binary::Binary;
use mpz_vm_core::Vm;
use std::collections::VecDeque;
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
use tlsn_universal_hash::UniversalHash;
use tracing::{debug, instrument, trace};

mod actor;
use actor::MpcTlsLeaderCtrl;

/// Controller for MPC-TLS leader.
pub type LeaderCtrl = MpcTlsLeaderCtrl;

/// MPC-TLS leader.
pub struct MpcTlsLeader<K, P, C, U> {
    config: MpcTlsLeaderConfig,
    channel: MpcTlsChannel,

    state: State,

    ke: K,
    prf: P,
    cipher: C,
    hash: U,
    /// When set, notifies the backend that there are TLS messages which need to
    /// be decrypted.
    notifier: BackendNotifier,
    /// Whether the backend is ready to decrypt messages.
    is_decrypting: bool,
    /// Messages which have been committed but not yet decrypted.
    buffer: VecDeque<OpaqueMessage>,
    /// Whether we have already committed to the transcript.
    committed: bool,
}

impl<K, P, C, U> MpcTlsLeader<K, P, C, U> {
    /// Create a new leader instance
    pub fn new(
        config: MpcTlsLeaderConfig,
        channel: MpcTlsChannel,
        ke: K,
        prf: P,
        cipher: C,
        hash: U,
    ) -> Self {
        let is_decrypting = !config.defer_decryption_from_start();

        Self {
            config,
            channel,
            state: State::default(),
            ke,
            prf,
            cipher,
            hash,
            notifier: BackendNotifier::new(),
            is_decrypting,
            buffer: VecDeque::new(),
            committed: false,
        }
    }

    /// Performs any one-time setup operations.
    #[instrument(level = "debug", skip_all, err)]
    pub async fn setup(&mut self) -> Result<(), MpcTlsError> {
        todo!()
    }

    /// Returns the number of bytes sent and received.
    pub fn bytes_transferred(&self) -> (usize, usize) {
        todo!()
    }

    fn check_transcript_length(&self, direction: Direction, len: usize) -> Result<(), MpcTlsError> {
        todo!()
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn encrypt_client_finished(
        &mut self,
        msg: PlainMessage,
    ) -> Result<OpaqueMessage, MpcTlsError> {
        todo!()
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn encrypt_alert(&mut self, msg: PlainMessage) -> Result<OpaqueMessage, MpcTlsError> {
        todo!()
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn encrypt_application_data(
        &mut self,
        msg: PlainMessage,
    ) -> Result<OpaqueMessage, MpcTlsError> {
        todo!()
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn decrypt_server_finished(
        &mut self,
        msg: OpaqueMessage,
    ) -> Result<PlainMessage, MpcTlsError> {
        todo!()
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn decrypt_alert(&mut self, msg: OpaqueMessage) -> Result<PlainMessage, MpcTlsError> {
        todo!()
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn decrypt_application_data(
        &mut self,
        msg: OpaqueMessage,
    ) -> Result<PlainMessage, MpcTlsError> {
        todo!()
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn commit(&mut self) -> Result<(), MpcTlsError> {
        todo!()
    }

    /// Closes the connection.
    #[instrument(name = "close_connection", level = "debug", skip_all, err)]
    pub async fn close_connection(
        &mut self,
        ctx: &mut LudiContext<Self>,
    ) -> Result<(), MpcTlsError> {
        todo!()
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

    pub fn test<V>()
    where
        C: Cipher<CipherCircuit, V>,
        V: Vm<Binary>,
    {
    }
}

#[async_trait]
impl<K, P, C, U> Backend for MpcTlsLeader<K, P, C, U>
where
    Self: Send,
    K: KeyExchange,
    P: Prf,
{
    async fn set_protocol_version(&mut self, version: ProtocolVersion) -> Result<(), BackendError> {
        let Ke {
            protocol_version, ..
        } = self.state.try_as_ke_mut()?;

        trace!("setting protocol version: {:?}", version);

        *protocol_version = Some(version);

        Ok(())
    }

    async fn set_cipher_suite(&mut self, suite: SupportedCipherSuite) -> Result<(), BackendError> {
        let Ke { cipher_suite, .. } = self.state.try_as_ke_mut()?;

        trace!("setting cipher suite: {:?}", suite);

        *cipher_suite = Some(suite.suite());

        Ok(())
    }

    async fn get_suite(&mut self) -> Result<SupportedCipherSuite, BackendError> {
        unimplemented!()
    }

    async fn set_encrypt(&mut self, _mode: EncryptMode) -> Result<(), BackendError> {
        unimplemented!()
    }

    async fn set_decrypt(&mut self, _mode: DecryptMode) -> Result<(), BackendError> {
        unimplemented!()
    }

    async fn get_client_random(&mut self) -> Result<Random, BackendError> {
        let Ke { client_random, .. } = self.state.try_as_ke()?;

        Ok(*client_random)
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn get_client_key_share(&mut self) -> Result<PublicKey, BackendError>
    where
        K: KeyExchange,
    {
        let pk = self
            .ke
            .client_key()
            .await
            .map_err(|err| BackendError::KeyExchange(err.to_string()))?;

        Ok(PublicKey::new(
            NamedGroup::secp256r1,
            &p256::EncodedPoint::from(pk).to_bytes(),
        ))
    }

    async fn set_server_random(&mut self, random: Random) -> Result<(), BackendError> {
        let Ke { server_random, .. } = self.state.try_as_ke_mut()?;

        *server_random = Some(random);

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn set_server_key_share(&mut self, key: PublicKey) -> Result<(), BackendError> {
        let Ke {
            server_public_key, ..
        } = self.state.try_as_ke_mut()?;

        if key.group != NamedGroup::secp256r1 {
            Err(BackendError::InvalidServerKey(format!(
                "unsupported key group: {:?}",
                key.group
            )))
        } else {
            let server_key = p256::PublicKey::from_sec1_bytes(&key.key)
                .map_err(|err| BackendError::InvalidServerKey(err.to_string()))?;

            *server_public_key = Some(key);

            self.ke
                .set_server_key(server_key)
                .await
                .map_err(|err| BackendError::KeyExchange(err.to_string()))?;

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
        } = self.state.try_as_ke_mut()?;

        *server_cert_details = Some(cert_details);

        Ok(())
    }

    async fn set_server_kx_details(
        &mut self,
        kx_details: ServerKxDetails,
    ) -> Result<(), BackendError> {
        let Ke {
            server_kx_details, ..
        } = self.state.try_as_ke_mut()?;

        *server_kx_details = Some(kx_details);

        Ok(())
    }

    async fn set_hs_hash_client_key_exchange(
        &mut self,
        _hash: Vec<u8>,
    ) -> Result<(), BackendError> {
        Ok(())
    }

    async fn set_hs_hash_server_hello(&mut self, _hash: Vec<u8>) -> Result<(), BackendError> {
        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn get_server_finished_vd(&mut self, hash: Vec<u8>) -> Result<Vec<u8>, BackendError> {
        let hash: [u8; 32] = hash.try_into().map_err(|_| {
            BackendError::ServerFinished(
                "server finished handshake hash is not 32 bytes".to_string(),
            )
        })?;

        self.channel
            .send(MpcTlsMessage::ServerFinishedVd(ServerFinishedVd {
                handshake_hash: hash,
            }))
            .await
            .map_err(|e| BackendError::InternalError(e.to_string()))?;

        let vd = self
            .prf
            .set_sf_hash(hash)
            .await
            .map_err(|err| BackendError::ServerFinished(err.to_string()))?;

        Ok(vd.to_vec())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn get_client_finished_vd(&mut self, hash: Vec<u8>) -> Result<Vec<u8>, BackendError> {
        let hash: [u8; 32] = hash.try_into().map_err(|_| {
            BackendError::ClientFinished(
                "client finished handshake hash is not 32 bytes".to_string(),
            )
        })?;

        self.channel
            .send(MpcTlsMessage::ClientFinishedVd(ClientFinishedVd {
                handshake_hash: hash,
            }))
            .await
            .map_err(|err| BackendError::InternalError(err.to_string()))?;

        let vd = self
            .prf
            .set_cf_hash(hash)
            .await
            .map_err(|err| BackendError::ClientFinished(err.to_string()))?;

        Ok(vd.to_vec())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn prepare_encryption(&mut self) -> Result<(), BackendError> {
        let Ke {
            protocol_version,
            cipher_suite,
            client_random,
            server_random,
            server_cert_details,
            server_public_key,
            server_kx_details,
        } = self.state.take().try_into_ke()?;

        let protocol_version =
            protocol_version.ok_or(BackendError::Other("protocol version not set".to_string()))?;
        let cipher_suite =
            cipher_suite.ok_or(BackendError::Other("cipher suite not set".to_string()))?;
        let server_cert_details =
            server_cert_details.ok_or(BackendError::Other("server cert not set".to_string()))?;
        let server_kx_details = server_kx_details
            .ok_or(BackendError::Other("server kx details not set".to_string()))?;
        let server_public_key = server_public_key
            .ok_or(BackendError::Other("server public key not set".to_string()))?;
        let server_random =
            server_random.ok_or(BackendError::Other("server random not set".to_string()))?;

        let handshake_data = HandshakeData::new(
            server_cert_details.clone(),
            server_kx_details.clone(),
            client_random,
            server_random,
        );

        self.channel
            .send(MpcTlsMessage::ComputeKeyExchange(ComputeKeyExchange {
                server_random: server_random.0,
            }))
            .await
            .map_err(|e| BackendError::InternalError(e.to_string()))?;

        self.ke
            .compute_pms()
            .await
            .map_err(|err| BackendError::KeyExchange(err.to_string()))?;

        self.prf
            .set_server_random(server_random.0)
            .await
            .map_err(|err| BackendError::Prf(err.to_string()))?;

        // futures::try_join!(self.encrypter.start(), self.decrypter.start())?;

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
        _seq: u64,
    ) -> Result<OpaqueMessage, BackendError> {
        let msg = match msg.typ {
            ContentType::Handshake => self
                .encrypt_client_finished(msg)
                .await
                .map_err(|err| BackendError::EncryptionError(err.to_string()))?,
            ContentType::ApplicationData => self
                .encrypt_application_data(msg)
                .await
                .map_err(|err| BackendError::EncryptionError(err.to_string()))?,
            ContentType::Alert => self
                .encrypt_alert(msg)
                .await
                .map_err(|err| BackendError::EncryptionError(err.to_string()))?,
            _ => {
                return Err(BackendError::EncryptionError(
                    "unexpected content type".to_string(),
                ))
            }
        };

        Ok(msg)
    }

    async fn decrypt(
        &mut self,
        msg: OpaqueMessage,
        _seq: u64,
    ) -> Result<PlainMessage, BackendError> {
        let msg = match msg.typ {
            ContentType::Handshake => self
                .decrypt_server_finished(msg)
                .await
                .map_err(|err| BackendError::DecryptionError(err.to_string()))?,
            ContentType::ApplicationData => self
                .decrypt_application_data(msg)
                .await
                .map_err(|err| BackendError::DecryptionError(err.to_string()))?,
            ContentType::Alert => self
                .decrypt_alert(msg)
                .await
                .map_err(|err| BackendError::DecryptionError(err.to_string()))?,
            _ => {
                return Err(BackendError::DecryptionError(
                    "unexpected content type".to_string(),
                ))
            }
        };

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
        self.commit()
            .await
            .map_err(|err| BackendError::Other(err.to_string()))
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

    impl From<StateError> for BackendError {
        fn from(err: StateError) -> Self {
            BackendError::InvalidState(err.to_string())
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
