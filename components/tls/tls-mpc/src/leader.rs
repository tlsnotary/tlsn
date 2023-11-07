use std::any::Any;

use async_trait::async_trait;
use futures::{SinkExt, TryFutureExt};

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
    cipher::make_tls12_aad,
    handshake::HandshakeData,
    ke::ServerKxDetails,
    key::PublicKey,
    msgs::{
        base::Payload,
        enums::{CipherSuite, ContentType, NamedGroup, ProtocolVersion},
        handshake::Random,
        message::{OpaqueMessage, PlainMessage},
    },
    suites::SupportedCipherSuite,
};

use crate::{
    msg::{DecryptMessage, EncryptMessage, MpcTlsMessage},
    MpcTlsChannel, MpcTlsError, MpcTlsLeaderConfig,
};

/// Wrapper for protocol instances of the leader
pub struct MpcTlsLeader {
    config: MpcTlsLeaderConfig,
    channel: MpcTlsChannel,

    conn_state: ConnectionState,

    ke: Box<dyn KeyExchange + Send>,
    prf: Box<dyn Prf + Send>,
    encrypter: Box<dyn Aead + Send>,
    decrypter: Box<dyn Aead + Send>,
}

struct ConnectionState {
    protocol_version: Option<ProtocolVersion>,
    cipher_suite: Option<CipherSuite>,

    client_random: Random,
    server_random: Option<Random>,

    server_cert_details: Option<ServerCertDetails>,
    server_public_key: Option<PublicKey>,
    server_kx_details: Option<ServerKxDetails>,

    handshake_data: Option<HandshakeData>,
    handshake_decommitment: Option<Decommitment<HandshakeData>>,

    sent_bytes: usize,
    recv_bytes: usize,
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self {
            protocol_version: Default::default(),
            cipher_suite: Default::default(),
            client_random: Random::new().expect("thread rng is available"),
            server_random: Default::default(),
            server_cert_details: Default::default(),
            server_public_key: Default::default(),
            server_kx_details: Default::default(),
            handshake_data: Default::default(),
            handshake_decommitment: Default::default(),
            sent_bytes: 0,
            recv_bytes: 0,
        }
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
        Self {
            config,
            channel,
            conn_state: ConnectionState::default(),
            ke,
            prf,
            encrypter,
            decrypter,
        }
    }

    /// Performs any one-time setup operations.
    pub async fn setup(&mut self) -> Result<(), MpcTlsError> {
        let pms = self.ke.setup().await?;
        self.prf.setup(pms.into_value()).await?;

        Ok(())
    }

    /// Sets the protocol version.
    pub fn set_protocol_version(&mut self, version: ProtocolVersion) {
        self.conn_state.protocol_version = Some(version);
    }

    /// Sets the cipher suite.
    pub fn set_cipher_suite(&mut self, suite: CipherSuite) {
        self.conn_state.cipher_suite = Some(suite);
    }

    /// Sets the server random.
    pub fn set_server_random(&mut self, random: Random) {
        self.conn_state.server_random = Some(random);
    }

    /// Sets the server ephemeral key.
    pub fn set_server_key(&mut self, key: PublicKey) -> Result<(), MpcTlsError> {
        if key.group != NamedGroup::secp256r1 {
            return Err(MpcTlsError::UnsupportedCurveGroup(key.group));
        }

        self.conn_state.server_public_key = Some(key);

        Ok(())
    }

    /// Returns the server's ephemeral public key.
    pub fn server_public_key(&self) -> Option<&PublicKey> {
        self.conn_state.server_public_key.as_ref()
    }

    /// Returns the server's certificate details.
    pub fn server_cert_details(&self) -> Option<&ServerCertDetails> {
        self.conn_state.server_cert_details.as_ref()
    }

    /// Returns the server's kx details.
    pub fn server_kx_details(&self) -> Option<&ServerKxDetails> {
        self.conn_state.server_kx_details.as_ref()
    }

    /// Returns the handshake data.
    pub fn handshake_decommitment(&self) -> Option<&Decommitment<HandshakeData>> {
        self.conn_state.handshake_decommitment.as_ref()
    }

    /// Returns a mutable reference to the handshake data.
    pub fn handshake_decommitment_mut(&mut self) -> &mut Option<Decommitment<HandshakeData>> {
        &mut self.conn_state.handshake_decommitment
    }

    /// Returns the number of bytes sent and received.
    pub fn bytes_transferred(&self) -> (usize, usize) {
        (self.conn_state.sent_bytes, self.conn_state.recv_bytes)
    }

    /// Returns the total number of bytes sent and received.
    fn total_bytes_transferred(&self) -> usize {
        self.conn_state.sent_bytes + self.conn_state.recv_bytes
    }

    /// Computes the combined key
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip(self), err)
    )]
    pub async fn compute_client_key(&mut self) -> Result<PublicKey, MpcTlsError> {
        let pk = self
            .ke
            .compute_client_key(SecretKey::random(&mut rand::rngs::OsRng))
            .await?
            .expect("client key is returned as leader");

        Ok(PublicKey::new(
            NamedGroup::secp256r1,
            &p256::EncodedPoint::from(pk).to_bytes(),
        ))
    }

    /// Computes the TLS session keys
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip(self), err)
    )]
    pub async fn compute_session_keys(&mut self) -> Result<(), MpcTlsError> {
        let server_cert_details = self
            .conn_state
            .server_cert_details
            .as_ref()
            .ok_or(MpcTlsError::ServerCertNotSet)?;

        let server_kx_details = self
            .conn_state
            .server_kx_details
            .as_ref()
            .ok_or(MpcTlsError::ServerKxDetailsNotSet)?;

        let server_key = self
            .conn_state
            .server_public_key
            .as_ref()
            .ok_or(MpcTlsError::ServerKeyNotSet)?;

        let server_random = self
            .conn_state
            .server_random
            .ok_or(MpcTlsError::ServerRandomNotSet)?;

        let client_random = self.conn_state.client_random;

        let handshake_data = HandshakeData::new(
            server_cert_details.clone(),
            server_kx_details.clone(),
            client_random,
            server_random,
        );

        if self.config.common().handshake_commit() {
            let (decommitment, commitment) = handshake_data.clone().hash_commit();

            self.conn_state.handshake_decommitment = Some(decommitment);

            self.channel
                .send(MpcTlsMessage::HandshakeCommitment(commitment))
                .await?;
        }

        self.conn_state.handshake_data = Some(handshake_data);

        let server_key = p256::PublicKey::from_sec1_bytes(&server_key.key)
            .map_err(|_| MpcTlsError::InvalidServerKey)?;

        self.ke.set_server_key(server_key);

        self.ke.compute_pms().await?;

        let SessionKeys {
            client_write_key,
            server_write_key,
            client_iv,
            server_iv,
        } = self
            .prf
            .compute_session_keys_private(client_random.0, server_random.0)
            .await?;

        self.encrypter.set_key(client_write_key, client_iv).await?;
        self.decrypter.set_key(server_write_key, server_iv).await?;

        Ok(())
    }

    /// Computes the client finished verify data
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip(self, hash), err)
    )]
    pub async fn compute_client_finished_vd(
        &mut self,
        hash: &[u8],
    ) -> Result<Vec<u8>, MpcTlsError> {
        let hash: [u8; 32] = hash
            .try_into()
            .map_err(|_| MpcTlsError::InvalidHandshakeHash(hash.to_vec()))?;

        let vd = self.prf.compute_client_finished_vd_private(hash).await?;

        Ok(vd.to_vec())
    }

    /// Computes the server finished verify data
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip(self, hash), err)
    )]
    pub async fn compute_server_finished_vd(
        &mut self,
        hash: &[u8],
    ) -> Result<Vec<u8>, MpcTlsError> {
        let hash: [u8; 32] = hash
            .try_into()
            .map_err(|_| MpcTlsError::InvalidHandshakeHash(hash.to_vec()))?;

        let vd = self.prf.compute_server_finished_vd_private(hash).await?;

        Ok(vd.to_vec())
    }

    /// Encrypt a message
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip(self, m), err)
    )]
    pub async fn encrypt(
        &mut self,
        m: PlainMessage,
        seq: u64,
    ) -> Result<OpaqueMessage, MpcTlsError> {
        if self.total_bytes_transferred() + m.payload.0.len()
            > self.config.common().max_transcript_size()
        {
            return Err(MpcTlsError::MaxTranscriptLengthExceeded(
                self.total_bytes_transferred() + m.payload.0.len(),
                self.config.common().max_transcript_size(),
            ));
        }

        let explicit_nonce = seq.to_be_bytes().to_vec();

        let aad = make_tls12_aad(seq, m.typ, m.version, m.payload.0.len());

        match m.typ {
            ContentType::Alert => {
                self.channel
                    .send(MpcTlsMessage::SendCloseNotify(EncryptMessage {
                        typ: m.typ,
                        seq,
                        len: m.payload.0.len(),
                    }))
                    .await?;
            }
            _ => {
                self.channel
                    .send(MpcTlsMessage::EncryptMessage(EncryptMessage {
                        typ: m.typ,
                        seq,
                        len: m.payload.0.len(),
                    }))
                    .await?;
            }
        }

        // Set the transcript id depending on the type of message
        match m.typ {
            ContentType::ApplicationData => self
                .encrypter
                .set_transcript_id(self.config.common().tx_transcript_id()),
            _ => self
                .encrypter
                .set_transcript_id(self.config.common().opaque_tx_transcript_id()),
        }

        let ciphertext = self
            .encrypter
            .encrypt_private(explicit_nonce.clone(), m.payload.0, aad.to_vec())
            .await?;

        self.conn_state.sent_bytes += ciphertext.len();

        let mut payload = explicit_nonce;
        payload.extend(ciphertext);

        let msg = OpaqueMessage {
            typ: m.typ,
            version: m.version,
            payload: Payload::new(payload),
        };

        Ok(msg)
    }

    /// Decrypt a message
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip(self, m), err)
    )]
    pub async fn decrypt(
        &mut self,
        m: OpaqueMessage,
        seq: u64,
    ) -> Result<PlainMessage, MpcTlsError> {
        if self.total_bytes_transferred() + m.payload.0.len()
            > self.config.common().max_transcript_size()
        {
            return Err(MpcTlsError::MaxTranscriptLengthExceeded(
                self.total_bytes_transferred() + m.payload.0.len(),
                self.config.common().max_transcript_size(),
            ));
        }

        let mut payload = m.payload.0;

        let explicit_nonce: Vec<u8> = payload.drain(..8).collect();
        let ciphertext = payload;

        let aad = make_tls12_aad(seq, m.typ, m.version, ciphertext.len() - 16);

        let typ: ContentType = m.typ;

        self.channel
            .send(MpcTlsMessage::DecryptMessage(DecryptMessage {
                typ: m.typ,
                explicit_nonce: explicit_nonce.clone(),
                seq,
                ciphertext: ciphertext.clone(),
            }))
            .await?;

        // Set the transcript id depending on the type of message
        match m.typ {
            ContentType::ApplicationData => self
                .decrypter
                .set_transcript_id(self.config.common().rx_transcript_id()),
            _ => self
                .decrypter
                .set_transcript_id(self.config.common().opaque_rx_transcript_id()),
        }

        let plaintext = match typ {
            ContentType::Alert => {
                self.decrypter
                    .decrypt_public(explicit_nonce, ciphertext, aad.to_vec())
                    .await?
            }
            _ => {
                self.decrypter
                    .decrypt_private(explicit_nonce, ciphertext, aad.to_vec())
                    .await?
            }
        };

        self.conn_state.recv_bytes += plaintext.len();

        let msg = PlainMessage {
            typ: m.typ,
            version: m.version,
            payload: Payload::new(plaintext),
        };

        Ok(msg)
    }
}

#[async_trait]
impl Backend for MpcTlsLeader {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    async fn set_protocol_version(&mut self, version: ProtocolVersion) -> Result<(), BackendError> {
        self.set_protocol_version(version);

        Ok(())
    }

    async fn set_cipher_suite(&mut self, suite: SupportedCipherSuite) -> Result<(), BackendError> {
        self.set_cipher_suite(suite.suite());

        Ok(())
    }

    async fn get_suite(&mut self) -> Result<SupportedCipherSuite, BackendError> {
        todo!()
    }

    async fn set_encrypt(&mut self, _mode: EncryptMode) -> Result<(), BackendError> {
        Ok(())
    }

    async fn set_decrypt(&mut self, _mode: DecryptMode) -> Result<(), BackendError> {
        Ok(())
    }

    async fn get_client_random(&mut self) -> Result<Random, BackendError> {
        Ok(self.conn_state.client_random)
    }

    async fn get_client_key_share(&mut self) -> Result<PublicKey, BackendError> {
        let key = self.compute_client_key().await.unwrap();

        Ok(key)
    }

    async fn set_server_random(&mut self, random: Random) -> Result<(), BackendError> {
        self.set_server_random(random);

        Ok(())
    }

    async fn set_server_key_share(&mut self, key: PublicKey) -> Result<(), BackendError> {
        self.set_server_key(key)
            .map_err(|_| BackendError::InvalidServerKey)?;

        Ok(())
    }

    fn set_server_cert_details(&mut self, cert_details: ServerCertDetails) {
        self.conn_state.server_cert_details = Some(cert_details);
    }

    fn set_server_kx_details(&mut self, kx_details: ServerKxDetails) {
        self.conn_state.server_kx_details = Some(kx_details);
    }

    async fn set_hs_hash_client_key_exchange(&mut self, _hash: &[u8]) -> Result<(), BackendError> {
        Ok(())
    }

    async fn set_hs_hash_server_hello(&mut self, _hash: &[u8]) -> Result<(), BackendError> {
        Ok(())
    }

    async fn get_server_finished_vd(&mut self, hash: &[u8]) -> Result<Vec<u8>, BackendError> {
        Ok(self
            .compute_server_finished_vd(hash)
            .await
            .map_err(|e| BackendError::InternalError(e.to_string()))?)
    }

    async fn get_client_finished_vd(&mut self, hash: &[u8]) -> Result<Vec<u8>, BackendError> {
        Ok(self
            .compute_client_finished_vd(hash)
            .await
            .map_err(|e| BackendError::InternalError(e.to_string()))?)
    }

    async fn prepare_encryption(&mut self) -> Result<(), BackendError> {
        self.compute_session_keys()
            .await
            .map_err(|e| BackendError::InternalError(e.to_string()))
    }

    async fn encrypt(
        &mut self,
        msg: PlainMessage,
        seq: u64,
    ) -> Result<OpaqueMessage, BackendError> {
        self.encrypt(msg, seq)
            .map_err(|e| BackendError::EncryptionError(e.to_string()))
            .await
    }

    async fn decrypt(
        &mut self,
        msg: OpaqueMessage,
        seq: u64,
    ) -> Result<PlainMessage, BackendError> {
        self.decrypt(msg, seq)
            .map_err(|e| BackendError::DecryptionError(e.to_string()))
            .await
    }
}
