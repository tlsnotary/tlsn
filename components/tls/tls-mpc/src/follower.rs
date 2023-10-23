use futures::StreamExt;

use hmac_sha256 as prf;
use key_exchange as ke;
use mpz_core::hash::Hash;
use mpz_garble::ValueRef;

use p256::elliptic_curve::sec1::ToEncodedPoint;
use prf::SessionKeys;

use aead::Aead;
use hmac_sha256::Prf;
use ke::KeyExchange;
use tls_core::{
    cipher::make_tls12_aad,
    key::PublicKey,
    msgs::{
        alert::AlertMessagePayload,
        codec::Codec,
        enums::{AlertDescription, AlertLevel, ContentType, NamedGroup, ProtocolVersion},
    },
};
use utils_aio::expect_msg_or_err;

use crate::{
    msg::{DecryptMessage, EncryptMessage, MpcTlsMessage},
    MpcTlsChannel, MpcTlsError, MpcTlsFollowerConfig,
};

/// The follower of the MPC TLS protocol.
pub struct MpcTlsFollower {
    config: MpcTlsFollowerConfig,
    channel: MpcTlsChannel,

    ke: Box<dyn KeyExchange + Send>,
    prf: Box<dyn Prf + Send>,
    encrypter: Encrypter,
    decrypter: Decrypter,

    handshake_commitment: Option<Hash>,

    closed: bool,
}

impl MpcTlsFollower {
    /// Create a new follower instance
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "debug", skip(channel, ke, prf, encrypter, decrypter))
    )]
    pub fn new(
        config: MpcTlsFollowerConfig,
        channel: MpcTlsChannel,
        ke: Box<dyn KeyExchange + Send>,
        prf: Box<dyn Prf + Send>,
        encrypter: Box<dyn Aead + Send>,
        decrypter: Box<dyn Aead + Send>,
    ) -> Self {
        let encrypter = Encrypter {
            aead: encrypter,
            seq: 0,
            sent_bytes: 0,
            transcript_id: config.common().tx_transcript_id().to_string(),
            opaque_transcript_id: config.common().opaque_tx_transcript_id().to_string(),
        };

        let decrypter = Decrypter {
            aead: decrypter,
            seq: 0,
            recv_bytes: 0,
            transcript_id: config.common().rx_transcript_id().to_string(),
            opaque_transcript_id: config.common().opaque_rx_transcript_id().to_string(),
        };

        Self {
            config,
            channel,
            ke,
            prf,
            encrypter,
            decrypter,
            handshake_commitment: None,
            closed: false,
        }
    }

    /// Performs any one-time setup operations.
    pub async fn setup(&mut self) -> Result<(), MpcTlsError> {
        self.prf.setup().await?;

        Ok(())
    }

    /// Returns the amount of application data sent and received.
    pub fn bytes_transferred(&self) -> (usize, usize) {
        (self.encrypter.sent_bytes(), self.decrypter.recv_bytes())
    }

    /// Returns the total number of bytes sent and received.
    fn total_bytes_transferred(&self) -> usize {
        self.encrypter.sent_bytes() + self.decrypter.recv_bytes()
    }

    /// Returns the server's public key
    pub fn server_key(&self) -> Option<PublicKey> {
        self.ke.server_key().map(|key| {
            PublicKey::new(
                NamedGroup::secp256r1,
                key.to_encoded_point(false).as_bytes(),
            )
        })
    }

    /// Returns the leader's handshake commitment
    pub fn handshake_commitment(&self) -> Option<Hash> {
        self.handshake_commitment
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip(self), err)
    )]
    async fn run_key_exchange(&mut self) -> Result<(), MpcTlsError> {
        // Key exchange
        _ = self
            .ke
            .compute_client_key(p256::SecretKey::random(&mut rand::rngs::OsRng))
            .await?;

        if self.config.common().handshake_commit() {
            let handshake_commitment =
                expect_msg_or_err!(self.channel, MpcTlsMessage::HandshakeCommitment)?;

            self.handshake_commitment = Some(handshake_commitment);
        }

        let pms = self.ke.compute_pms().await?;

        // PRF
        let SessionKeys {
            client_write_key,
            server_write_key,
            client_iv,
            server_iv,
        } = self
            .prf
            .compute_session_keys_blind(pms.into_value())
            .await?;

        self.encrypter.set_key(client_write_key, client_iv).await?;
        self.decrypter.set_key(server_write_key, server_iv).await?;

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip(self), err)
    )]
    async fn run_client_finished(&mut self) -> Result<(), MpcTlsError> {
        self.prf.compute_client_finished_vd_blind().await?;

        let EncryptMessage { typ, seq, len } =
            expect_msg_or_err!(self.channel, MpcTlsMessage::EncryptMessage)?;

        if typ != ContentType::Handshake {
            return Err(MpcTlsError::UnexpectedContentType(typ));
        }

        self.encrypter.encrypt_blind(typ, seq, len).await?;

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip(self), err)
    )]
    async fn run_server_finished(&mut self) -> Result<(), MpcTlsError> {
        let DecryptMessage {
            typ,
            explicit_nonce,
            ciphertext,
            seq,
        } = expect_msg_or_err!(self.channel, MpcTlsMessage::DecryptMessage)?;

        if typ != ContentType::Handshake {
            return Err(MpcTlsError::UnexpectedContentType(typ));
        }

        self.decrypter
            .decrypt_blind(typ, explicit_nonce, ciphertext, seq)
            .await?;

        self.prf.compute_server_finished_vd_blind().await?;

        Ok(())
    }

    async fn handle_encrypt_msg(&mut self, msg: EncryptMessage) -> Result<(), MpcTlsError> {
        let EncryptMessage { typ, seq, len } = msg;

        if self.total_bytes_transferred() + len > self.config.common().max_transcript_size() {
            return Err(MpcTlsError::MaxTranscriptLengthExceeded(
                self.total_bytes_transferred() + len,
                self.config.common().max_transcript_size(),
            ));
        }

        self.encrypter.encrypt_blind(typ, seq, len).await
    }

    async fn handle_decrypt_msg(&mut self, msg: DecryptMessage) -> Result<(), MpcTlsError> {
        let DecryptMessage {
            typ,
            explicit_nonce,
            ciphertext,
            seq,
        } = msg;

        if self.total_bytes_transferred() + ciphertext.len()
            > self.config.common().max_transcript_size()
        {
            return Err(MpcTlsError::MaxTranscriptLengthExceeded(
                self.total_bytes_transferred() + ciphertext.len(),
                self.config.common().max_transcript_size(),
            ));
        }

        match typ {
            ContentType::ApplicationData => {
                self.decrypter
                    .decrypt_blind(typ, explicit_nonce, ciphertext, seq)
                    .await
            }
            ContentType::Alert => {
                let bytes = self
                    .decrypter
                    .decrypt_public(typ, explicit_nonce, ciphertext, seq)
                    .await?;

                let alert = AlertMessagePayload::read_bytes(&bytes)
                    .ok_or(MpcTlsError::PayloadDecodingError)?;

                if alert.level == AlertLevel::Fatal {
                    return Err(MpcTlsError::ReceivedFatalAlert);
                }

                if alert.description == AlertDescription::CloseNotify {
                    self.closed = true;
                }

                Ok(())
            }
            typ => Err(MpcTlsError::UnexpectedContentType(typ)),
        }
    }

    async fn handle_close_notify(&mut self, msg: EncryptMessage) -> Result<(), MpcTlsError> {
        let EncryptMessage { typ, seq, len } = msg;

        // We could use `encrypt_public` here, but it is not required.
        self.encrypter.encrypt_blind(typ, seq, len).await
    }

    /// Runs the follower instance
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip(self), err)
    )]
    pub async fn run(&mut self) -> Result<(), MpcTlsError> {
        self.run_key_exchange().await?;
        self.run_client_finished().await?;
        self.run_server_finished().await?;

        loop {
            let msg = match self.channel.next().await {
                Some(msg) => msg?,
                None => return Err(MpcTlsError::LeaderClosedAbruptly),
            };

            match msg {
                MpcTlsMessage::EncryptMessage(msg) => {
                    self.handle_encrypt_msg(msg).await?;
                }
                MpcTlsMessage::DecryptMessage(msg) => {
                    self.handle_decrypt_msg(msg).await?;
                }
                MpcTlsMessage::SendCloseNotify(msg) => {
                    self.handle_close_notify(msg).await?;
                }
                msg => {
                    return Err(MpcTlsError::UnexpectedMessage(msg));
                }
            }

            if self.closed {
                break;
            }
        }

        Ok(())
    }
}

struct Encrypter {
    aead: Box<dyn aead::Aead>,
    seq: u64,
    sent_bytes: usize,
    transcript_id: String,
    opaque_transcript_id: String,
}

impl Encrypter {
    fn sent_bytes(&self) -> usize {
        self.sent_bytes
    }

    async fn set_key(&mut self, key: ValueRef, iv: ValueRef) -> Result<(), MpcTlsError> {
        self.aead.set_key(key, iv).await?;

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip(self), err)
    )]
    async fn encrypt_blind(
        &mut self,
        typ: ContentType,
        seq: u64,
        len: usize,
    ) -> Result<(), MpcTlsError> {
        // Set the transcript id depending on the type of message
        match typ {
            ContentType::ApplicationData => {
                self.aead.set_transcript_id(&self.transcript_id);
                self.sent_bytes += len;
            }
            _ => self.aead.set_transcript_id(&self.opaque_transcript_id),
        }

        if seq != self.seq {
            return Err(MpcTlsError::UnexpectedSequenceNumber(seq));
        }

        self.seq += 1;

        let explicit_nonce = seq.to_be_bytes().to_vec();
        let aad = make_tls12_aad(seq, typ, ProtocolVersion::TLSv1_2, len);

        self.aead
            .encrypt_blind(explicit_nonce, len, aad.to_vec())
            .await?;

        Ok(())
    }
}

struct Decrypter {
    aead: Box<dyn aead::Aead>,
    seq: u64,
    recv_bytes: usize,
    transcript_id: String,
    opaque_transcript_id: String,
}

impl Decrypter {
    fn recv_bytes(&self) -> usize {
        self.recv_bytes
    }

    async fn set_key(&mut self, key: ValueRef, iv: ValueRef) -> Result<(), MpcTlsError> {
        self.aead.set_key(key, iv).await?;

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip(self), err)
    )]
    async fn decrypt_blind(
        &mut self,
        typ: ContentType,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        seq: u64,
    ) -> Result<(), MpcTlsError> {
        let len = ciphertext.len() - 16;

        self.prepare_decrypt(typ, seq, len)?;

        let aad = make_tls12_aad(seq, typ, ProtocolVersion::TLSv1_2, len);
        self.aead
            .decrypt_blind(explicit_nonce, ciphertext, aad.to_vec())
            .await?;

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip(self), err)
    )]
    async fn decrypt_public(
        &mut self,
        typ: ContentType,
        explicit_nonce: Vec<u8>,
        ciphertext: Vec<u8>,
        seq: u64,
    ) -> Result<Vec<u8>, MpcTlsError> {
        let len = ciphertext.len() - 16;

        self.prepare_decrypt(typ, seq, len)?;

        let aad = make_tls12_aad(seq, typ, ProtocolVersion::TLSv1_2, len);
        let plaintext = self
            .aead
            .decrypt_public(explicit_nonce, ciphertext, aad.to_vec())
            .await?;

        Ok(plaintext)
    }

    fn prepare_decrypt(
        &mut self,
        typ: ContentType,
        seq: u64,
        len: usize,
    ) -> Result<(), MpcTlsError> {
        // Set the transcript id depending on the type of message
        match typ {
            ContentType::ApplicationData => {
                self.aead.set_transcript_id(&self.transcript_id);
                self.recv_bytes += len;
            }
            _ => self.aead.set_transcript_id(&self.opaque_transcript_id),
        }

        if seq != self.seq {
            return Err(MpcTlsError::UnexpectedSequenceNumber(seq));
        }

        self.seq += 1;

        Ok(())
    }
}
