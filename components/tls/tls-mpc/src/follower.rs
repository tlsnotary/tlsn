use std::collections::VecDeque;

use futures::StreamExt;

use hmac_sha256 as prf;
use key_exchange as ke;
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
        codec::Codec,
        enums::{AlertDescription, AlertLevel, ContentType, NamedGroup},
        message::OpaqueMessage,
    },
};
use utils_aio::stream::ExpectStreamExt;

use crate::{
    msg::{EncryptMessage, MpcTlsMessage},
    record_layer::{Decrypter, Encrypter},
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

    buf: VecDeque<OpaqueMessage>,

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
            ke,
            prf,
            encrypter,
            decrypter,
            handshake_commitment: None,
            buf: VecDeque::new(),
            closed: false,
        }
    }

    /// Performs any one-time setup operations.
    pub async fn setup(&mut self) -> Result<(), MpcTlsError> {
        let pms = self.ke.setup().await?;
        self.prf.setup(pms.into_value()).await?;

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
            let handshake_commitment = self
                .channel
                .expect_next()
                .await?
                .try_into_handshake_commitment()?;

            self.handshake_commitment = Some(handshake_commitment);
        }

        self.ke.compute_pms().await?;

        // PRF
        let SessionKeys {
            client_write_key,
            server_write_key,
            client_iv,
            server_iv,
        } = self.prf.compute_session_keys_blind().await?;

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

        let EncryptMessage { typ, version, len } = self
            .channel
            .expect_next()
            .await?
            .try_into_encrypt_message()?;

        if typ != ContentType::Handshake {
            return Err(MpcTlsError::UnexpectedContentType(typ));
        }

        self.encrypter.encrypt_blind(typ, version, len).await?;

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip(self), err)
    )]
    async fn run_server_finished(&mut self) -> Result<(), MpcTlsError> {
        let msg = self
            .channel
            .expect_next()
            .await?
            .try_into_commit_message()?;

        self.channel
            .expect_next()
            .await?
            .try_into_decrypt_message()?;

        if msg.typ != ContentType::Handshake {
            return Err(MpcTlsError::UnexpectedContentType(msg.typ));
        }

        self.decrypter.decrypt_blind(msg).await?;

        self.prf.compute_server_finished_vd_blind().await?;

        Ok(())
    }

    async fn handle_encrypt_msg(&mut self, msg: EncryptMessage) -> Result<(), MpcTlsError> {
        let EncryptMessage { typ, version, len } = msg;

        if self.total_bytes_transferred() + len > self.config.common().max_transcript_size() {
            return Err(MpcTlsError::MaxTranscriptLengthExceeded(
                self.total_bytes_transferred() + len,
                self.config.common().max_transcript_size(),
            ));
        }

        self.encrypter.encrypt_blind(typ, version, len).await
    }

    async fn handle_commit_msg(&mut self, msg: OpaqueMessage) -> Result<(), MpcTlsError> {
        if self.total_bytes_transferred() + msg.payload.0.len()
            > self.config.common().max_transcript_size()
        {
            return Err(MpcTlsError::MaxTranscriptLengthExceeded(
                self.total_bytes_transferred() + msg.payload.0.len(),
                self.config.common().max_transcript_size(),
            ));
        }

        self.buf.push_front(msg);

        Ok(())
    }

    async fn handle_decrypt_msg(&mut self) -> Result<(), MpcTlsError> {
        let msg = self.buf.pop_back().ok_or(MpcTlsError::NoCommittedMessage)?;

        match msg.typ {
            ContentType::ApplicationData => {
                self.decrypter.decrypt_blind(msg).await?;
            }
            ContentType::Alert => {
                let msg = self.decrypter.decrypt_public(msg).await?;

                let alert = AlertMessagePayload::read_bytes(&msg.payload.0)
                    .ok_or(MpcTlsError::PayloadDecodingError)?;

                if alert.level == AlertLevel::Fatal {
                    return Err(MpcTlsError::ReceivedFatalAlert);
                }

                if alert.description == AlertDescription::CloseNotify {
                    self.closed = true;
                }
            }
            typ => return Err(MpcTlsError::UnexpectedContentType(typ)),
        }

        Ok(())
    }

    async fn handle_close_notify(&mut self, msg: EncryptMessage) -> Result<(), MpcTlsError> {
        let EncryptMessage { typ, version, len } = msg;

        // We could use `encrypt_public` here, but it is not required.
        self.encrypter.encrypt_blind(typ, version, len).await
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
                MpcTlsMessage::CommitMessage(msg) => {
                    self.handle_commit_msg(msg).await?;
                }
                MpcTlsMessage::DecryptMessage => {
                    self.handle_decrypt_msg().await?;
                }
                MpcTlsMessage::SendCloseNotify(msg) => {
                    self.handle_close_notify(msg).await?;
                }
                msg => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("unexpected message: {:?}", msg),
                    ))?;
                }
            }

            if self.closed {
                break;
            }
        }

        Ok(())
    }
}
