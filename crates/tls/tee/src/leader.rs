use std::{collections::VecDeque, future::Future};

use futures::{
    stream::{SplitSink, SplitStream},
    StreamExt,
};

use async_trait::async_trait;
use futures::SinkExt;

use tls_backend::{
    Backend, BackendError, BackendNotifier, BackendNotify, DecryptMode, EncryptMode,
};
use tls_core::{
    cert::ServerCertDetails,
    ke::ServerKxDetails,
    key::PublicKey,
    msgs::{
        enums::{NamedGroup, ProtocolVersion},
        handshake::Random,
        message::{OpaqueMessage, PlainMessage},
    },
    suites::{
        tls12::SerializableTls12CipherSuite, tls13::SerializableTls13CipherSuite,
        SerializableCipherSuiteCommon, SerializableSupportedCipherSuite, SupportedCipherSuite,
    },
};
use tracing::{debug, instrument, Instrument};

use crate::{
    error::Kind,
    follower::{
        ComputeClientKey, ComputeClientRandom, Decrypt, Encrypt, GetClientFinishedVd,
        ServerFinishedVd, SetCipherSuite, SetProtocolVersion, SetServerCertDetails,
        SetServerKeyShare, SetServerKxDetails, SetServerRandom, ServerClosed
    },
    msg::{CloseConnection, Commit, TeeTlsLeaderMsg, TeeTlsMessage},
    TeeTlsChannel, TeeTlsError,
};

/// Controller for Tee-TLS leader.
pub type TeeLeaderCtrl = TeeTlsLeaderCtrl<ludi::FuturesAddress<TeeTlsLeaderMsg>>;

/// Tee-TLS leader.
#[derive(ludi::Controller)]
pub struct TeeTlsLeader {
    sink: SplitSink<TeeTlsChannel, TeeTlsMessage>,
    stream: Option<SplitStream<TeeTlsChannel>>,

    /// When set, notifies the backend that there are TLS messages which need to be decrypted.
    notifier: BackendNotifier,

    /// Whether the backend is ready to decrypt messages.
    is_decrypting: bool,
    /// Messages which have been committed but not yet decrypted.
    buffer: VecDeque<OpaqueMessage>,
    /// Whether we have already committed to the transcript.
    committed: bool,
}

impl ludi::Actor for TeeTlsLeader {
    type Stop = ();
    type Error = TeeTlsError;

    async fn stopped(&mut self) -> Result<(), Self::Error> {
        debug!("Leader stopped...");

        Ok(())
    }
}

impl TeeTlsLeader {
    /// Create a new leader instance
    pub fn new(channel: TeeTlsChannel) -> Self {
        debug!("Creating a new leader...");

        let (sink, stream) = channel.split();

        Self {
            sink,
            stream: Some(stream),
            notifier: BackendNotifier::new(),
            is_decrypting: true,
            buffer: VecDeque::new(),
            committed: false,
        }
    }

    /// Performs any one-time setup operations.
    #[instrument(level = "trace", skip_all, err)]
    pub async fn setup(&mut self) -> Result<(), TeeTlsError> {
        debug!("Setting up the leader...");
        Ok(())
    }

    /// Runs the leader actor.
    ///
    /// Returns a control handle and a future that resolves when the actor is stopped.
    ///
    /// # Note
    ///
    /// The future must be polled continuously to make progress.
    pub fn run(mut self) -> (TeeLeaderCtrl, impl Future<Output = Result<(), TeeTlsError>>) {
        debug!("Running the leader...");
        let (mut mailbox, addr) = ludi::mailbox(100);

        let ctrl = TeeLeaderCtrl::from(addr);
        let fut = async move { ludi::run(&mut self, &mut mailbox).await };

        (ctrl, fut.in_current_span())
    }

    /// Returns the number of bytes sent and received.
    pub fn bytes_transferred(&self) -> (usize, usize) {
        (0, 0)
    }

    async fn commit(&mut self) -> Result<(), TeeTlsError> {
        debug!("Leader Committing...");
        Ok(())
    }
}

#[ludi::implement(msg(name = "{name}"), ctrl(err))]
impl TeeTlsLeader {
    /// Closes the connection.
    #[instrument(level = "trace", skip_all, err)]
    #[msg(skip, name = "CloseConnection")]
    pub async fn close_connection(&mut self) -> Result<(), TeeTlsError> {
        debug!("Leader closing the connection...");
        self.sink
            .send(TeeTlsMessage::CloseConnection(CloseConnection))
            .await?;

        ctx.stop();

        Ok(())
    }

    /// Defers decryption of any incoming messages.
    pub async fn defer_decryption(&mut self) -> Result<(), TeeTlsError> {
        Ok(())
    }

   #[instrument(level = "trace", skip_all, err)]
    #[msg(skip, name = "Commit")]
    pub async fn commit(&mut self) -> Result<(), TeeTlsError> {
        self.commit().await
    }
}

#[ludi::implement]
#[ctrl(err = "TeeTlsError::from")]
#[msg(foreign, wrap, vis = "pub")]
#[async_trait]
impl Backend for TeeTlsLeader {
    async fn set_protocol_version(&mut self, version: ProtocolVersion) -> Result<(), BackendError> {
        debug!("Leader setting the protocol version {:?}", version);

        self.sink
            .send(TeeTlsMessage::SetProtocolVersion(SetProtocolVersion {
                msg: version,
            }))
            .await
            .map_err(TeeTlsError::from)?;

        Ok(())
    }

    async fn set_cipher_suite(&mut self, suite: SupportedCipherSuite) -> Result<(), BackendError> {
        debug!("Leader setting the cipher suite to {:?}", suite.suite());
        let sscs: SerializableSupportedCipherSuite = match suite {
            SupportedCipherSuite::Tls13(s) => {
                SerializableSupportedCipherSuite::Tls13(SerializableTls13CipherSuite {
                    common: SerializableCipherSuiteCommon {
                        suite: s.common.suite,
                        aead_algorithm: s.common.aead_algorithm.clone(),
                    },
                    hkdf_algorithm: s.hkdf_algorithm.clone(),
                })
            }
            SupportedCipherSuite::Tls12(s) => {
                SerializableSupportedCipherSuite::Tls12(SerializableTls12CipherSuite {
                    common: SerializableCipherSuiteCommon {
                        suite: s.common.suite,
                        aead_algorithm: s.common.aead_algorithm.clone(),
                    },
                    kx: s.kx.clone(),
                    sign: s.sign.to_vec(),
                    fixed_iv_len: s.fixed_iv_len,
                    explicit_nonce_len: s.explicit_nonce_len,
                    hmac_algorithm: s.hash_algorithm().clone(),
                })
            }
        };

        self.sink
            .send(TeeTlsMessage::SetCipherSuite(SetCipherSuite { msg: sscs }))
            .await
            .map_err(TeeTlsError::from)?;

        Ok(())
    }

    async fn get_suite(&mut self) -> Result<SupportedCipherSuite, BackendError> {
        debug!("Leader getting the cipher suite...");

        unimplemented!()
    }

    async fn set_encrypt(&mut self, mode: EncryptMode) -> Result<(), BackendError> {
        debug!("Leader setting the encryption mode...");
        unimplemented!()
    }

    async fn set_decrypt(&mut self, mode: DecryptMode) -> Result<(), BackendError> {
        debug!("Leader setting the decryption mode...");
        unimplemented!()
    }

    async fn get_client_random(&mut self) -> Result<Random, BackendError> {
        // fetch remote attestation from follower
        // verify remote attestation
        debug!("Leader getting the client random...");
        self.sink
            .send(TeeTlsMessage::ComputeClientRandom(ComputeClientRandom {
                msg: None,
            }))
            .await
            .map_err(TeeTlsError::from)?;

        let stream = self.stream.as_mut().unwrap();

        while let Some(msg) = stream.next().await {
            let msg = msg.unwrap();
            let msg: TeeTlsMessage = TeeTlsMessage::try_from(msg).unwrap();
            if let TeeTlsMessage::ComputeClientRandom(rnd) = msg {
                return Ok(rnd.msg.unwrap());
            }
        }
        Err(TeeTlsError::new(
            Kind::PeerMisbehaved,
            "ComputeClientRandom message not received",
        )
        .into())
    }

    async fn get_client_key_share(&mut self) -> Result<PublicKey, BackendError> {
        debug!("Leader getting the client key share...");
        self.sink
            .send(TeeTlsMessage::ComputeClientKey(ComputeClientKey {
                msg: vec![0],
            }))
            .await
            .map_err(TeeTlsError::from)?;
        let stream = self.stream.as_mut().unwrap();

        while let Some(msg) = stream.next().await {
            let msg = msg.unwrap();
            let msg: TeeTlsMessage = TeeTlsMessage::try_from(msg).unwrap();
            if let TeeTlsMessage::ComputeClientKey(cck) = msg {
                return Ok(PublicKey::new(NamedGroup::secp256r1, &cck.msg));
            }
        }
        Err(TeeTlsError::new(
            Kind::PeerMisbehaved,
            "ComputeClientKey message not received",
        )
        .into())
    }

    async fn set_server_random(&mut self, random: Random) -> Result<(), BackendError> {
        debug!("Leader setting the server random {:?}", random);

        self.sink
            .send(TeeTlsMessage::SetServerRandom(SetServerRandom {
                msg: random,
            }))
            .await
            .map_err(TeeTlsError::from)?;

        Ok(())
    }

    async fn set_server_key_share(&mut self, key: PublicKey) -> Result<(), BackendError> {
        debug!("Leader setting the server key share...");

        self.sink
            .send(TeeTlsMessage::SetServerKeyShare(SetServerKeyShare {
                msg: key.clone(),
            }))
            .await
            .map_err(TeeTlsError::from)?;
        Ok(())
    }

    async fn set_server_cert_details(
        &mut self,
        cert_details: ServerCertDetails,
    ) -> Result<(), BackendError> {
        debug!("Leader setting the server cert details");

        self.sink
            .send(TeeTlsMessage::SetServerCertDetails(SetServerCertDetails {
                msg: cert_details.clone(),
            }))
            .await
            .map_err(TeeTlsError::from)?;

        Ok(())
    }

    async fn set_server_kx_details(
        &mut self,
        kx_details: ServerKxDetails,
    ) -> Result<(), BackendError> {
        debug!("Leader setting the server key exchange details...");

        self.sink
            .send(TeeTlsMessage::SetServerKxDetails(SetServerKxDetails {
                msg: kx_details.clone(),
            }))
            .await
            .map_err(TeeTlsError::from)?;

        Ok(())
    }

    async fn set_hs_hash_client_key_exchange(&mut self, hash: Vec<u8>) -> Result<(), BackendError> {
        debug!("Leader setting the client key exchange hash...");
        Ok(())
    }

    async fn set_hs_hash_server_hello(&mut self, hash: Vec<u8>) -> Result<(), BackendError> {
        debug!("Leader setting the server hello hash...");

        Ok(())
    }

    async fn get_server_finished_vd(&mut self, hash: Vec<u8>) -> Result<Vec<u8>, BackendError> {
        debug!("Leader getting the server finished VD...");
        self.sink
            .send(TeeTlsMessage::ServerFinishedVd(ServerFinishedVd {
                msg: hash,
            }))
            .await
            .map_err(|e| BackendError::InternalError(e.to_string()))?;

        let stream = self.stream.as_mut().unwrap();

        while let Some(msg) = stream.next().await {
            let msg = msg.unwrap();
            let msg: TeeTlsMessage = TeeTlsMessage::try_from(msg).unwrap();
            if let TeeTlsMessage::ServerFinishedVd(sfvd) = msg {
                return Ok(sfvd.msg);
            }
        }
        Err(TeeTlsError::new(
            Kind::PeerMisbehaved,
            "ServerFinishedVD message not received",
        )
        .into())
    }

    async fn get_client_finished_vd(&mut self, hash: Vec<u8>) -> Result<Vec<u8>, BackendError> {
        debug!("Leader getting the client finished VD...");
        self.sink
            .send(TeeTlsMessage::GetClientFinishedVd(GetClientFinishedVd {
                msg: hash,
            }))
            .await
            .map_err(|e| BackendError::InternalError(e.to_string()))?;

        let stream = self.stream.as_mut().unwrap();

        while let Some(msg) = stream.next().await {
            let msg = msg.unwrap();
            let msg: TeeTlsMessage = TeeTlsMessage::try_from(msg).unwrap();
            if let TeeTlsMessage::GetClientFinishedVd(cfvd) = msg {
                return Ok(cfvd.msg);
            }
        }
        Err(TeeTlsError::new(
            Kind::PeerMisbehaved,
            "ComputeClientKey message not received",
        )
        .into())
    }

    async fn prepare_encryption(&mut self) -> Result<(), BackendError> {
        debug!("Leader preparing the encryption...");
        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
    async fn encrypt(
        &mut self,
        msg: PlainMessage,
        seq: u64,
    ) -> Result<OpaqueMessage, BackendError> {
        debug!("Leader encrypting the message...");
        self.sink
            .send(TeeTlsMessage::Encrypt(Encrypt {
                msg: Some(msg),
                seq: Some(seq),
                opq: None,
            }))
            .await
            .map_err(|e| BackendError::InternalError(e.to_string()))?;

        let stream = self.stream.as_mut().unwrap();

        while let Some(msg) = stream.next().await {
            let msg = msg.unwrap();
            let msg: TeeTlsMessage = TeeTlsMessage::try_from(msg).unwrap();
            if let TeeTlsMessage::Encrypt(opq) = msg {
                return Ok(opq.opq.unwrap());
            }
        }
        Err(TeeTlsError::new(Kind::PeerMisbehaved, "Encrypted message not received").into())
    }

    async fn decrypt(
        &mut self,
        opq: OpaqueMessage,
        seq: u64,
    ) -> Result<PlainMessage, BackendError> {
        debug!("Leader decrypting the message...");
        self.sink
            .send(TeeTlsMessage::Decrypt(Decrypt {
                opq: Some(opq),
                seq: Some(seq),
                msg: None,
            }))
            .await
            .map_err(|e| BackendError::InternalError(e.to_string()))?;

        let stream = self.stream.as_mut().unwrap();

        while let Some(msg) = stream.next().await {
            let msg = msg.unwrap();
            let msg: TeeTlsMessage = TeeTlsMessage::try_from(msg).unwrap();
            if let TeeTlsMessage::Decrypt(msg) = msg {
                return Ok(msg.msg.unwrap());
            }
        }
        Err(TeeTlsError::new(Kind::PeerMisbehaved, "Decrypted message not received").into())
    }

    async fn buffer_incoming(&mut self, msg: OpaqueMessage) -> Result<(), BackendError> {
        debug!("Leader buffering the incoming message...");
        if self.committed {
            return Err(BackendError::InternalError(
                "cannot buffer messages after committing to transcript".to_string(),
            ));
        }

        self.buffer.push_back(msg);

        if self.is_decrypting {
            self.notifier.set();
        }

        Ok(())
    }

    async fn next_incoming(&mut self) -> Result<Option<OpaqueMessage>, BackendError> {
        debug!("Leader getting the next incoming message...");
        if !self.is_decrypting {
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
        debug!("Leader server closed...");
        self.sink
            .send(TeeTlsMessage::ServerClosed(ServerClosed))
            .await
            .map_err(|e| BackendError::InternalError(e.to_string()))?;
        Ok(())
    }
}
