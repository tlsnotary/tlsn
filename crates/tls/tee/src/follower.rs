use std::future::Future;

use futures::{
    stream::{SplitSink, SplitStream},
    FutureExt, SinkExt, StreamExt,
};

use ludi::{Address, FuturesAddress};

use mpz_core::serialize::CanonicalSerialize;
use serde::{Deserialize, Serialize};
use tls_client::{Backend, RustCryptoBackend, SignatureScheme, SupportedCipherSuite};
use tls_core::{
    cert::ServerCertDetails,
    ke::ServerKxDetails,
    key::PublicKey,
    msgs::{
        alert::AlertMessagePayload,
        codec::Codec,
        enums::{AlertDescription, ProtocolVersion},
        handshake::Random,
        message::{OpaqueMessage, PlainMessage},
    },
    suites::{
        AEADAlgorithm, CipherSuiteCommon, HashAlgorithm, SerializableSupportedCipherSuite,
        Tls12CipherSuite, Tls13CipherSuite,
    },
};

use crate::{
    error::Kind,
    msg::{CloseConnection, Commit, TeeTlsFollowerMsg, TeeTlsMessage},
    TeeTlsChannel, TeeTlsError,
};
use tls_core::msgs::enums::ContentType as TlsMessageType;
/// Controller for Tee-TLS follower.
pub type TeeFollowerCtrl = TeeTlsFollowerCtrl<FuturesAddress<TeeTlsFollowerMsg>>;

/// Tee-TLS follower.
#[derive(ludi::Controller)]
pub struct TeeTlsFollower {
    sink: SplitSink<TeeTlsChannel, TeeTlsMessage>,
    stream: Option<SplitStream<TeeTlsChannel>>,

    rcb: RustCryptoBackend,

    /// Whether the server has sent a CloseNotify alert.
    close_notify: bool,
    /// Whether the leader has committed to the transcript.
    committed: bool,
}

impl ludi::Actor for TeeTlsFollower {
    type Stop = ();
    type Error = TeeTlsError;

    async fn stopped(&mut self) -> Result<Self::Stop, Self::Error> {
        println!("Follower stopped...");
        Ok(())
    }
}

impl TeeTlsFollower {
    /// Create a new follower instance
    pub fn new(channel: TeeTlsChannel) -> Self {
        println!("Creating a new follower...");

        let (sink, stream) = channel.split();
        Self {
            sink,
            rcb: RustCryptoBackend::new(),
            stream: Some(stream),
            close_notify: false,
            committed: false,
        }
    }

    /// Performs any one-time setup operations.
    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    pub async fn setup(&mut self) -> Result<(), TeeTlsError> {
        println!("Setting up the follower...");
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
        TeeFollowerCtrl,
        impl Future<Output = Result<(), TeeTlsError>>,
    ) {
        println!("Running the follower...");
        let (mut mailbox, addr) = ludi::mailbox::<TeeTlsFollowerMsg>(100);
        let ctrl = TeeFollowerCtrl::from(addr.clone());

        let mut stream = self
            .stream
            .take()
            .expect("stream should be present from constructor");

        let mut remote_fut = Box::pin(async move {
            while let Some(msg) = stream.next().await {
                let msg = TeeTlsFollowerMsg::try_from(msg?)?;
                addr.send_await(msg).await?;
            }

            Ok::<_, TeeTlsError>(())
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

    /// Returns an error if the follower is not accepting new messages.
    ///
    /// This can happen if the follower has received a CloseNotify alert or if the leader has
    /// committed to the transcript.
    fn is_accepting_messages(&self) -> Result<(), TeeTlsError> {
        println!("Checking if the follower is accepting messages...");
        if self.close_notify {
            return Err(TeeTlsError::new(
                Kind::PeerMisbehaved,
                "attempted to commit a message after receiving CloseNotify",
            ));
        }

        if self.committed {
            return Err(TeeTlsError::new(
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
    async fn get_client_finished_vd(&mut self, hash: Vec<u8>) -> Result<Vec<u8>, TeeTlsError> {
        println!("Follower getting the client finished VD...");
        let verify_data = self
            .rcb
            .get_client_finished_vd(hash)
            .await
            .map_err(|e| {
                TeeTlsError::new(
                    Kind::Other,
                    format!("Failed to get client finished VD: {:?}", e),
                )
            })
            .unwrap();
        self.sink
            .send(TeeTlsMessage::GetClientFinishedVd(GetClientFinishedVd {
                msg: verify_data.to_vec(),
            }))
            .await?;
        Ok(verify_data.to_vec())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    async fn set_server_key_share(&mut self, key_share: PublicKey) -> Result<(), TeeTlsError> {
        println!("Follower setting the server key share");
        self.rcb
            .set_server_key_share(key_share.clone())
            .await
            .map_err(|e| {
                TeeTlsError::new(
                    Kind::Other,
                    format!("Failed to set server key share: {:?}", e),
                )
            })?;

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    async fn set_server_kx_details(
        &mut self,
        kx_details: ServerKxDetails,
    ) -> Result<(), TeeTlsError> {
        println!("Follower setting the server key exchange details");
        self.rcb
            .set_server_kx_details(kx_details.clone())
            .await
            .map_err(|e| {
                TeeTlsError::new(
                    Kind::Other,
                    format!("Failed to set server kx details: {:?}", e),
                )
            })?;

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    async fn set_server_cert_details(
        &mut self,
        cert_details: ServerCertDetails,
    ) -> Result<(), TeeTlsError> {
        println!("Follower setting the server cert details");
        self.rcb
            .set_server_cert_details(cert_details.clone())
            .await
            .map_err(|e| {
                TeeTlsError::new(
                    Kind::Other,
                    format!("Failed to set server cert details: {:?}", e),
                )
            })?;

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    async fn set_server_random(&mut self, random: Random) -> Result<(), TeeTlsError> {
        println!("Follower setting the server random to {:?}", random);
        self.rcb
            .set_server_random(random.clone())
            .await
            .map_err(|e| {
                TeeTlsError::new(Kind::Other, format!("Failed to set server random: {:?}", e))
            })?;
        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    async fn set_cipher_suite(
        &mut self,
        suite: SerializableSupportedCipherSuite,
    ) -> Result<(), TeeTlsError> {
        let scs = match suite {
            SerializableSupportedCipherSuite::Tls13(sscs) => {
                let aead: &'static AEADAlgorithm = Box::leak(Box::new(sscs.common.aead_algorithm));
                let tls13: &'static Tls13CipherSuite = Box::leak(Box::new(Tls13CipherSuite {
                    common: CipherSuiteCommon {
                        suite: sscs.common.suite,
                        aead_algorithm: aead,
                    },
                    hkdf_algorithm: sscs.hkdf_algorithm,
                }));
                SupportedCipherSuite::Tls13(tls13)
            }
            SerializableSupportedCipherSuite::Tls12(sscs) => {
                let aead: &'static AEADAlgorithm = Box::leak(Box::new(sscs.common.aead_algorithm));
                let hmac: &'static HashAlgorithm = Box::leak(Box::new(sscs.hmac_algorithm));
                let sign: &'static [SignatureScheme] = Box::leak(Box::new(sscs.sign));
                let tls12: &'static Tls12CipherSuite = Box::leak(Box::new(Tls12CipherSuite {
                    common: CipherSuiteCommon {
                        suite: sscs.common.suite,
                        aead_algorithm: aead,
                    },
                    hmac_algorithm: hmac,
                    kx: sscs.kx,
                    sign: sign,
                    fixed_iv_len: sscs.fixed_iv_len,
                    explicit_nonce_len: sscs.explicit_nonce_len,
                }));
                SupportedCipherSuite::Tls12(tls12)
            }
        };
        println!("Follower setting the cipher suite to {:?}", scs);
        self.rcb.set_cipher_suite(scs).await.map_err(|e| {
            TeeTlsError::new(Kind::Other, format!("Failed to set cipher suite: {:?}", e))
        })?;

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    async fn set_protocol_version(&mut self, version: ProtocolVersion) -> Result<(), TeeTlsError> {
        println!("Follower setting the protocol version to {:?}", version);

        self.rcb.set_protocol_version(version).await.map_err(|e| {
            TeeTlsError::new(
                Kind::Other,
                format!("Failed to set protocol version: {:?}", e),
            )
        })?;
        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    async fn compute_client_random(&mut self, _msg: Option<Random>) -> Result<(), TeeTlsError> {
        println!("Follower computing the client random...");
        let rnd = self.rcb.get_client_random().await.map_err(|e| {
            TeeTlsError::new(Kind::Other, format!("Failed to get client random: {:?}", e))
        })?;
        self.sink
            .send(TeeTlsMessage::ComputeClientRandom(ComputeClientRandom {
                msg: Some(rnd),
            }))
            .await?;

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    async fn compute_client_key(&mut self, _pk: Vec<u8>) -> Result<(), TeeTlsError> {
        println!("Follower computing the client key share...");
        let pk = self.rcb.get_client_key_share().await.map_err(|e| {
            TeeTlsError::new(
                Kind::Other,
                format!("Failed to get client key share: {:?}", e),
            )
        })?;

        self.sink
            .send(TeeTlsMessage::ComputeClientKey(ComputeClientKey {
                msg: pk.key.to_vec(),
            }))
            .await?;

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    async fn server_finished_vd(&mut self, hash: Vec<u8>) -> Result<(), TeeTlsError> {
        println!("Follower setting the server finished VD...");
        let verify_data = self.rcb.get_server_finished_vd(hash).await.map_err(|e| {
            TeeTlsError::new(
                Kind::Other,
                format!("Failed to get server finished VD: {:?}", e),
            )
        })?;

        self.sink
            .send(TeeTlsMessage::ServerFinishedVd(ServerFinishedVd {
                msg: verify_data.to_vec(),
            }))
            .await?;
        // });

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    async fn decrypt(
        &mut self,
        opq: Option<OpaqueMessage>,
        seq: Option<u64>,
        _msg: Option<PlainMessage>,
    ) -> Result<(), TeeTlsError> {
        println!("Follower decrypting the message...");

        match (opq, seq) {
            (Some(opq), Some(seq)) => {
                let msg = self.rcb.decrypt(opq, seq).await.map_err(|e| {
                    TeeTlsError::new(Kind::Other, format!("Failed to decrypt message: {:?}", e))
                })?;

                // Convert msg.payload to string
                if (msg.typ == TlsMessageType::ApplicationData) {
                    let payload_bytes = msg.payload.to_bytes();
                    let payload_string = String::from_utf8_lossy(&payload_bytes).to_string();
                    println!("Decrypted message as string: {}", payload_string);
                }

                self.sink
                    .send(TeeTlsMessage::Decrypt(Decrypt {
                        msg: Some(msg),
                        seq: None,
                        opq: None,
                    }))
                    .await?;
            }
            _ => {
                return Err(TeeTlsError::new(
                    Kind::PeerMisbehaved,
                    "invalid decrypt message",
                ));
            }
        };

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    async fn encrypt(
        &mut self,
        msg: Option<PlainMessage>,
        seq: Option<u64>,
        _opq: Option<OpaqueMessage>,
    ) -> Result<(), TeeTlsError> {
        println!("Follower encrypting the message...");

        match (msg, seq) {
            (Some(msg), Some(seq)) => {
                let opq_msg = self.rcb.encrypt(msg, seq).await.map_err(|e| {
                    TeeTlsError::new(Kind::Other, format!("Failed to encrypt message: {:?}", e))
                })?;

                self.sink
                    .send(TeeTlsMessage::Encrypt(Encrypt {
                        msg: None,
                        seq: None,
                        opq: Some(opq_msg),
                    }))
                    .await?;
            }
            _ => {
                return Err(TeeTlsError::new(
                    Kind::PeerMisbehaved,
                    "invalid encrypt message",
                ));
            }
        };

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    async fn encrypt_alert(&mut self, msg: Vec<u8>) -> Result<(), TeeTlsError> {
        println!("Encrypting the alert...");
        self.is_accepting_messages()?;
        if let Some(alert) = AlertMessagePayload::read_bytes(&msg) {
            // We only allow the leader to send a CloseNotify alert
            if alert.description != AlertDescription::CloseNotify {
                return Err(TeeTlsError::new(
                    Kind::PeerMisbehaved,
                    "attempted to send an alert other than CloseNotify",
                ));
            }
        } else {
            return Err(TeeTlsError::new(
                Kind::PeerMisbehaved,
                "invalid alert message",
            ));
        }

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    async fn encrypt_message(&mut self, _len: usize) -> Result<(), TeeTlsError> {
        println!("Encrypting the message...");
        self.is_accepting_messages()?;

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    fn commit_message(&mut self, _payload: Vec<u8>) -> Result<(), TeeTlsError> {
        println!("Follower committing the message...");
        self.is_accepting_messages()?;

        Ok(())
    }

    #[cfg_attr(
        feature = "tracing",
        tracing::instrument(level = "trace", skip_all, err)
    )]
    fn close_connection(&mut self) -> Result<(), TeeTlsError> {
        println!("Follower closing the connection...");

        Ok(())
    }

    async fn commit(&mut self) -> Result<(), TeeTlsError> {
        println!("Follower committing the transcript...");
        Ok(())
    }
}

#[ludi::implement]
#[msg(name = "{name}")]
#[msg(attrs(derive(Debug, Serialize, Deserialize)))]
impl TeeTlsFollower {
    pub async fn server_finished_vd(&mut self, msg: Vec<u8>) {
        ctx.try_or_stop(|_| self.server_finished_vd(msg)).await;
    }
    pub async fn decrypt(
        &mut self,
        opq: Option<OpaqueMessage>,
        seq: Option<u64>,
        msg: Option<PlainMessage>,
    ) {
        ctx.try_or_stop(|_| self.decrypt(opq, seq, msg)).await;
    }
    pub async fn encrypt(
        &mut self,
        msg: Option<PlainMessage>,
        seq: Option<u64>,
        opq: Option<OpaqueMessage>,
    ) {
        ctx.try_or_stop(|_| self.encrypt(msg, seq, opq)).await;
    }
    pub async fn get_client_finished_vd(&mut self, msg: Vec<u8>) {
        ctx.try_or_stop(|_| self.get_client_finished_vd(msg)).await;
    }

    pub async fn set_server_key_share(&mut self, msg: PublicKey) {
        ctx.try_or_stop(|_| self.set_server_key_share(msg)).await;
    }
    pub async fn set_server_kx_details(&mut self, msg: ServerKxDetails) {
        ctx.try_or_stop(|_| self.set_server_kx_details(msg)).await;
    }
    pub async fn set_server_cert_details(&mut self, msg: ServerCertDetails) {
        ctx.try_or_stop(|_| self.set_server_cert_details(msg)).await;
    }
    pub async fn set_server_random(&mut self, msg: Random) {
        ctx.try_or_stop(|_| self.set_server_random(msg)).await;
    }
    pub async fn set_cipher_suite(&mut self, msg: SerializableSupportedCipherSuite) {
        ctx.try_or_stop(|_| self.set_cipher_suite(msg)).await;
    }
    pub async fn set_protocol_version(&mut self, msg: ProtocolVersion) {
        ctx.try_or_stop(|_| self.set_protocol_version(msg)).await;
    }
    pub async fn compute_client_random(&mut self, msg: Option<Random>) {
        ctx.try_or_stop(|_| self.compute_client_random(msg)).await;
    }
    pub async fn compute_client_key(&mut self, msg: Vec<u8>) {
        ctx.try_or_stop(|_| self.compute_client_key(msg)).await;
    }

    pub async fn encrypt_alert(&mut self, msg: Vec<u8>) {
        ctx.try_or_stop(|_| self.encrypt_alert(msg)).await;
    }

    pub async fn encrypt_message(&mut self, len: usize) {
        ctx.try_or_stop(|_| self.encrypt_message(len)).await;
    }

    pub async fn commit_message(&mut self, msg: Vec<u8>) {
        ctx.try_or_stop(|_| async { self.commit_message(msg) })
            .await;
    }

    #[msg(skip, name = "CloseConnection")]
    pub async fn close_connection(&mut self) -> Result<(), TeeTlsError> {
        ctx.try_or_stop(|_| async { self.close_connection() }).await;

        ctx.stop();

        Ok(())
    }

    #[msg(skip, name = "Commit")]
    pub async fn commit(&mut self) -> Result<(), TeeTlsError> {
        ctx.try_or_stop(|_| self.commit()).await;

        Ok(())
    }
}
