use std::{ future::Future, mem};


use futures::{
    stream::{SplitSink, SplitStream},
    FutureExt, SinkExt, StreamExt,
};

use ludi::{Address, FuturesAddress};

use serde::{Deserialize, Serialize};
use tls_client::{Backend, RustCryptoBackend, SignatureScheme, SupportedCipherSuite};
use tls_core::{
    cert::ServerCertDetails,
    ke::ServerKxDetails,
    key::PublicKey,
    msgs::{
        alert::AlertMessagePayload,
        codec::Codec,
        enums::{AlertDescription, ProtocolVersion, ContentType,},
        handshake::Random,
        message::{OpaqueMessage, PlainMessage},
    },
    suites::{
        AEADAlgorithm, CipherSuiteCommon, HashAlgorithm, SerializableSupportedCipherSuite,
        Tls12CipherSuite, Tls13CipherSuite,
    },
};
use tracing::{debug, instrument, Instrument};

use crate::{
    error::Kind,
    msg::{CloseConnection, Commit, TeeTlsFollowerMsg, TeeTlsMessage},
    TeeTlsChannel, TeeTlsError,
};
/// Controller for Tee-TLS follower.
pub type TeeFollowerCtrl = TeeTlsFollowerCtrl<FuturesAddress<TeeTlsFollowerMsg>>;

/// Tee-TLS follower.
#[derive(ludi::Controller)]
pub struct TeeTlsFollower {
    state: State,

    sink: SplitSink<TeeTlsChannel, TeeTlsMessage>,
    stream: Option<SplitStream<TeeTlsChannel>>,

    rcb: RustCryptoBackend,

    /// Whether the server has sent a CloseNotify alert.
    close_notify: bool,
    /// Whether the leader has committed to the transcript.
    committed: bool,
}

/// Data collected by the TEE-TLS follower
#[derive(Debug)]
pub struct TeeTlsFollowerData {
    /// The recorded application data.
    pub application_data: String,
}

impl ludi::Actor for TeeTlsFollower {
    type Stop = TeeTlsFollowerData;
    type Error = TeeTlsError;

    async fn stopped(&mut self) -> Result<Self::Stop, Self::Error> {
        debug!("Follower stopped...");
        let Closed {
            application_data,
        } = self.state.take().try_into_closed()?;

        Ok(TeeTlsFollowerData {
            application_data,
        })
    }
}

impl TeeTlsFollower {
    /// Create a new follower instance
    pub fn new(channel: TeeTlsChannel) -> Self {
        debug!("Creating a new follower...");

        let (sink, stream) = channel.split();
        Self {
            state: State::Active(Active {
                application_data: "".to_string(),
            }),
            sink,
            rcb: RustCryptoBackend::new(),
            stream: Some(stream),
            close_notify: false,
            committed: false,
        }
    }

    /// Performs any one-time setup operations.
    #[instrument(level = "trace", skip_all, err)]
    pub async fn setup(&mut self) -> Result<(), TeeTlsError> {
        debug!("Setting up the follower...");
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
        impl Future<Output = Result<TeeTlsFollowerData, TeeTlsError>>,
    ) {
        debug!("Running the follower...");
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

        (ctrl, fut.in_current_span())
    }

    #[instrument(level = "trace", skip_all, err)]
    fn is_accepting_messages(&self) -> Result<(), TeeTlsError> {
        debug!("Checking if the follower is accepting messages...");
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

    #[instrument(level = "trace", skip_all, err)]
    async fn get_client_finished_vd(&mut self, hash: Vec<u8>) -> Result<Vec<u8>, TeeTlsError> {
        debug!("Follower getting the client finished VD...");
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

    #[instrument(level = "trace", skip_all, err)]
    async fn set_server_key_share(&mut self, key_share: PublicKey) -> Result<(), TeeTlsError> {
        debug!("Follower setting the server key share");
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

    #[instrument(level = "trace", skip_all, err)]
    async fn set_server_kx_details(
        &mut self,
        kx_details: ServerKxDetails,
    ) -> Result<(), TeeTlsError> {
        debug!("Follower setting the server key exchange details");
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

    #[instrument(level = "trace", skip_all, err)]
    async fn set_server_cert_details(
        &mut self,
        cert_details: ServerCertDetails,
    ) -> Result<(), TeeTlsError> {
        debug!("Follower setting the server cert details");
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

    #[instrument(level = "trace", skip_all, err)]
    async fn set_server_random(&mut self, random: Random) -> Result<(), TeeTlsError> {
        debug!("Follower setting the server random to {:?}", random);
        self.rcb
            .set_server_random(random.clone())
            .await
            .map_err(|e| {
                TeeTlsError::new(Kind::Other, format!("Failed to set server random: {:?}", e))
            })?;
        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
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
        debug!("Follower setting the cipher suite to {:?}", scs);
        self.rcb.set_cipher_suite(scs).await.map_err(|e| {
            TeeTlsError::new(Kind::Other, format!("Failed to set cipher suite: {:?}", e))
        })?;

        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
    async fn set_protocol_version(&mut self, version: ProtocolVersion) -> Result<(), TeeTlsError> {
        debug!("Follower setting the protocol version to {:?}", version);

        self.rcb.set_protocol_version(version).await.map_err(|e| {
            TeeTlsError::new(
                Kind::Other,
                format!("Failed to set protocol version: {:?}", e),
            )
        })?;
        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
    async fn compute_client_random(&mut self, _msg: Option<Random>) -> Result<(), TeeTlsError> {
        debug!("Follower computing the client random...");
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

    #[instrument(level = "trace", skip_all, err)]
    async fn compute_client_key(&mut self, _pk: Vec<u8>) -> Result<(), TeeTlsError> {
        debug!("Follower computing the client key share...");
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

    #[instrument(level = "trace", skip_all, err)]
    async fn server_finished_vd(&mut self, hash: Vec<u8>) -> Result<(), TeeTlsError> {
        debug!("Follower setting the server finished VD...");
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

        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
    async fn decrypt(
        &mut self,
        opq: Option<OpaqueMessage>,
        seq: Option<u64>,
        _msg: Option<PlainMessage>,
    ) -> Result<(), TeeTlsError> {
        debug!("Follower decrypting the message...");
        let Active { application_data, .. } = self.state.try_as_active_mut()?;

        match (opq, seq) {
            (Some(opq), Some(seq)) => {
                let msg = self.rcb.decrypt(opq, seq).await.map_err(|e| {
                    TeeTlsError::new(Kind::Other, format!("Failed to decrypt message: {:?}", e))
                })?;

                // Convert msg.payload to string
                if msg.typ == ContentType::ApplicationData {
                    let payload_string = String::from_utf8_lossy(&msg.payload.0).to_string();
                    application_data.push_str(&payload_string);
                    debug!("Decrypted message as string: {}", payload_string);
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

    #[instrument(level = "trace", skip_all, err)]
    async fn encrypt(
        &mut self,
        msg: Option<PlainMessage>,
        seq: Option<u64>,
        _opq: Option<OpaqueMessage>,
    ) -> Result<(), TeeTlsError> {
        debug!("Follower encrypting the message...");

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

    #[instrument(level = "trace", skip_all, err)]
    async fn encrypt_alert(&mut self, msg: Vec<u8>) -> Result<(), TeeTlsError> {
        debug!("Encrypting the alert...");
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

    #[instrument(level = "trace", skip_all, err)]
    async fn encrypt_message(&mut self, _len: usize) -> Result<(), TeeTlsError> {
        debug!("Encrypting the message...");
        self.is_accepting_messages()?;

        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
    fn commit_message(&mut self, _payload: Vec<u8>) -> Result<(), TeeTlsError> {
        debug!("Follower committing the message...");
        self.is_accepting_messages()?;

        Ok(())
    }

    #[instrument(level = "trace", skip_all, err)]
    fn close_connection(&mut self) -> Result<(), TeeTlsError> {
        debug!("Follower closing the connection...");

        let Active {
            application_data,
        } = self.state.take().try_into_active()?;

        self.state = State::Closed(Closed {
            application_data,
        });

        Ok(())
    }

    async fn commit(&mut self) -> Result<(), TeeTlsError> {
        debug!("Follower committing the transcript...");
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

    pub async fn server_closed(&mut self) -> Result<(), TeeTlsError> {
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

mod state {
    use super::*;
    use enum_try_as_inner::EnumTryAsInner;

    #[derive(Debug, EnumTryAsInner)]
    #[derive_err(Debug)]
    pub(super) enum State {
        Active(Active),
        Closed(Closed),
        Error,
    }

    impl State {
        pub(super) fn take(&mut self) -> Self {
            mem::replace(self, State::Error)
        }
    }

    impl From<StateError> for TeeTlsError {
        fn from(err: StateError) -> Self {
            TeeTlsError::new(Kind::State, err)
        }
    }

    #[derive(Debug)]
    pub(super) struct Active {
        pub(super) application_data: String,
    }

    #[derive(Debug)]
    pub(super) struct Closed {
        pub(super) application_data: String,
    }
}

use state::*;
