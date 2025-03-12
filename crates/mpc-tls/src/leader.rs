mod actor;

use crate::{
    error::MpcTlsError,
    msg::{
        ClientFinishedVd, Decrypt, Encrypt, Message, ServerFinishedVd, SetServerKey,
        SetServerRandom,
    },
    record_layer::{aead::MpcAesGcm, DecryptMode, EncryptMode, RecordLayer},
    utils::opaque_into_parts,
    Config, LeaderOutput, Role, SessionKeys, Vm,
};
use async_trait::async_trait;
use hmac_sha256::{MpcPrf, PrfConfig, PrfOutput};
use ke::KeyExchange;
use key_exchange::{self as ke, MpcKeyExchange};
use ludi::Context as LudiContext;
use mpz_common::{scoped_futures::ScopedFutureExt, Context, Flush};
use mpz_core::{bitvec::BitVec, Block};
use mpz_memory_core::DecodeFutureTyped;
use mpz_ole::{Receiver as OLEReceiver, Sender as OLESender};
use mpz_ot::{
    rcot::{RCOTReceiver, RCOTSender},
    rot::{
        any::{AnyReceiver, AnySender},
        randomize::{RandomizeRCOTReceiver, RandomizeRCOTSender},
    },
};
use mpz_share_conversion::{ShareConversionReceiver, ShareConversionSender};
use mpz_vm_core::prelude::*;
use rand::{thread_rng, Rng};
use serio::SinkExt;
use tls_backend::{Backend, BackendError, BackendNotifier, BackendNotify};
use tls_core::{
    cert::ServerCertDetails,
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
use tracing::{debug, instrument, trace};

/// Controller for MPC-TLS leader.
pub type LeaderCtrl = actor::MpcTlsLeaderCtrl;

/// MPC-TLS leader.
#[derive(Debug)]
pub struct MpcTlsLeader {
    self_handle: Option<LeaderCtrl>,
    config: Config,
    state: State,

    /// When set, notifies the backend that there are TLS messages which need to
    /// be decrypted.
    notifier: BackendNotifier,
    /// Whether the record layer is decrypting application data.
    is_decrypting: bool,
}

impl MpcTlsLeader {
    /// Create a new leader instance
    pub fn new<CS, CR>(
        config: Config,
        ctx: Context,
        vm: Vm,
        cot_send: (CS, CS, CS),
        cot_recv: CR,
    ) -> Self
    where
        CS: RCOTSender<Block> + Flush + Send + Sync + 'static,
        CR: RCOTReceiver<bool, Block> + Flush + Send + Sync + 'static,
    {
        let mut rng = thread_rng();

        let ke = Box::new(MpcKeyExchange::new(
            key_exchange::Role::Leader,
            ShareConversionSender::new(OLESender::new(
                rng.gen(),
                AnySender::new(RandomizeRCOTSender::new(cot_send.0)),
            )),
            ShareConversionReceiver::new(OLEReceiver::new(AnyReceiver::new(
                RandomizeRCOTReceiver::new(cot_recv),
            ))),
        )) as Box<dyn KeyExchange + Send + Sync>;

        let prf = MpcPrf::new(
            PrfConfig::builder()
                .role(hmac_sha256::Role::Leader)
                .build()
                .expect("prf config is valid"),
        );

        let encrypter = MpcAesGcm::new(
            ShareConversionSender::new(OLESender::new(
                rng.gen(),
                AnySender::new(RandomizeRCOTSender::new(cot_send.1)),
            )),
            Role::Leader,
        );
        let decrypter = MpcAesGcm::new(
            ShareConversionSender::new(OLESender::new(
                rng.gen(),
                AnySender::new(RandomizeRCOTSender::new(cot_send.2)),
            )),
            Role::Leader,
        );

        let record_layer = RecordLayer::new(Role::Leader, encrypter, decrypter);

        let is_decrypting = !config.defer_decryption;
        Self {
            self_handle: None,
            config,
            state: State::Init {
                ctx,
                vm,
                ke,
                prf,
                record_layer,
            },
            notifier: BackendNotifier::new(),
            is_decrypting,
        }
    }

    /// Allocates resources for the connection.
    pub fn alloc(&mut self) -> Result<SessionKeys, MpcTlsError> {
        let State::Init {
            ctx,
            vm,
            mut ke,
            mut prf,
            mut record_layer,
        } = self.state.take()
        else {
            return Err(MpcTlsError::state("must be in init state to allocate"));
        };

        let mut vm_lock = vm
            .clone()
            .try_lock_owned()
            .map_err(|_| MpcTlsError::other("VM lock is held"))?;

        let client_random = Random::new().expect("rng is available");

        // Allocate
        let pms = ke.alloc(&mut (*vm_lock))?;
        let PrfOutput { keys, cf_vd, sf_vd } = prf.alloc(&mut (*vm_lock), pms)?;
        record_layer.set_keys(
            keys.client_write_key,
            keys.client_iv,
            keys.server_write_key,
            keys.server_iv,
        )?;

        prf.set_client_random(&mut (*vm_lock), Some(client_random.0))?;

        let cf_vd = vm_lock.decode(cf_vd).map_err(MpcTlsError::alloc)?;
        let sf_vd = vm_lock.decode(sf_vd).map_err(MpcTlsError::alloc)?;

        record_layer.alloc(
            &mut (*vm_lock),
            self.config.max_sent_records,
            self.config.max_recv_records,
            self.config.max_sent,
            self.config.max_recv_online,
        )?;

        self.state = State::Setup {
            ctx,
            vm,
            keys: keys.into(),
            ke,
            prf,
            record_layer,
            cf_vd,
            sf_vd,
            client_random,
        };

        Ok(keys.into())
    }

    /// Preprocesses the connection.
    #[instrument(level = "debug", skip_all, err)]
    pub async fn preprocess(&mut self) -> Result<(), MpcTlsError> {
        let State::Setup {
            mut ctx,
            vm,
            keys,
            mut ke,
            prf,
            mut record_layer,
            cf_vd,
            sf_vd,
            client_random,
        } = self.state.take()
        else {
            return Err(MpcTlsError::state("must be in setup state to preprocess"));
        };

        let mut vm_lock = vm
            .clone()
            .try_lock_owned()
            .map_err(|_| MpcTlsError::other("VM lock is held"))?;

        let (ke, record_layer, _) = ctx
            .try_join3(
                |ctx| {
                    async move {
                        ke.setup(ctx)
                            .await
                            .map(|_| ke)
                            .map_err(MpcTlsError::preprocess)
                    }
                    .scope_boxed()
                },
                |ctx| {
                    async move {
                        record_layer
                            .preprocess(ctx)
                            .await
                            .map(|_| record_layer)
                            .map_err(MpcTlsError::preprocess)
                    }
                    .scope_boxed()
                },
                |ctx| {
                    async move {
                        vm_lock.flush(ctx).await.map_err(MpcTlsError::preprocess)?;
                        vm_lock
                            .preprocess(ctx)
                            .await
                            .map_err(MpcTlsError::preprocess)?;
                        vm_lock.flush(ctx).await.map_err(MpcTlsError::preprocess)?;

                        Ok::<_, MpcTlsError>(())
                    }
                    .scope_boxed()
                },
            )
            .await
            .map_err(MpcTlsError::preprocess)??;

        self.state = State::Handshake {
            ctx,
            vm,
            keys,
            ke,
            prf,
            record_layer,
            cf_vd,
            sf_vd,
            protocol_version: None,
            cipher_suite: None,
            client_random,
            server_random: None,
            server_cert_details: None,
            server_key: None,
            server_kx_details: None,
        };

        Ok(())
    }

    /// Closes the connection.
    #[instrument(name = "close_connection", level = "debug", skip_all, err)]
    pub async fn close_connection(&mut self) -> Result<(), MpcTlsError> {
        let State::Active {
            mut ctx,
            vm,
            keys,
            mut record_layer,
            protocol_version,
            cipher_suite,
            client_random,
            server_random,
            server_cert_details,
            server_key,
            server_kx_details,
            ..
        } = self.state.take()
        else {
            return Err(MpcTlsError::state(
                "must be in active state to close connection",
            ));
        };

        debug!("closing connection");

        ctx.io_mut().send(Message::CloseConnection).await?;

        debug!("committing to transcript");

        let transcript = record_layer.commit(&mut ctx, vm.clone()).await?;

        debug!("committed to transcript");

        if !record_layer.is_empty() {
            debug!("notifying client to process remaining messages");
            self.notifier.set();
        }

        self.state = State::Closed {
            ctx,
            vm,
            record_layer,
            data: LeaderOutput {
                protocol_version,
                cipher_suite,
                server_key,
                server_cert_details,
                server_kx_details,
                client_random,
                server_random,
                transcript,
                keys,
            },
        };

        Ok(())
    }

    /// Defers decryption of any incoming messages.
    #[instrument(level = "debug", skip_all, err)]
    pub async fn defer_decryption(&mut self) -> Result<(), MpcTlsError> {
        self.is_decrypting = false;
        self.notifier.clear();

        Ok(())
    }

    /// Stops the actor.
    pub fn stop(&mut self, ctx: &mut LudiContext<Self>) {
        ctx.stop();
    }
}

#[async_trait]
impl Backend for MpcTlsLeader {
    async fn set_protocol_version(&mut self, version: ProtocolVersion) -> Result<(), BackendError> {
        let State::Handshake {
            protocol_version, ..
        } = &mut self.state
        else {
            return Err(
                MpcTlsError::state("must be in handshake state to set protocol version").into(),
            );
        };

        trace!("setting protocol version: {:?}", version);

        *protocol_version = Some(version);

        Ok(())
    }

    async fn set_cipher_suite(&mut self, suite: SupportedCipherSuite) -> Result<(), BackendError> {
        let State::Handshake { cipher_suite, .. } = &mut self.state else {
            return Err(
                MpcTlsError::state("must be in handshake state to set cipher suite").into(),
            );
        };

        trace!("setting cipher suite: {:?}", suite);

        *cipher_suite = Some(suite.suite());

        Ok(())
    }

    async fn get_suite(&mut self) -> Result<SupportedCipherSuite, BackendError> {
        unimplemented!()
    }

    async fn set_encrypt(&mut self, _mode: tls_backend::EncryptMode) -> Result<(), BackendError> {
        unimplemented!()
    }

    async fn set_decrypt(&mut self, _mode: tls_backend::DecryptMode) -> Result<(), BackendError> {
        unimplemented!()
    }

    async fn get_client_random(&mut self) -> Result<Random, BackendError> {
        let State::Handshake { client_random, .. } = &self.state else {
            return Err(
                MpcTlsError::state("must be in handshake state to get client random").into(),
            );
        };

        Ok(*client_random)
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn get_client_key_share(&mut self) -> Result<PublicKey, BackendError> {
        let State::Handshake { ke, .. } = &self.state else {
            return Err(
                MpcTlsError::state("must be in handshake state to get client key share").into(),
            );
        };

        let pk = ke
            .client_key()
            .map_err(|err| BackendError::InvalidState(err.to_string()))?;

        Ok(PublicKey::new(
            NamedGroup::secp256r1,
            &p256::EncodedPoint::from(pk).to_bytes(),
        ))
    }

    async fn set_server_random(&mut self, random: Random) -> Result<(), BackendError> {
        let State::Handshake {
            ctx,
            vm,
            prf,
            server_random,
            ..
        } = &mut self.state
        else {
            return Err(
                MpcTlsError::state("must be in handshake state to set server random").into(),
            );
        };

        ctx.io_mut()
            .send(Message::SetServerRandom(SetServerRandom {
                random: random.0,
            }))
            .await
            .map_err(MpcTlsError::from)?;

        let mut vm = vm
            .try_lock()
            .map_err(|_| MpcTlsError::other("VM lock is held"))?;

        prf.set_server_random(&mut (*vm), random.0)
            .map_err(MpcTlsError::hs)?;

        *server_random = Some(random);

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn set_server_key_share(&mut self, key: PublicKey) -> Result<(), BackendError> {
        let State::Handshake {
            ctx, server_key, ..
        } = &mut self.state
        else {
            return Err(
                MpcTlsError::state("must be in handshake state to set server key share").into(),
            );
        };

        if key.group != NamedGroup::secp256r1 {
            return Err(BackendError::InvalidServerKey);
        }

        ctx.io_mut()
            .send(Message::SetServerKey(SetServerKey { key: key.clone() }))
            .await
            .map_err(MpcTlsError::hs)?;

        *server_key = Some(key);

        Ok(())
    }

    async fn set_server_cert_details(
        &mut self,
        cert_details: ServerCertDetails,
    ) -> Result<(), BackendError> {
        let State::Handshake {
            server_cert_details,
            ..
        } = &mut self.state
        else {
            return Err(MpcTlsError::state(
                "must be in handshake state to set server cert details",
            )
            .into());
        };

        *server_cert_details = Some(cert_details);

        Ok(())
    }

    async fn set_server_kx_details(
        &mut self,
        kx_details: ServerKxDetails,
    ) -> Result<(), BackendError> {
        let State::Handshake {
            server_kx_details, ..
        } = &mut self.state
        else {
            return Err(
                MpcTlsError::state("must be in handshake state to set server kx details").into(),
            );
        };

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
        let State::Active {
            ctx,
            vm,
            prf,
            sf_vd,
            ..
        } = &mut self.state
        else {
            return Err(
                MpcTlsError::state("must be in active state to get server finished vd").into(),
            );
        };

        debug!("computing server finished verify data");

        let hash: [u8; 32] = hash
            .try_into()
            .map_err(|_| MpcTlsError::hs("server finished handshake hash is not 32 bytes"))?;

        ctx.io_mut()
            .send(Message::ServerFinishedVd(ServerFinishedVd {
                handshake_hash: hash,
            }))
            .await
            .map_err(MpcTlsError::from)?;

        let mut vm = vm
            .try_lock()
            .map_err(|_| MpcTlsError::other("VM lock is held"))?;
        prf.set_sf_hash(&mut (*vm), hash).map_err(MpcTlsError::hs)?;

        vm.execute_all(ctx).await.map_err(MpcTlsError::hs)?;

        let sf_vd = sf_vd
            .try_recv()
            .map_err(MpcTlsError::hs)?
            .ok_or_else(|| MpcTlsError::hs("sf_vd is not decoded"))?;

        Ok(sf_vd.to_vec())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn get_client_finished_vd(&mut self, hash: Vec<u8>) -> Result<Vec<u8>, BackendError> {
        let State::Active {
            ctx,
            vm,
            prf,
            cf_vd,
            ..
        } = &mut self.state
        else {
            return Err(
                MpcTlsError::state("must be in active state to get client finished vd").into(),
            );
        };

        debug!("computing client finished verify data");

        let hash: [u8; 32] = hash
            .try_into()
            .map_err(|_| MpcTlsError::hs("client finished handshake hash is not 32 bytes"))?;

        ctx.io_mut()
            .send(Message::ClientFinishedVd(ClientFinishedVd {
                handshake_hash: hash,
            }))
            .await
            .map_err(MpcTlsError::hs)?;

        let mut vm = vm
            .try_lock()
            .map_err(|_| MpcTlsError::hs("VM lock is held"))?;
        prf.set_cf_hash(&mut (*vm), hash).map_err(MpcTlsError::hs)?;

        vm.execute_all(ctx).await.map_err(MpcTlsError::hs)?;

        let cf_vd = cf_vd
            .try_recv()
            .map_err(MpcTlsError::hs)?
            .ok_or_else(|| MpcTlsError::hs("cf_vd is not decoded"))?;

        Ok(cf_vd.to_vec())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn prepare_encryption(&mut self) -> Result<(), BackendError> {
        let State::Handshake {
            mut ctx,
            vm,
            keys,
            mut ke,
            prf,
            mut record_layer,
            cf_vd,
            sf_vd,
            protocol_version,
            cipher_suite,
            client_random,
            server_random,
            server_cert_details,
            server_key,
            server_kx_details,
        } = self.state.take()
        else {
            return Err(
                MpcTlsError::state("must be in handshake state to prepare encryption").into(),
            );
        };

        debug!("preparing encryption");

        let protocol_version =
            protocol_version.ok_or_else(|| MpcTlsError::hs("protocol version is not set"))?;
        let cipher_suite =
            cipher_suite.ok_or_else(|| MpcTlsError::hs("cipher suite is not set"))?;
        let server_random =
            server_random.ok_or_else(|| MpcTlsError::hs("server random is not set"))?;
        let server_cert_details =
            server_cert_details.ok_or_else(|| MpcTlsError::hs("server cert details is not set"))?;
        let server_key = server_key.ok_or_else(|| MpcTlsError::hs("server key is not set"))?;
        let server_kx_details =
            server_kx_details.ok_or_else(|| MpcTlsError::hs("server kx details is not set"))?;

        ke.set_server_key(
            p256::PublicKey::from_sec1_bytes(&server_key.key).map_err(MpcTlsError::hs)?,
        )
        .map_err(|err| BackendError::InvalidState(err.to_string()))?;

        ke.compute_shares(&mut ctx).await.map_err(MpcTlsError::hs)?;

        {
            let mut vm_lock = vm
                .try_lock()
                .map_err(|_| MpcTlsError::other("VM lock is held"))?;

            ke.assign(&mut (*vm_lock)).map_err(MpcTlsError::hs)?;
            vm_lock
                .execute_all(&mut ctx)
                .await
                .map_err(MpcTlsError::hs)?;
            ke.finalize().await.map_err(MpcTlsError::hs)?;
            record_layer.setup(&mut ctx).await?;
        }

        debug!("encryption prepared");

        self.state = State::Active {
            ctx,
            vm,
            keys,
            _ke: ke,
            prf,
            record_layer,
            cf_vd,
            sf_vd,
            protocol_version,
            cipher_suite,
            client_random,
            server_random,
            server_cert_details,
            server_key,
            server_kx_details,
        };

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn push_incoming(&mut self, msg: OpaqueMessage) -> Result<(), BackendError> {
        let (ctx, record_layer) = match &mut self.state {
            State::Active {
                record_layer, ctx, ..
            } => (ctx, record_layer),
            State::Handshake {
                record_layer, ctx, ..
            } => (ctx, record_layer),
            _ => {
                return Err(MpcTlsError::state(
                    "must be in active or handshake state to push incoming message",
                )
                .into())
            }
        };

        let OpaqueMessage {
            typ,
            version,
            payload,
        } = msg;
        let (explicit_nonce, ciphertext, tag) = opaque_into_parts(payload.0)?;

        debug!(
            "received incoming message, type: {:?}, len: {}",
            typ,
            ciphertext.len()
        );

        let mode = match typ {
            ContentType::ApplicationData => DecryptMode::Private,
            _ => DecryptMode::Public,
        };

        record_layer.push_decrypt(
            typ,
            version,
            explicit_nonce.clone(),
            ciphertext.clone(),
            tag.clone(),
            mode,
        )?;

        ctx.io_mut()
            .send(Message::Decrypt(Decrypt {
                typ,
                version,
                explicit_nonce,
                ciphertext,
                tag,
                mode,
            }))
            .await
            .map_err(MpcTlsError::from)?;

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn next_incoming(&mut self) -> Result<Option<PlainMessage>, BackendError> {
        let record_layer =
            match &mut self.state {
                State::Active { record_layer, .. } => record_layer,
                State::Closed { record_layer, .. } => record_layer,
                State::Handshake { record_layer, .. } => record_layer,
                _ => return Err(MpcTlsError::state(
                    "must be in active, closed or handshake state to pull next incoming message",
                )
                .into()),
            };

        let record = record_layer.next_decrypted().map(|record| PlainMessage {
            typ: record.typ,
            version: record.version,
            payload: Payload::new(
                record
                    .plaintext
                    .expect("leader should always know plaintext"),
            ),
        });

        if let Some(record) = &record {
            debug!(
                "processing incoming message, type: {:?}, len: {}",
                record.typ,
                record.payload.0.len()
            );
        }

        Ok(record)
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn push_outgoing(&mut self, msg: PlainMessage) -> Result<(), BackendError> {
        let (ctx, record_layer) = match &mut self.state {
            State::Active {
                record_layer, ctx, ..
            } => (ctx, record_layer),
            State::Handshake {
                record_layer, ctx, ..
            } => (ctx, record_layer),
            _ => {
                return Err(MpcTlsError::state(
                    "must be in active or handshake state to push outgoing message",
                )
                .into())
            }
        };

        debug!(
            "encrypting outgoing message, type: {:?}, len: {}",
            msg.typ,
            msg.payload.0.len()
        );

        let PlainMessage {
            typ,
            version,
            payload,
        } = msg;
        let plaintext = payload.0;

        let mode = match typ {
            ContentType::ApplicationData => EncryptMode::Private,
            _ => EncryptMode::Public,
        };

        record_layer.push_encrypt(typ, version, plaintext.len(), Some(plaintext.clone()), mode)?;

        ctx.io_mut()
            .send(Message::Encrypt(Encrypt {
                typ,
                version,
                len: plaintext.len(),
                plaintext: match mode {
                    EncryptMode::Private => None,
                    EncryptMode::Public => Some(plaintext),
                },
                mode,
            }))
            .await
            .map_err(MpcTlsError::from)?;

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn next_outgoing(&mut self) -> Result<Option<OpaqueMessage>, BackendError> {
        let record_layer = match &mut self.state {
            State::Active { record_layer, .. } => record_layer,
            State::Closed { record_layer, .. } => record_layer,
            State::Handshake { record_layer, .. } => record_layer,
            _ => {
                return Err(MpcTlsError::state(
                    "must be in active, closed or hanshake state to pull next outgoing message",
                )
                .into())
            }
        };

        let record = record_layer.next_encrypted().map(|record| {
            let mut payload = record.explicit_nonce;
            payload.extend_from_slice(&record.ciphertext);
            payload.extend_from_slice(&record.tag.expect("leader should always know tag"));
            OpaqueMessage {
                typ: record.typ,
                version: record.version,
                payload: Payload::new(payload),
            }
        });

        if let Some(record) = &record {
            debug!(
                "sending outgoing message, type: {:?}, len: {}",
                record.typ,
                record.payload.0.len()
            );
        }

        Ok(record)
    }

    #[instrument(level = "debug", skip_all, err)]
    async fn flush(&mut self) -> Result<(), BackendError> {
        if !self
            .state
            .record_layer()
            .expect("record layer should be present")
            .wants_flush()
        {
            debug!("record layer is empty, skipping flush");
            return Ok(());
        }

        let (ctx, vm, record_layer) = match &mut self.state {
            State::Active {
                ctx,
                vm,
                record_layer,
                ..
            } => (ctx, vm, record_layer),
            State::Closed {
                ctx,
                vm,
                record_layer,
                ..
            } => (ctx, vm, record_layer),
            _ => {
                return Err(MpcTlsError::state(
                    "must be in active or closed state to flush record layer",
                )
                .into())
            }
        };

        debug!("flushing record layer");

        ctx.io_mut()
            .send(Message::Flush {
                is_decrypting: self.is_decrypting,
            })
            .await
            .map_err(MpcTlsError::from)?;

        record_layer
            .flush(ctx, vm.clone(), self.is_decrypting)
            .await
            .map_err(BackendError::from)
    }

    async fn get_notify(&mut self) -> Result<BackendNotify, BackendError> {
        Ok(self.notifier.get())
    }

    async fn is_empty(&mut self) -> Result<bool, BackendError> {
        let is_empty = match &self.state {
            State::Active { record_layer, .. } => record_layer.is_empty(),
            State::Closed { record_layer, .. } => record_layer.is_empty(),
            _ => true,
        };

        Ok(is_empty)
    }

    async fn server_closed(&mut self) -> Result<(), BackendError> {
        self.close_connection().await.map_err(BackendError::from)
    }
}

enum State {
    Init {
        ctx: Context,
        vm: Vm,
        ke: Box<dyn KeyExchange + Send + Sync + 'static>,
        prf: MpcPrf,
        record_layer: RecordLayer,
    },
    Setup {
        ctx: Context,
        vm: Vm,
        keys: SessionKeys,
        ke: Box<dyn KeyExchange + Send + Sync + 'static>,
        prf: MpcPrf,
        record_layer: RecordLayer,
        cf_vd: DecodeFutureTyped<BitVec, [u8; 12]>,
        sf_vd: DecodeFutureTyped<BitVec, [u8; 12]>,
        client_random: Random,
    },
    Handshake {
        ctx: Context,
        vm: Vm,
        keys: SessionKeys,
        ke: Box<dyn KeyExchange + Send + Sync + 'static>,
        prf: MpcPrf,
        record_layer: RecordLayer,
        cf_vd: DecodeFutureTyped<BitVec, [u8; 12]>,
        sf_vd: DecodeFutureTyped<BitVec, [u8; 12]>,
        protocol_version: Option<ProtocolVersion>,
        cipher_suite: Option<CipherSuite>,
        client_random: Random,
        server_random: Option<Random>,
        server_cert_details: Option<ServerCertDetails>,
        server_key: Option<PublicKey>,
        server_kx_details: Option<ServerKxDetails>,
    },
    Active {
        ctx: Context,
        vm: Vm,
        keys: SessionKeys,
        _ke: Box<dyn KeyExchange + Send + Sync + 'static>,
        prf: MpcPrf,
        record_layer: RecordLayer,
        cf_vd: DecodeFutureTyped<BitVec, [u8; 12]>,
        sf_vd: DecodeFutureTyped<BitVec, [u8; 12]>,
        protocol_version: ProtocolVersion,
        cipher_suite: CipherSuite,
        client_random: Random,
        server_random: Random,
        server_cert_details: ServerCertDetails,
        server_key: PublicKey,
        server_kx_details: ServerKxDetails,
    },
    Closed {
        ctx: Context,
        vm: Vm,
        record_layer: RecordLayer,
        data: LeaderOutput,
    },
    Error,
}

impl State {
    fn take(&mut self) -> Self {
        std::mem::replace(self, State::Error)
    }

    fn record_layer(&self) -> Option<&RecordLayer> {
        match self {
            State::Init { record_layer, .. } => Some(record_layer),
            State::Setup { record_layer, .. } => Some(record_layer),
            State::Handshake { record_layer, .. } => Some(record_layer),
            State::Active { record_layer, .. } => Some(record_layer),
            State::Closed { record_layer, .. } => Some(record_layer),
            State::Error => None,
        }
    }
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Init { .. } => f.debug_struct("Init").finish_non_exhaustive(),
            Self::Setup { .. } => f.debug_struct("Setup").finish_non_exhaustive(),
            Self::Handshake { .. } => f.debug_struct("Handshake").finish_non_exhaustive(),
            Self::Active { .. } => f.debug_struct("Active").finish_non_exhaustive(),
            Self::Closed { .. } => f.debug_struct("Closed").finish_non_exhaustive(),
            Self::Error => write!(f, "Error"),
        }
    }
}
