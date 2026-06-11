use crate::{
    Config, Role, SessionKeys, Vm,
    error::MpcTlsError,
    msg::{Decrypt, Encrypt, Message, ServerHello},
    record_layer::{RecordLayer, aead::MpcAesGcm},
    utils::{flush_prf, opaque_into_parts, verify_transcript},
};
use hmac_sha256::{MSMode, Prf, PrfConfig, PrfOutput};
use ke::KeyExchange;
use key_exchange::{self as ke, MpcKeyExchange};
use mpz_common::{Context, Flush};
use mpz_core::{Block, bitvec::BitVec};
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
use serio::SinkExt;
use tls_core::{
    cert::ServerCertDetails,
    ke::ServerKxDetails,
    key::PublicKey,
    msgs::{
        base::Payload,
        enums::{ContentType, NamedGroup},
        handshake::Random,
        message::{OpaqueMessage, PlainMessage},
    },
    verify::verify_sig_determine_alg,
};
use tlsn_core::{
    connection::{CertBinding, CertBindingV1_2, ServerSignature, TlsVersion},
    transcript::TlsTranscript,
    webpki::CertificateDer,
};

use tracing::{debug, instrument};

/// MPC-TLS leader.
#[derive(Debug)]
pub struct MpcTlsLeader {
    config: Config,
    state: State,

    /// Whether the record layer is decrypting application data.
    is_decrypting: bool,
}

impl MpcTlsLeader {
    /// Creates a new leader instance.
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
        let mut rng = rand::rng();

        let ke = Box::new(MpcKeyExchange::new(
            key_exchange::Role::Leader,
            ShareConversionSender::new(OLESender::new(
                Block::random(&mut rng),
                AnySender::new(RandomizeRCOTSender::new(cot_send.0)),
            )),
            ShareConversionReceiver::new(OLEReceiver::new(AnyReceiver::new(
                RandomizeRCOTReceiver::new(cot_recv),
            ))),
        )) as Box<dyn KeyExchange + Send + Sync>;

        let prf = Prf::new(PrfConfig::new(config.prf, MSMode::Standard));

        let encrypter = MpcAesGcm::new(
            ShareConversionSender::new(OLESender::new(
                Block::random(&mut rng),
                AnySender::new(RandomizeRCOTSender::new(cot_send.1)),
            )),
            Role::Leader,
        );
        let decrypter = MpcAesGcm::new(
            ShareConversionSender::new(OLESender::new(
                Block::random(&mut rng),
                AnySender::new(RandomizeRCOTSender::new(cot_send.2)),
            )),
            Role::Leader,
        );

        let record_layer = RecordLayer::new(Role::Leader, encrypter, decrypter);

        let is_decrypting = !config.defer_decryption;
        Self {
            config,
            state: State::Init {
                core: Core {
                    ctx,
                    vm,
                    ke,
                    prf,
                    record_layer,
                },
            },
            is_decrypting,
        }
    }

    /// Allocates resources for the connection.
    pub fn alloc(&mut self) -> Result<SessionKeys, MpcTlsError> {
        let State::Init { mut core } = self.state.take() else {
            return Err(MpcTlsError::state("must be in init state to allocate"));
        };

        let client_random = Random::new().expect("rng is available");

        let mut vm = core
            .vm
            .clone()
            .try_lock_owned()
            .map_err(|_| MpcTlsError::other("VM lock is held"))?;

        // Allocate.
        let pms = core.ke.alloc(&mut (*vm))?;
        let PrfOutput { keys, cf_vd, sf_vd } = core.prf.alloc_pms(&mut (*vm), pms)?;
        core.record_layer.set_keys(
            keys.client_write_key,
            keys.client_iv,
            keys.server_write_key,
            keys.server_iv,
        )?;

        let cf_vd_fut = vm.decode(cf_vd).map_err(MpcTlsError::alloc)?;
        let sf_vd_fut = vm.decode(sf_vd).map_err(MpcTlsError::alloc)?;

        let server_write_mac_key = core.record_layer.alloc(
            &mut (*vm),
            self.config.max_sent_records,
            self.config.max_recv_records_online,
            self.config.max_sent,
            self.config.max_recv_online,
            self.config.max_recv,
        )?;

        let keys = SessionKeys {
            client_write_key: keys.client_write_key,
            client_write_iv: keys.client_iv,
            server_write_key: keys.server_write_key,
            server_write_iv: keys.server_iv,
            server_write_mac_key,
        };

        drop(vm);
        self.state = State::Setup {
            core,
            client_random,
            cf_vd_fut,
            sf_vd_fut,
        };

        Ok(keys)
    }

    /// Preprocesses the connection.
    #[instrument(level = "debug", skip_all, err)]
    pub async fn preprocess(&mut self) -> Result<(), MpcTlsError> {
        let State::Setup {
            core:
                Core {
                    mut ctx,
                    vm,
                    ke,
                    mut prf,
                    record_layer,
                },
            client_random,
            cf_vd_fut,
            sf_vd_fut,
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
                move |ctx| {
                    Box::pin(async move {
                        let mut ke = ke;
                        ke.setup(ctx)
                            .await
                            .map(|_| ke)
                            .map_err(MpcTlsError::preprocess)
                    })
                },
                move |ctx| {
                    Box::pin(async move {
                        let mut record_layer = record_layer;
                        record_layer
                            .preprocess(ctx)
                            .await
                            .map(|_| record_layer)
                            .map_err(MpcTlsError::preprocess)
                    })
                },
                move |ctx| {
                    Box::pin(async move {
                        vm_lock
                            .preprocess(ctx)
                            .await
                            .map_err(MpcTlsError::preprocess)?;
                        vm_lock.flush(ctx).await.map_err(MpcTlsError::preprocess)?;

                        Ok::<_, MpcTlsError>(())
                    })
                },
            )
            .await
            .map_err(MpcTlsError::preprocess)??;

        ctx.io_mut()
            .send(Message::SetClientRandom(client_random.0))
            .await
            .map_err(MpcTlsError::from)?;

        prf.set_client_random(client_random.0);

        self.state = State::Ready {
            core: Core {
                ctx,
                vm,
                ke,
                prf,
                record_layer,
            },
            client_random,
            cf_vd_fut,
            sf_vd_fut,
        };

        Ok(())
    }

    /// Returns if incoming messages are decrypted.
    pub fn is_decrypting(&self) -> bool {
        self.is_decrypting
    }
}

impl MpcTlsLeader {
    /// Returns the client random.
    pub(crate) fn client_random(&self) -> Result<Random, MpcTlsError> {
        let State::Ready { client_random, .. } = &self.state else {
            return Err(MpcTlsError::state(
                "must be in ready state to get client random",
            ));
        };

        Ok(*client_random)
    }

    /// Returns the client key share for the key exchange.
    pub(crate) fn client_key_share(&self) -> Result<PublicKey, MpcTlsError> {
        let State::Ready { core, .. } = &self.state else {
            return Err(MpcTlsError::state(
                "must be in ready state to get client key share",
            ));
        };

        let pk = core
            .ke
            .client_key()
            .map_err(|err| MpcTlsError::state(err.to_string()))?;

        Ok(PublicKey::new(
            NamedGroup::secp256r1,
            &p256::EncodedPoint::from(pk).to_bytes(),
        ))
    }

    /// Computes the session keys from the handshake data collected by the
    /// client, preparing the record layer for encryption.
    #[instrument(level = "debug", skip_all, err)]
    pub(crate) async fn prepare_encryption(
        &mut self,
        hs: HandshakeData,
    ) -> Result<(), MpcTlsError> {
        let State::Ready {
            core:
                Core {
                    mut ctx,
                    vm,
                    mut ke,
                    mut prf,
                    mut record_layer,
                },
            client_random,
            cf_vd_fut,
            sf_vd_fut,
        } = self.state.take()
        else {
            return Err(MpcTlsError::state(
                "must be in ready state to prepare encryption",
            ));
        };

        debug!("preparing encryption");

        if hs.server_key.group != NamedGroup::secp256r1 {
            return Err(MpcTlsError::hs("invalid server public keyshare"));
        }

        let time = web_time::UNIX_EPOCH
            .elapsed()
            .expect("system time is available")
            .as_secs();

        ctx.io_mut()
            .send(Message::ServerHello(ServerHello {
                time,
                random: hs.server_random.0,
                key: hs.server_key.clone(),
            }))
            .await
            .map_err(MpcTlsError::from)?;

        prf.set_server_random(hs.server_random.0)
            .map_err(MpcTlsError::hs)?;

        ke.set_server_key(
            p256::PublicKey::from_sec1_bytes(&hs.server_key.key).map_err(MpcTlsError::hs)?,
        )
        .map_err(|err| MpcTlsError::state(err.to_string()))?;

        ke.compute_shares(&mut ctx).await.map_err(MpcTlsError::hs)?;

        {
            let mut vm = vm
                .try_lock()
                .map_err(|_| MpcTlsError::other("VM lock is held"))?;

            ke.assign(&mut (*vm)).map_err(MpcTlsError::hs)?;
            flush_prf(&mut prf, &mut *vm, &mut ctx).await?;

            ke.finalize().await.map_err(MpcTlsError::hs)?;
            record_layer.setup(&mut ctx).await?;
        }

        debug!("encryption prepared");

        self.state = State::Active {
            core: Core {
                ctx,
                vm,
                ke,
                prf,
                record_layer,
            },
            client_random,
            cf_vd_fut,
            sf_vd_fut,
            cf_vd: None,
            sf_vd: None,
            time,
            hs,
        };

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    pub(crate) async fn get_client_finished_vd(
        &mut self,
        hash: Vec<u8>,
    ) -> Result<Vec<u8>, MpcTlsError> {
        let State::Active {
            core,
            cf_vd_fut,
            cf_vd,
            ..
        } = &mut self.state
        else {
            return Err(MpcTlsError::state(
                "must be in active state to get client finished vd",
            ));
        };

        debug!("computing client finished verify data");

        let hash: [u8; 32] = hash
            .try_into()
            .map_err(|_| MpcTlsError::hs("client finished handshake hash is not 32 bytes"))?;

        core.ctx
            .io_mut()
            .send(Message::ClientFinishedVd(hash))
            .await
            .map_err(MpcTlsError::hs)?;

        let mut vm = core
            .vm
            .try_lock()
            .map_err(|_| MpcTlsError::other("VM lock is held"))?;
        core.prf.set_cf_hash(hash).map_err(MpcTlsError::hs)?;
        flush_prf(&mut core.prf, &mut *vm, &mut core.ctx).await?;

        let vd = cf_vd_fut
            .try_recv()
            .map_err(MpcTlsError::hs)?
            .ok_or_else(|| MpcTlsError::hs("cf_vd is not decoded"))?;

        *cf_vd = Some(vd);

        Ok(vd.to_vec())
    }

    #[instrument(level = "debug", skip_all, err)]
    pub(crate) async fn get_server_finished_vd(
        &mut self,
        hash: Vec<u8>,
    ) -> Result<Vec<u8>, MpcTlsError> {
        let State::Active {
            core,
            sf_vd_fut,
            sf_vd,
            ..
        } = &mut self.state
        else {
            return Err(MpcTlsError::state(
                "must be in active state to get server finished vd",
            ));
        };

        debug!("computing server finished verify data");

        let hash: [u8; 32] = hash
            .try_into()
            .map_err(|_| MpcTlsError::hs("server finished handshake hash is not 32 bytes"))?;

        core.ctx
            .io_mut()
            .send(Message::ServerFinishedVd(hash))
            .await
            .map_err(MpcTlsError::from)?;

        let mut vm = core
            .vm
            .try_lock()
            .map_err(|_| MpcTlsError::other("VM lock is held"))?;
        core.prf.set_sf_hash(hash).map_err(MpcTlsError::hs)?;
        flush_prf(&mut core.prf, &mut *vm, &mut core.ctx).await?;

        let vd = sf_vd_fut
            .try_recv()
            .map_err(MpcTlsError::hs)?
            .ok_or_else(|| MpcTlsError::hs("sf_vd is not decoded"))?;

        *sf_vd = Some(vd);

        Ok(vd.to_vec())
    }

    #[instrument(level = "debug", skip_all, err)]
    pub(crate) async fn push_incoming(&mut self, msg: OpaqueMessage) -> Result<(), MpcTlsError> {
        let State::Active { core, .. } = &mut self.state else {
            return Err(MpcTlsError::state(format!(
                "can not push incoming message in state: {}",
                self.state
            )));
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

        core.record_layer.push_decrypt(
            typ,
            version,
            explicit_nonce.clone(),
            ciphertext.clone(),
            tag.clone(),
        )?;

        core.ctx
            .io_mut()
            .send(Message::Decrypt(Decrypt {
                typ,
                version,
                explicit_nonce,
                ciphertext,
                tag,
            }))
            .await
            .map_err(MpcTlsError::from)?;

        Ok(())
    }

    pub(crate) fn next_incoming(&mut self) -> Result<Option<PlainMessage>, MpcTlsError> {
        let record_layer = match &mut self.state {
            State::Ready { core, .. } | State::Active { core, .. } => &mut core.record_layer,
            State::Closed { record_layer, .. } => record_layer,
            state => {
                return Err(MpcTlsError::state(format!(
                    "can not pull next incoming message in state: {state}",
                )));
            }
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
    pub(crate) async fn push_outgoing(&mut self, msg: PlainMessage) -> Result<(), MpcTlsError> {
        let State::Active { core, .. } = &mut self.state else {
            return Err(MpcTlsError::state(format!(
                "can not push outgoing message in state: {}",
                self.state
            )));
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

        // Only the contents of application data is hidden from the follower.
        let public_plaintext = match typ {
            ContentType::ApplicationData => None,
            _ => Some(plaintext.clone()),
        };

        core.record_layer
            .push_encrypt(typ, version, plaintext.len(), Some(plaintext.clone()))?;

        core.ctx
            .io_mut()
            .send(Message::Encrypt(Encrypt {
                typ,
                version,
                len: plaintext.len(),
                plaintext: public_plaintext,
            }))
            .await
            .map_err(MpcTlsError::from)?;

        Ok(())
    }

    pub(crate) fn next_outgoing(&mut self) -> Result<Option<OpaqueMessage>, MpcTlsError> {
        let record_layer = match &mut self.state {
            State::Ready { core, .. } | State::Active { core, .. } => &mut core.record_layer,
            State::Closed { record_layer, .. } => record_layer,
            state => {
                return Err(MpcTlsError::state(format!(
                    "can not pull next outgoing message in state: {state}",
                )));
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

    pub(crate) async fn start_traffic(&mut self) -> Result<(), MpcTlsError> {
        let State::Active { core, .. } = &mut self.state else {
            return Err(MpcTlsError::state(format!(
                "can not start traffic in state: {}",
                self.state
            )));
        };

        core.record_layer.start_traffic();
        core.ctx
            .io_mut()
            .send(Message::StartTraffic)
            .await
            .map_err(MpcTlsError::from)?;

        Ok(())
    }

    #[instrument(level = "debug", skip_all, err)]
    pub(crate) async fn flush(&mut self) -> Result<(), MpcTlsError> {
        let core = match &mut self.state {
            State::Ready { .. } => {
                debug!("record layer is not ready, skipping flush");
                return Ok(());
            }
            State::Active { core, .. } => core,
            // The record layer is guaranteed to be empty after the connection
            // was closed.
            State::Closed { .. } => return Ok(()),
            state => {
                return Err(MpcTlsError::state(format!(
                    "can not flush record layer in state: {state}",
                )));
            }
        };

        if !core.record_layer.wants_flush() {
            debug!("record layer is empty, skipping flush");
            return Ok(());
        }

        debug!("flushing record layer");

        core.ctx
            .io_mut()
            .send(Message::Flush {
                is_decrypting: self.is_decrypting,
            })
            .await
            .map_err(MpcTlsError::from)?;

        core.record_layer
            .flush(&mut core.ctx, core.vm.clone(), self.is_decrypting)
            .await
    }

    /// Returns whether the record layer has no buffered records.
    pub(crate) fn is_empty(&self) -> bool {
        match &self.state {
            State::Active { core, .. } => core.record_layer.is_empty(),
            State::Closed { record_layer, .. } => record_layer.is_empty(),
            _ => true,
        }
    }

    /// Closes the connection.
    #[instrument(name = "close_connection", level = "debug", skip_all, err)]
    pub(crate) async fn close_connection(&mut self) -> Result<(), MpcTlsError> {
        let State::Active {
            core:
                Core {
                    mut ctx,
                    vm,
                    mut record_layer,
                    ..
                },
            client_random,
            cf_vd,
            sf_vd,
            time,
            hs,
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

        let (sent_records, recv_records) = record_layer.commit(&mut ctx, vm).await?;

        debug!("committed to transcript");

        let cf_vd = cf_vd.ok_or(MpcTlsError::state("client finished verify data not set"))?;
        let sf_vd = sf_vd.ok_or(MpcTlsError::state("server finished verify data not set"))?;

        let server_cert_chain = hs
            .server_cert_details
            .cert_chain()
            .iter()
            .map(|cert| CertificateDer(cert.0.clone()))
            .collect();

        let mut sig_msg = Vec::new();
        sig_msg.extend_from_slice(&client_random.0);
        sig_msg.extend_from_slice(&hs.server_random.0);
        sig_msg.extend_from_slice(hs.server_kx_details.kx_params());

        let server_signature_alg = verify_sig_determine_alg(
            &hs.server_cert_details.cert_chain()[0],
            &sig_msg,
            hs.server_kx_details.kx_sig(),
        )
        .expect("only supported signature should have been accepted");

        let server_signature = ServerSignature {
            alg: server_signature_alg.into(),
            sig: hs.server_kx_details.kx_sig().sig.0.clone(),
        };

        let binding = CertBinding::V1_2(CertBindingV1_2 {
            client_random: client_random.0,
            server_random: hs.server_random.0,
            server_ephemeral_key: hs
                .server_key
                .try_into()
                .expect("only supported key scheme should have been accepted"),
        });

        let transcript = TlsTranscript::builder()
            .time(time)
            .version(TlsVersion::V1_2)
            .server_signature(server_signature)
            .server_cert_chain(server_cert_chain)
            .certificate_binding(binding)
            .records_sent(sent_records)
            .records_recv(recv_records)
            .build()
            .map_err(MpcTlsError::other)?;

        verify_transcript(&transcript, cf_vd, sf_vd)?;

        self.state = State::Closed {
            ctx,
            record_layer,
            transcript,
        };

        Ok(())
    }

    pub(crate) fn enable_decryption(&mut self, enable: bool) {
        self.is_decrypting = enable;
    }

    pub(crate) fn finish(&mut self) -> Option<(Context, TlsTranscript)> {
        match self.state.take() {
            State::Closed {
                ctx, transcript, ..
            } => Some((ctx, transcript)),
            state => {
                self.state = state;
                None
            }
        }
    }
}

/// Server parameters of the TLS handshake, collected by the client and
/// handed over before the session keys are computed.
#[derive(Debug)]
pub(crate) struct HandshakeData {
    /// The server random.
    pub(crate) server_random: Random,
    /// The server ephemeral public key.
    pub(crate) server_key: PublicKey,
    /// The server certificate chain and certificate metadata.
    pub(crate) server_cert_details: ServerCertDetails,
    /// The server key exchange parameters and signature.
    pub(crate) server_kx_details: ServerKxDetails,
}

/// The MPC machinery of the connection.
struct Core {
    ctx: Context,
    vm: Vm,
    ke: Box<dyn KeyExchange + Send + Sync + 'static>,
    prf: Prf,
    record_layer: RecordLayer,
}

enum State {
    Init {
        core: Core,
    },
    Setup {
        core: Core,
        client_random: Random,
        cf_vd_fut: DecodeFutureTyped<BitVec, [u8; 12]>,
        sf_vd_fut: DecodeFutureTyped<BitVec, [u8; 12]>,
    },
    Ready {
        core: Core,
        client_random: Random,
        cf_vd_fut: DecodeFutureTyped<BitVec, [u8; 12]>,
        sf_vd_fut: DecodeFutureTyped<BitVec, [u8; 12]>,
    },
    Active {
        core: Core,
        client_random: Random,
        cf_vd_fut: DecodeFutureTyped<BitVec, [u8; 12]>,
        sf_vd_fut: DecodeFutureTyped<BitVec, [u8; 12]>,
        cf_vd: Option<[u8; 12]>,
        sf_vd: Option<[u8; 12]>,
        time: u64,
        hs: HandshakeData,
    },
    Closed {
        ctx: Context,
        record_layer: RecordLayer,
        transcript: TlsTranscript,
    },
    Error,
}

impl State {
    fn take(&mut self) -> Self {
        std::mem::replace(self, State::Error)
    }
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Init { .. } => "Init",
            Self::Setup { .. } => "Setup",
            Self::Ready { .. } => "Ready",
            Self::Active { .. } => "Active",
            Self::Closed { .. } => "Closed",
            Self::Error => "Error",
        })
    }
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}
