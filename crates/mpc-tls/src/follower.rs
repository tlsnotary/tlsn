use crate::{
    msg::{Message, StartHandshake},
    record_layer::{aead::MpcAesGcm, RecordLayer},
    Config, MpcTlsError, Role, SessionKeys, Vm,
};
use hmac_sha256::{MpcPrf, PrfOutput};
use ke::KeyExchange;
use key_exchange::{self as ke, MpcKeyExchange};
use mpz_common::{Context, Flush};
use mpz_core::{bitvec::BitVec, Block};
use mpz_memory_core::{DecodeFutureTyped, MemoryExt};
use mpz_ole::{Receiver as OLEReceiver, Sender as OLESender};
use mpz_ot::{
    rcot::{RCOTReceiver, RCOTSender},
    rot::{
        any::{AnyReceiver, AnySender},
        randomize::{RandomizeRCOTReceiver, RandomizeRCOTSender},
    },
};
use mpz_share_conversion::{ShareConversionReceiver, ShareConversionSender};
use serio::stream::IoStreamExt;
use std::mem;
use tls_core::msgs::enums::NamedGroup;
use tlsn_core::{
    connection::{HandshakeData, HandshakeDataV1_2, TlsVersion, VerifyData},
    transcript::TlsTranscript,
};
use tracing::{debug, instrument};

// Maximum handshake time difference in seconds.
const MAX_TIME_DIFF: u64 = 5;

/// MPC-TLS follower.
#[derive(Debug)]
pub struct MpcTlsFollower {
    config: Config,
    ctx: Context,
    state: State,
}

impl MpcTlsFollower {
    /// Creates a new follower.
    pub fn new<CS, CR>(
        config: Config,
        ctx: Context,
        vm: Vm,
        cot_send: CS,
        cot_recv: (CR, CR, CR),
    ) -> Self
    where
        CS: RCOTSender<Block> + Flush + Send + Sync + 'static,
        CR: RCOTReceiver<bool, Block> + Flush + Send + Sync + 'static,
    {
        let mut rng = rand::rng();

        let ke = Box::new(MpcKeyExchange::new(
            key_exchange::Role::Follower,
            ShareConversionReceiver::new(OLEReceiver::new(AnyReceiver::new(
                RandomizeRCOTReceiver::new(cot_recv.0),
            ))),
            ShareConversionSender::new(OLESender::new(
                Block::random(&mut rng),
                AnySender::new(RandomizeRCOTSender::new(cot_send)),
            )),
        )) as Box<dyn KeyExchange + Send + Sync>;

        let prf = MpcPrf::new(config.prf);

        let encrypter = MpcAesGcm::new(
            ShareConversionReceiver::new(OLEReceiver::new(AnyReceiver::new(
                RandomizeRCOTReceiver::new(cot_recv.1),
            ))),
            Role::Follower,
        );
        let decrypter = MpcAesGcm::new(
            ShareConversionReceiver::new(OLEReceiver::new(AnyReceiver::new(
                RandomizeRCOTReceiver::new(cot_recv.2),
            ))),
            Role::Follower,
        );

        let record_layer = RecordLayer::new(Role::Follower, encrypter, decrypter);

        Self {
            config,
            ctx,
            state: State::Init {
                vm,
                ke,
                prf,
                record_layer,
            },
        }
    }

    /// Allocates resources for the connection.
    pub fn alloc(&mut self) -> Result<SessionKeys, MpcTlsError> {
        let State::Init {
            vm,
            mut ke,
            mut prf,
            mut record_layer,
        } = self.state.take()
        else {
            return Err(MpcTlsError::state("must be in init state to allocate"));
        };

        let (keys, cf_vd, sf_vd, sw_mac_key) = {
            let vm = &mut (*vm
                .try_lock()
                .map_err(|_| MpcTlsError::other("VM lock is held"))?);

            let pms = ke.alloc(vm)?;
            let PrfOutput { keys, cf_vd, sf_vd } = prf.alloc(vm, pms)?;
            record_layer.set_keys(
                keys.client_write_key,
                keys.client_iv,
                keys.server_write_key,
                keys.server_iv,
            )?;

            let cf_vd = vm.decode(cf_vd).map_err(MpcTlsError::alloc)?;
            let sf_vd = vm.decode(sf_vd).map_err(MpcTlsError::alloc)?;

            let server_write_mac_key = record_layer.alloc(
                vm,
                self.config.max_sent_records,
                self.config.max_recv_records_online,
                self.config.max_sent,
                self.config.max_recv_online,
                self.config.max_recv,
            )?;

            (keys, cf_vd, sf_vd, server_write_mac_key)
        };

        let keys: SessionKeys = SessionKeys {
            client_write_key: keys.client_write_key,
            client_write_iv: keys.client_iv,
            server_write_key: keys.server_write_key,
            server_write_iv: keys.server_iv,
            server_write_mac_key: sw_mac_key,
        };

        self.state = State::Setup {
            vm,
            ke,
            prf,
            record_layer,
            cf_vd,
            sf_vd,
        };

        Ok(keys)
    }

    /// Preprocesses the connection.
    #[instrument(skip_all, err)]
    pub async fn preprocess(&mut self) -> Result<(), MpcTlsError> {
        let State::Setup {
            vm,
            mut ke,
            prf,
            mut record_layer,
            cf_vd,
            sf_vd,
            ..
        } = self.state.take()
        else {
            return Err(MpcTlsError::state("must be in setup state to preprocess"));
        };

        let (ke, record_layer, _) = {
            let mut vm = vm
                .clone()
                .try_lock_owned()
                .map_err(|_| MpcTlsError::other("VM lock is held"))?;
            self.ctx
                .try_join3(
                    async move |ctx| {
                        ke.setup(ctx)
                            .await
                            .map(|_| ke)
                            .map_err(MpcTlsError::preprocess)
                    },
                    async move |ctx| {
                        record_layer
                            .preprocess(ctx)
                            .await
                            .map(|_| record_layer)
                            .map_err(MpcTlsError::preprocess)
                    },
                    async move |ctx| {
                        vm.preprocess(ctx).await.map_err(MpcTlsError::preprocess)?;
                        vm.flush(ctx).await.map_err(MpcTlsError::preprocess)?;

                        Ok::<_, MpcTlsError>(())
                    },
                )
                .await
                .map_err(MpcTlsError::hs)??
        };

        self.state = State::Ready {
            vm,
            ke,
            prf,
            record_layer,
            cf_vd,
            sf_vd,
        };

        Ok(())
    }

    /// Runs the follower.
    #[instrument(skip_all, err)]
    pub async fn run(mut self) -> Result<(Context, TlsTranscript), MpcTlsError> {
        let State::Ready {
            vm,
            mut ke,
            mut prf,
            mut record_layer,
            cf_vd: mut cf_vd_fut,
            sf_vd: mut sf_vd_fut,
            ..
        } = self.state.take()
        else {
            return Err(MpcTlsError::state("must be in ready state to run"));
        };

        let mut time = None;
        let mut client_random = None;
        let mut server_random = None;
        let mut server_key = None;
        let mut cf_vd = None;
        let mut sf_vd = None;
        loop {
            let msg: Message = self.ctx.io_mut().expect_next().await?;
            match msg {
                Message::SetClientRandom(random) => {
                    if client_random.is_some() {
                        return Err(MpcTlsError::hs("client random already set"));
                    }

                    prf.set_client_random(random.random)?;
                    client_random = Some(random.random);
                }
                Message::StartHandshake(StartHandshake { time: prover_time }) => {
                    if time.is_some() {
                        return Err(MpcTlsError::hs("time already set"));
                    }

                    let this_time = web_time::UNIX_EPOCH
                        .elapsed()
                        .expect("system time is available")
                        .as_secs();

                    if prover_time.abs_diff(this_time) > MAX_TIME_DIFF {
                        return Err(MpcTlsError::hs("handshake time difference exceeds limit"));
                    }

                    time = Some(prover_time);
                }
                Message::SetServerRandom(random) => {
                    if server_random.is_some() {
                        return Err(MpcTlsError::hs("server random already set"));
                    }

                    prf.set_server_random(random.random)?;
                    server_random = Some(random.random);
                }
                Message::SetServerKey(key) => {
                    if server_key.is_some() {
                        return Err(MpcTlsError::hs("server key already set"));
                    }

                    let key = key.key;
                    let NamedGroup::secp256r1 = key.group else {
                        return Err(MpcTlsError::hs("unsupported server key group"));
                    };

                    ke.set_server_key(
                        p256::PublicKey::from_sec1_bytes(&key.key)
                            .map_err(|_| MpcTlsError::hs("failed to parse server key"))?,
                    )?;

                    server_key = Some(key);

                    let mut vm = vm
                        .try_lock()
                        .map_err(|_| MpcTlsError::other("VM lock is held"))?;

                    ke.compute_shares(&mut self.ctx).await?;
                    ke.assign(&mut (*vm))?;

                    while prf.wants_flush() {
                        prf.flush(&mut *vm)?;
                        vm.execute_all(&mut self.ctx)
                            .await
                            .map_err(MpcTlsError::hs)?;
                    }

                    ke.finalize().await?;
                    record_layer.setup(&mut self.ctx).await?;
                }
                Message::ClientFinishedVd(vd) => {
                    if cf_vd.is_some() {
                        return Err(MpcTlsError::hs("client finished VD already computed"));
                    }

                    let mut vm = vm
                        .try_lock()
                        .map_err(|_| MpcTlsError::other("VM lock is held"))?;

                    prf.set_cf_hash(vd.handshake_hash)?;

                    while prf.wants_flush() {
                        prf.flush(&mut *vm)?;
                        vm.execute_all(&mut self.ctx)
                            .await
                            .map_err(MpcTlsError::hs)?;
                    }

                    cf_vd = Some(
                        cf_vd_fut
                            .try_recv()
                            .map_err(MpcTlsError::hs)?
                            .ok_or(MpcTlsError::hs("client finished VD not computed"))?,
                    );
                }
                Message::ServerFinishedVd(vd) => {
                    if sf_vd.is_some() {
                        return Err(MpcTlsError::hs("server finished VD already computed"));
                    }

                    let mut vm = vm
                        .try_lock()
                        .map_err(|_| MpcTlsError::other("VM lock is held"))?;

                    prf.set_sf_hash(vd.handshake_hash)?;

                    while prf.wants_flush() {
                        prf.flush(&mut *vm)?;
                        vm.execute_all(&mut self.ctx)
                            .await
                            .map_err(MpcTlsError::hs)?;
                    }

                    sf_vd = Some(
                        sf_vd_fut
                            .try_recv()
                            .map_err(MpcTlsError::hs)?
                            .ok_or(MpcTlsError::hs("server finished VD not computed"))?,
                    );
                }
                Message::Encrypt(encrypt) => {
                    record_layer
                        .push_encrypt(
                            encrypt.typ,
                            encrypt.version,
                            encrypt.len,
                            encrypt.plaintext,
                            encrypt.mode,
                        )
                        .map_err(MpcTlsError::record_layer)?;
                }
                Message::Decrypt(decrypt) => {
                    record_layer
                        .push_decrypt(
                            decrypt.typ,
                            decrypt.version,
                            decrypt.explicit_nonce,
                            decrypt.ciphertext,
                            decrypt.tag,
                            decrypt.mode,
                        )
                        .map_err(MpcTlsError::record_layer)?;
                }
                Message::StartTraffic => {
                    record_layer.start_traffic();
                }
                Message::Flush { is_decrypting } => {
                    record_layer
                        .flush(&mut self.ctx, vm.clone(), is_decrypting)
                        .await?;
                    debug!("flushed record layer");
                }
                Message::CloseConnection => {
                    break;
                }
            }
        }

        debug!("committing");

        let (sent_records, recv_records) = record_layer.commit(&mut self.ctx, vm).await?;

        debug!("committed");

        let time = time.ok_or(MpcTlsError::hs("time was not set"))?;
        let server_key = server_key.ok_or(MpcTlsError::hs("server key not set"))?;
        let client_random = client_random.ok_or(MpcTlsError::hs("client random not set"))?;
        let server_random = server_random.ok_or(MpcTlsError::hs("client random not set"))?;
        let cf_vd = cf_vd.ok_or(MpcTlsError::hs("client finished VD not computed"))?;
        let sf_vd = sf_vd.ok_or(MpcTlsError::hs("server finished VD not computed"))?;

        let handshake_data = HandshakeData::V1_2(HandshakeDataV1_2 {
            client_random,
            server_random,
            server_ephemeral_key: server_key
                .try_into()
                .expect("only supported key scheme should have been accepted"),
        });

        let transcript = TlsTranscript::new(
            time,
            TlsVersion::V1_2,
            None,
            None,
            handshake_data,
            VerifyData {
                client_finished: cf_vd.to_vec(),
                server_finished: sf_vd.to_vec(),
            },
            sent_records,
            recv_records,
        )
        .map_err(MpcTlsError::other)?;

        Ok((self.ctx, transcript))
    }
}

enum State {
    Init {
        vm: Vm,
        ke: Box<dyn KeyExchange + Send + Sync + 'static>,
        prf: MpcPrf,
        record_layer: RecordLayer,
    },
    Setup {
        vm: Vm,
        ke: Box<dyn KeyExchange + Send + Sync + 'static>,
        prf: MpcPrf,
        record_layer: RecordLayer,
        cf_vd: DecodeFutureTyped<BitVec, [u8; 12]>,
        sf_vd: DecodeFutureTyped<BitVec, [u8; 12]>,
    },
    Ready {
        vm: Vm,
        ke: Box<dyn KeyExchange + Send + Sync + 'static>,
        prf: MpcPrf,
        record_layer: RecordLayer,
        cf_vd: DecodeFutureTyped<BitVec, [u8; 12]>,
        sf_vd: DecodeFutureTyped<BitVec, [u8; 12]>,
    },
    Error,
}

impl State {
    fn take(&mut self) -> Self {
        mem::replace(self, State::Error)
    }
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Init { .. } => f.debug_struct("Init").finish_non_exhaustive(),
            Self::Setup { .. } => f.debug_struct("Setup").finish_non_exhaustive(),
            Self::Ready { .. } => f.debug_struct("Ready").finish_non_exhaustive(),
            Self::Error => write!(f, "Error"),
        }
    }
}
