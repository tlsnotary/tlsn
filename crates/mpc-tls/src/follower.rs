use crate::{
    Config, MpcTlsError, Role, SessionKeys, Vm,
    msg::{Message, ServerHello},
    record_layer::{RecordLayer, aead::MpcAesGcm},
    utils::{alloc_session, flush_prf, verify_transcript},
};
use hmac_sha256::{MSMode, Prf, PrfConfig};
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
use serio::stream::IoStreamExt;
use std::mem;
use tls_core::msgs::enums::NamedGroup;
use tlsn_core::{
    connection::{CertBinding, CertBindingV1_2, TlsVersion},
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

        let prf = Prf::new(PrfConfig::new(config.prf, MSMode::Standard));

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

        let (keys, cf_vd, sf_vd) = {
            let mut vm = vm
                .try_lock()
                .map_err(|_| MpcTlsError::other("VM lock is held"))?;

            alloc_session(
                &mut *vm,
                &self.config,
                &mut *ke,
                &mut prf,
                &mut record_layer,
            )?
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
                    move |ctx| {
                        Box::pin(async move {
                            ke.setup(ctx)
                                .await
                                .map(|_| ke)
                                .map_err(MpcTlsError::preprocess)
                        })
                    },
                    move |ctx| {
                        Box::pin(async move {
                            record_layer
                                .preprocess(ctx)
                                .await
                                .map(|_| record_layer)
                                .map_err(MpcTlsError::preprocess)
                        })
                    },
                    move |ctx| {
                        Box::pin(async move {
                            vm.preprocess(ctx).await.map_err(MpcTlsError::preprocess)?;
                            vm.flush(ctx).await.map_err(MpcTlsError::preprocess)?;

                            Ok::<_, MpcTlsError>(())
                        })
                    },
                )
                .await
                .map_err(MpcTlsError::preprocess)??
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
        } = self.state.take()
        else {
            return Err(MpcTlsError::state("must be in ready state to run"));
        };

        let mut client_random = None;
        let mut server_hello: Option<ServerHello> = None;
        let mut expected_cf_vd = None;
        let mut expected_sf_vd = None;
        loop {
            let msg: Message = self.ctx.io_mut().expect_next().await?;
            match msg {
                Message::SetClientRandom(random) => {
                    if client_random.is_some() {
                        return Err(MpcTlsError::hs("client random already set"));
                    }

                    prf.set_client_random(random);
                    client_random = Some(random);
                }
                Message::ServerHello(hello) => {
                    if server_hello.is_some() {
                        return Err(MpcTlsError::hs("server hello already set"));
                    }

                    let this_time = web_time::UNIX_EPOCH
                        .elapsed()
                        .expect("system time is available")
                        .as_secs();

                    if hello.time.abs_diff(this_time) > MAX_TIME_DIFF {
                        return Err(MpcTlsError::hs("handshake time difference exceeds limit"));
                    }

                    prf.set_server_random(hello.random)?;

                    let NamedGroup::secp256r1 = hello.key.group else {
                        return Err(MpcTlsError::hs("unsupported server key group"));
                    };

                    ke.set_server_key(
                        p256::PublicKey::from_sec1_bytes(&hello.key.key)
                            .map_err(|_| MpcTlsError::hs("failed to parse server key"))?,
                    )?;

                    let mut vm = vm
                        .try_lock()
                        .map_err(|_| MpcTlsError::other("VM lock is held"))?;

                    ke.compute_shares(&mut self.ctx).await?;
                    ke.assign(&mut (*vm))?;

                    flush_prf(&mut prf, &mut *vm, &mut self.ctx).await?;

                    ke.finalize().await?;
                    record_layer.setup(&mut self.ctx).await?;

                    server_hello = Some(hello);
                }
                Message::ClientFinishedVd(handshake_hash) => {
                    if expected_cf_vd.is_some() {
                        return Err(MpcTlsError::hs("client finished VD already computed"));
                    }

                    let mut vm = vm
                        .try_lock()
                        .map_err(|_| MpcTlsError::other("VM lock is held"))?;

                    prf.set_cf_hash(handshake_hash)?;
                    flush_prf(&mut prf, &mut *vm, &mut self.ctx).await?;

                    expected_cf_vd = Some(
                        cf_vd_fut
                            .try_recv()
                            .map_err(MpcTlsError::hs)?
                            .ok_or(MpcTlsError::hs("client finished VD not computed"))?,
                    );
                }
                Message::ServerFinishedVd(handshake_hash) => {
                    if expected_sf_vd.is_some() {
                        return Err(MpcTlsError::hs("server finished VD already computed"));
                    }

                    let mut vm = vm
                        .try_lock()
                        .map_err(|_| MpcTlsError::other("VM lock is held"))?;

                    prf.set_sf_hash(handshake_hash)?;
                    flush_prf(&mut prf, &mut *vm, &mut self.ctx).await?;

                    expected_sf_vd = Some(
                        sf_vd_fut
                            .try_recv()
                            .map_err(MpcTlsError::hs)?
                            .ok_or(MpcTlsError::hs("server finished VD not computed"))?,
                    );
                }
                Message::Encrypt(encrypt) => {
                    record_layer.push_encrypt(
                        encrypt.typ,
                        encrypt.version,
                        encrypt.len,
                        encrypt.plaintext,
                    )?;
                }
                Message::Decrypt(decrypt) => {
                    record_layer.push_decrypt(
                        decrypt.typ,
                        decrypt.version,
                        decrypt.explicit_nonce,
                        decrypt.ciphertext,
                        decrypt.tag,
                    )?;
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

        let server_hello = server_hello.ok_or(MpcTlsError::hs("server hello not set"))?;
        let client_random = client_random.ok_or(MpcTlsError::hs("client random not set"))?;
        let expected_cf_vd =
            expected_cf_vd.ok_or(MpcTlsError::hs("client finished VD not computed"))?;
        let expected_sf_vd =
            expected_sf_vd.ok_or(MpcTlsError::hs("server finished VD not computed"))?;

        let binding = CertBinding::V1_2(CertBindingV1_2 {
            client_random,
            server_random: server_hello.random,
            server_ephemeral_key: server_hello
                .key
                .try_into()
                .expect("only supported key scheme should have been accepted"),
        });

        let transcript = TlsTranscript::builder()
            .time(server_hello.time)
            .version(TlsVersion::V1_2)
            .certificate_binding(binding)
            .records_sent(sent_records)
            .records_recv(recv_records)
            .build()
            .map_err(MpcTlsError::other)?;

        verify_transcript(&transcript, expected_cf_vd, expected_sf_vd)?;

        Ok((self.ctx, transcript))
    }
}

enum State {
    Init {
        vm: Vm,
        ke: Box<dyn KeyExchange + Send + Sync + 'static>,
        prf: Prf,
        record_layer: RecordLayer,
    },
    Setup {
        vm: Vm,
        ke: Box<dyn KeyExchange + Send + Sync + 'static>,
        prf: Prf,
        record_layer: RecordLayer,
        cf_vd: DecodeFutureTyped<BitVec, [u8; 12]>,
        sf_vd: DecodeFutureTyped<BitVec, [u8; 12]>,
    },
    Ready {
        vm: Vm,
        ke: Box<dyn KeyExchange + Send + Sync + 'static>,
        prf: Prf,
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
        f.write_str(match self {
            Self::Init { .. } => "Init",
            Self::Setup { .. } => "Setup",
            Self::Ready { .. } => "Ready",
            Self::Error => "Error",
        })
    }
}
