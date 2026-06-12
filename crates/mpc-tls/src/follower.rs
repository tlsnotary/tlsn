//! MPC-TLS follower.
//!
//! The follower is the verifier-side peer of the [`MpcTlsLeader`](crate::MpcTlsLeader).
//! It runs no TLS protocol logic of its own: it embeds an [`MpcSession`] and
//! mirrors the leader's decisions, which arrive as [`Message`]s, by running the
//! same MPC operations on its session.

use hmac_sha256::{MSMode, Prf, PrfConfig};
use ke::KeyExchange;
use key_exchange::{self as ke, MpcKeyExchange};
use mpz_common::{Context, Flush};
use mpz_core::Block;
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
use tls_core::msgs::enums::NamedGroup;
use tlsn_core::{
    connection::{CertBinding, CertBindingV1_2, TlsVersion},
    transcript::TlsTranscript,
};
use tracing::{debug, instrument};

use crate::{
    Config, MpcTlsError, Role, SessionKeys, Vm,
    msg::{Message, ServerHello},
    record_layer::{RecordLayer, aead::MpcAesGcm},
    session::MpcSession,
};

// Maximum handshake time difference in seconds.
const MAX_TIME_DIFF: u64 = 5;

/// MPC-TLS follower.
#[derive(Debug)]
pub struct MpcTlsFollower {
    config: Config,
    /// The MPC session, taken out for [`MpcTlsFollower::preprocess`] (which
    /// consumes the session) and replaced afterwards.
    session: Option<MpcSession>,
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
        let session = MpcSession::new(ctx, vm, ke, prf, record_layer);

        Self {
            config,
            session: Some(session),
        }
    }

    fn session_mut(&mut self) -> Result<&mut MpcSession, MpcTlsError> {
        self.session
            .as_mut()
            .ok_or_else(|| MpcTlsError::state("follower session is not available"))
    }

    /// Allocates resources for the connection.
    pub fn alloc(&mut self) -> Result<SessionKeys, MpcTlsError> {
        let config = self.config.clone();
        self.session_mut()?.alloc(&config)
    }

    /// Preprocesses the connection.
    #[instrument(skip_all, err)]
    pub async fn preprocess(&mut self) -> Result<(), MpcTlsError> {
        let session = self
            .session
            .take()
            .ok_or_else(|| MpcTlsError::state("must be in setup state to preprocess"))?;
        self.session = Some(session.preprocess().await?);
        Ok(())
    }

    /// Runs the follower, mirroring the leader's MPC operations until the
    /// connection is closed, then committing and verifying the transcript.
    #[instrument(skip_all, err)]
    pub async fn run(mut self) -> Result<(Context, TlsTranscript), MpcTlsError> {
        let mut session = self
            .session
            .take()
            .ok_or_else(|| MpcTlsError::state("must be in setup state to run"))?;

        let mut client_random = None;
        let mut server_hello: Option<ServerHello> = None;
        let mut cf_vd_computed = false;
        let mut sf_vd_computed = false;
        loop {
            let msg: Message = session.ctx_mut().io_mut().expect_next().await?;
            match msg {
                Message::SetClientRandom(random) => {
                    if client_random.is_some() {
                        return Err(MpcTlsError::hs("client random already set"));
                    }

                    session.set_client_random(random);
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

                    let NamedGroup::secp256r1 = hello.key.group else {
                        return Err(MpcTlsError::hs("unsupported server key group"));
                    };

                    let server_key = p256::PublicKey::from_sec1_bytes(&hello.key.key)
                        .map_err(|_| MpcTlsError::hs("failed to parse server key"))?;

                    session.compute_keys(hello.random, server_key).await?;

                    server_hello = Some(hello);
                }
                Message::ClientFinishedVd(handshake_hash) => {
                    if cf_vd_computed {
                        return Err(MpcTlsError::hs("client finished VD already computed"));
                    }

                    session.compute_cf_vd(handshake_hash).await?;
                    cf_vd_computed = true;
                }
                Message::ServerFinishedVd(handshake_hash) => {
                    if sf_vd_computed {
                        return Err(MpcTlsError::hs("server finished VD already computed"));
                    }

                    session.compute_sf_vd(handshake_hash).await?;
                    sf_vd_computed = true;
                }
                Message::Encrypt(encrypt) => {
                    session.push_encrypt(
                        encrypt.typ,
                        encrypt.version,
                        encrypt.len,
                        encrypt.plaintext,
                    )?;
                }
                Message::Decrypt(decrypt) => {
                    session.push_decrypt(
                        decrypt.typ,
                        decrypt.version,
                        decrypt.explicit_nonce,
                        decrypt.ciphertext,
                        decrypt.tag,
                    )?;
                }
                Message::StartTraffic => {
                    session.start_traffic();
                }
                Message::Flush { is_decrypting } => {
                    session.flush(is_decrypting).await?;
                    debug!("flushed record layer");
                }
                Message::CloseConnection => {
                    break;
                }
            }
        }

        debug!("committing");
        let (sent_records, recv_records) = session.commit().await?;
        debug!("committed");

        if !cf_vd_computed {
            return Err(MpcTlsError::hs("client finished VD not computed"));
        }
        if !sf_vd_computed {
            return Err(MpcTlsError::hs("server finished VD not computed"));
        }

        let server_hello = server_hello.ok_or(MpcTlsError::hs("server hello not set"))?;
        let client_random = client_random.ok_or(MpcTlsError::hs("client random not set"))?;

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

        session.verify_transcript(&transcript)?;

        let (ctx, _record_layer) = session.into_closed();

        Ok((ctx, transcript))
    }
}
