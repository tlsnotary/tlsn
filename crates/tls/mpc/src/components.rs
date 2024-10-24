use hmac_sha256::{MpcPrf, Prf, PrfConfig, Role as PrfRole};
use key_exchange::{KeyExchange, KeyExchangeConfig, MpcKeyExchange, Role as KeRole};
use mpz_common::{Context, Preprocess};
use mpz_fields::{gf2_128::Gf2_128, p256::P256};
use mpz_garble::{Decode, DecodePrivate, Execute, Load, Memory, Prove, Thread, Verify};
use mpz_ole::rot::{OLEReceiver, OLESender};
use mpz_ot::{OTError, RandomOTReceiver, RandomOTSender};
use mpz_share_conversion::{ShareConversionReceiver, ShareConversionSender};
use tlsn_stream_cipher::{Aes128Ctr, MpcStreamCipher, StreamCipherConfig};
use tlsn_universal_hash::{
    ghash::{Ghash, GhashConfig},
    UniversalHash,
};

use crate::{MpcTlsCommonConfig, TlsRole};

/// Builds the components for MPC-TLS.
pub fn build_components<K, P, OTS, OTR>(
    role: TlsRole,
    config: &MpcTlsCommonConfig,
    ctx: Ctx,
    vm: V,
    ot_send: OTS,
    ot_recv: OTR,
) -> (K, P)
where
    Ctx: Context + 'static,
    OTS: Preprocess<Ctx, Error = OTError>
        + RandomOTSender<Ctx, [P256; 2]>
        + RandomOTSender<Ctx, [Gf2_128; 2]>
        + Clone
        + Send
        + Sync
        + 'static,
    OTR: Preprocess<Ctx, Error = OTError>
        + RandomOTReceiver<Ctx, bool, P256>
        + RandomOTReceiver<Ctx, bool, Gf2_128>
        + Clone
        + Send
        + Sync
        + 'static,
{
    let ke = match role {
        TlsRole::Leader => MpcKeyExchange::new(
            KeyExchangeConfig::builder()
                .role(KeRole::Leader)
                .build()
                .unwrap(),
            ctx_ke,
            ShareConversionSender::new(OLESender::new(ot_send.clone())),
            ShareConversionReceiver::new(OLEReceiver::new(ot_recv.clone())),
            thread_ke,
        ),
        TlsRole::Follower => MpcKeyExchange::new(
            KeyExchangeConfig::builder()
                .role(KeRole::Follower)
                .build()
                .unwrap(),
            ctx_ke,
            ShareConversionReceiver::new(OLEReceiver::new(ot_recv.clone())),
            ShareConversionSender::new(OLESender::new(ot_send.clone())),
            thread_ke,
        ),
    };

    let prf = MpcPrf::new(
        PrfConfig::builder()
            .role(match role {
                TlsRole::Leader => PrfRole::Leader,
                TlsRole::Follower => PrfRole::Follower,
            })
            .build()
            .unwrap(),
    );

    let ghash_encrypt = match role {
        TlsRole::Leader => Ghash::new(
            GhashConfig::builder().build().unwrap(),
            ShareConversionSender::new(OLESender::new(ot_send.clone())),
        ),
        TlsRole::Follower => Ghash::new(
            GhashConfig::builder().build().unwrap(),
            ShareConversionReceiver::new(OLEReceiver::new(ot_recv.clone())),
        ),
    };

    let ghash_decrypt = match role {
        TlsRole::Leader => Ghash::new(
            GhashConfig::builder().build().unwrap(),
            ShareConversionSender::new(OLESender::new(ot_send)),
        ),
        TlsRole::Follower => Ghash::new(
            GhashConfig::builder().build().unwrap(),
            ShareConversionReceiver::new(OLEReceiver::new(ot_recv)),
        ),
    };

    (ke, prf, ghash_encrypt, ghash_decrypt)
}
