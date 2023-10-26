use hmac_sha256 as prf;
use key_exchange as ke;
use mpz_garble::{Decode, DecodePrivate, Execute, Load, Prove, Verify, Vm};
use mpz_share_conversion as ff;
use point_addition as pa;
use tlsn_stream_cipher as stream_cipher;
use tlsn_universal_hash as universal_hash;

use aead::Aead;
use hmac_sha256::Prf;
use ke::KeyExchange;

use utils_aio::mux::MuxChannel;

use crate::{config::MpcTlsCommonConfig, MpcTlsError, TlsRole};

/// Helper function for setting up components
#[allow(clippy::type_complexity)]
#[cfg_attr(
    feature = "tracing",
    tracing::instrument(level = "info", skip_all, err)
)]
pub async fn setup_components<
    M: MuxChannel<ke::KeyExchangeMessage> + MuxChannel<aead::AeadMessage> + Clone,
    VM: Vm + Send,
    PS: ff::ShareConversion<ff::P256> + Send + Sync + 'static + std::fmt::Debug,
    PR: ff::ShareConversion<ff::P256> + Send + Sync + 'static + std::fmt::Debug,
    GF: ff::ShareConversion<ff::Gf2_128> + Send + Sync + Clone + 'static + std::fmt::Debug,
>(
    config: &MpcTlsCommonConfig,
    role: TlsRole,
    mux: &mut M,
    vm: &mut VM,
    p256_send: PS,
    p256_recv: PR,
    gf: GF,
) -> Result<
    (
        Box<dyn KeyExchange + Send>,
        Box<dyn Prf + Send>,
        Box<dyn Aead + Send>,
        Box<dyn Aead + Send>,
    ),
    MpcTlsError,
>
where
    <VM as Vm>::Thread: Execute + Load + Decode + DecodePrivate + Prove + Verify + Send + Sync,
{
    // Set up channels
    let (mut mux_0, mut mux_1) = (mux.clone(), mux.clone());
    let (ke_channel, encrypter_channel, decrypter_channel) = futures::try_join!(
        mux_0.get_channel("ke"),
        mux_1.get_channel("encrypter"),
        mux.get_channel("decrypter")
    )?;

    let (ke_role, pa_role, aead_role) = match role {
        TlsRole::Leader => (
            ke::Role::Leader,
            pa::Role::Leader,
            aead::aes_gcm::Role::Leader,
        ),
        TlsRole::Follower => (
            ke::Role::Follower,
            pa::Role::Follower,
            aead::aes_gcm::Role::Follower,
        ),
    };

    // Key exchange
    let ke = ke::KeyExchangeCore::new(
        ke_channel,
        pa::MpcPointAddition::new(pa_role, p256_send),
        pa::MpcPointAddition::new(pa_role, p256_recv),
        vm.new_thread("ke").await?,
        ke::KeyExchangeConfig::builder()
            .id("ke")
            .role(ke_role)
            .build()
            .unwrap(),
    );

    // PRF
    let prf_role = match role {
        TlsRole::Leader => prf::Role::Leader,
        TlsRole::Follower => prf::Role::Follower,
    };
    let prf = prf::MpcPrf::new(
        prf::PrfConfig::builder().role(prf_role).build().unwrap(),
        vm.new_thread("prf/0").await?,
        vm.new_thread("prf/1").await?,
    );

    // Encrypter
    let block_cipher = block_cipher::MpcBlockCipher::<block_cipher::Aes128, _>::new(
        block_cipher::BlockCipherConfig::builder()
            .id("encrypter/block_cipher")
            .build()
            .unwrap(),
        vm.new_thread("encrypter/block_cipher").await?,
    );

    let stream_cipher = stream_cipher::MpcStreamCipher::<stream_cipher::Aes128Ctr, _>::new(
        stream_cipher::StreamCipherConfig::builder()
            .id("encrypter/stream_cipher")
            .transcript_id("tx")
            .build()
            .unwrap(),
        vm.new_thread_pool("encrypter/stream_cipher", config.num_threads())
            .await?,
    );

    let ghash = universal_hash::ghash::Ghash::new(
        universal_hash::ghash::GhashConfig::builder()
            .id("encrypter/ghash")
            .initial_block_count(64)
            .build()
            .unwrap(),
        gf.clone(),
    );

    let mut encrypter = aead::aes_gcm::MpcAesGcm::new(
        aead::aes_gcm::AesGcmConfig::builder()
            .id("encrypter/aes_gcm")
            .role(aead_role)
            .build()
            .unwrap(),
        encrypter_channel,
        Box::new(block_cipher),
        Box::new(stream_cipher),
        Box::new(ghash),
    );

    encrypter.set_transcript_id(config.opaque_tx_transcript_id());

    // Decrypter
    let block_cipher = block_cipher::MpcBlockCipher::<block_cipher::Aes128, _>::new(
        block_cipher::BlockCipherConfig::builder()
            .id("decrypter/block_cipher")
            .build()
            .unwrap(),
        vm.new_thread("decrypter/block_cipher").await?,
    );

    let stream_cipher = stream_cipher::MpcStreamCipher::<stream_cipher::Aes128Ctr, _>::new(
        stream_cipher::StreamCipherConfig::builder()
            .id("decrypter/stream_cipher")
            .transcript_id("rx")
            .build()
            .unwrap(),
        vm.new_thread_pool("decrypter/stream_cipher", config.num_threads())
            .await?,
    );

    let ghash = universal_hash::ghash::Ghash::new(
        universal_hash::ghash::GhashConfig::builder()
            .id("decrypter/ghash")
            .initial_block_count(64)
            .build()
            .unwrap(),
        gf,
    );

    let mut decrypter = aead::aes_gcm::MpcAesGcm::new(
        aead::aes_gcm::AesGcmConfig::builder()
            .id("decrypter/aes_gcm")
            .role(aead_role)
            .build()
            .unwrap(),
        decrypter_channel,
        Box::new(block_cipher),
        Box::new(stream_cipher),
        Box::new(ghash),
    );

    decrypter.set_transcript_id(config.opaque_rx_transcript_id());

    Ok((
        Box::new(ke),
        Box::new(prf),
        Box::new(encrypter),
        Box::new(decrypter),
    ))
}
