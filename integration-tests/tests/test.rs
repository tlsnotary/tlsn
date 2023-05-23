use actor_ot::{create_ot_pair, OTActorReceiverConfig, OTActorSenderConfig, ObliviousReveal};
use aead::{
    aes_gcm::{AesGcmConfig, MpcAesGcm, Role as AesGcmRole},
    Aead,
};
use block_cipher::{Aes128, BlockCipherConfigBuilder, MpcBlockCipher};
use ff::Gf2_128;
use hmac_sha256::{MpcPrf, Prf, SessionKeys};
use key_exchange::{KeyExchange, KeyExchangeConfig, Role as KeyExchangeRole};
use mpc_garble::{config::Role as GarbleRole, protocol::deap::DEAPVm, Vm};
use mpc_share_conversion as ff;
use p256::{NonZeroScalar, PublicKey, SecretKey};
use point_addition::{MpcPointAddition, Role as PointAdditionRole, P256};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use tlsn_stream_cipher::{Aes128Ctr, MpcStreamCipher, StreamCipherConfig};
use tlsn_universal_hash::ghash::{Ghash, GhashConfig};
use tokio_util::compat::TokioAsyncReadCompatExt;
use uid_mux::{yamux, UidYamux};
use utils_aio::{codec::BincodeMux, mux::MuxChannel};

#[tokio::test]
async fn test() {
    let mut rng = ChaCha20Rng::seed_from_u64(0);

    let rt = utils_aio::executor::SpawnCompatExt::compat(tokio::runtime::Handle::current());

    let (leader_socket, follower_socket) = tokio::io::duplex(2 << 25);

    let mut leader_mux = UidYamux::new(
        yamux::Config::default(),
        leader_socket.compat(),
        yamux::Mode::Client,
    );
    let mut follower_mux = UidYamux::new(
        yamux::Config::default(),
        follower_socket.compat(),
        yamux::Mode::Server,
    );

    let leader_mux_control = leader_mux.control();
    let follower_mux_control = follower_mux.control();

    tokio::spawn(async move { leader_mux.run().await.unwrap() });
    tokio::spawn(async move { follower_mux.run().await.unwrap() });

    let mut leader_mux = BincodeMux::new(leader_mux_control);
    let mut follower_mux = BincodeMux::new(follower_mux_control);

    let leader_ot_sender_config = OTActorSenderConfig::builder()
        .id("ot/0")
        .initial_count(100_000)
        .build()
        .unwrap();
    let follower_ot_recvr_config = OTActorReceiverConfig::builder()
        .id("ot/0")
        .initial_count(100_000)
        .build()
        .unwrap();

    let follower_ot_sender_config = OTActorSenderConfig::builder()
        .id("ot/1")
        .initial_count(100_000)
        .committed()
        .build()
        .unwrap();
    let leader_ot_recvr_config = OTActorReceiverConfig::builder()
        .id("ot/1")
        .initial_count(100_000)
        .committed()
        .build()
        .unwrap();

    let (mut leader_ot_sender, mut follower_ot_recvr) = create_ot_pair(
        "ot/0",
        &rt,
        leader_mux.clone(),
        follower_mux.clone(),
        leader_ot_sender_config,
        follower_ot_recvr_config,
    )
    .await
    .unwrap();

    let (mut follower_ot_sender, mut leader_ot_recvr) = create_ot_pair(
        "ot/1",
        &rt,
        follower_mux.clone(),
        leader_mux.clone(),
        follower_ot_sender_config,
        leader_ot_recvr_config,
    )
    .await
    .unwrap();

    let mut leader_vm = DEAPVm::new(
        "vm",
        GarbleRole::Leader,
        [0u8; 32],
        leader_mux.get_channel("vm").await.unwrap(),
        Box::new(leader_mux.clone()),
        leader_ot_sender.clone(),
        leader_ot_recvr.clone(),
    );

    let mut follower_vm = DEAPVm::new(
        "vm",
        GarbleRole::Follower,
        [1u8; 32],
        follower_mux.get_channel("vm").await.unwrap(),
        Box::new(follower_mux.clone()),
        follower_ot_sender.clone(),
        follower_ot_recvr.clone(),
    );

    let leader_p256_sender = ff::ConverterSender::<P256, _>::new(
        ff::SenderConfig::builder().id("p256/0").build().unwrap(),
        leader_ot_sender.clone(),
        leader_mux.get_channel("p256/0").await.unwrap(),
    );

    let leader_p256_receiver = ff::ConverterReceiver::<P256, _>::new(
        ff::ReceiverConfig::builder().id("p256/1").build().unwrap(),
        follower_ot_recvr.clone(),
        leader_mux.get_channel("p256/1").await.unwrap(),
    );

    let follower_p256_sender = ff::ConverterSender::<P256, _>::new(
        ff::SenderConfig::builder().id("p256/1").build().unwrap(),
        leader_ot_sender.clone(),
        follower_mux.get_channel("p256/1").await.unwrap(),
    );

    let follower_p256_receiver = ff::ConverterReceiver::<P256, _>::new(
        ff::ReceiverConfig::builder().id("p256/0").build().unwrap(),
        follower_ot_recvr.clone(),
        follower_mux.get_channel("p256/0").await.unwrap(),
    );

    let leader_pa_sender = MpcPointAddition::new(PointAdditionRole::Leader, leader_p256_sender);
    let leader_pa_receiver = MpcPointAddition::new(PointAdditionRole::Leader, leader_p256_receiver);

    let follower_pa_sender =
        MpcPointAddition::new(PointAdditionRole::Follower, follower_p256_sender);

    let follower_pa_receiver =
        MpcPointAddition::new(PointAdditionRole::Follower, follower_p256_receiver);

    let mut leader_ke = key_exchange::KeyExchangeCore::new(
        leader_mux.get_channel("ke").await.unwrap(),
        leader_pa_sender,
        leader_pa_receiver,
        leader_vm.new_thread("ke").await.unwrap(),
        KeyExchangeConfig::builder()
            .id("ke")
            .role(KeyExchangeRole::Leader)
            .build()
            .unwrap(),
    );

    let mut follower_ke = key_exchange::KeyExchangeCore::new(
        follower_mux.get_channel("ke").await.unwrap(),
        follower_pa_sender,
        follower_pa_receiver,
        follower_vm.new_thread("ke").await.unwrap(),
        KeyExchangeConfig::builder()
            .id("ke")
            .role(KeyExchangeRole::Follower)
            .build()
            .unwrap(),
    );

    let mut leader_prf = MpcPrf::new(leader_vm.new_thread("prf").await.unwrap());
    let mut follower_prf = MpcPrf::new(follower_vm.new_thread("prf").await.unwrap());

    let block_cipher_config = BlockCipherConfigBuilder::default()
        .id("aes")
        .build()
        .unwrap();
    let leader_block_cipher = MpcBlockCipher::<Aes128, _>::new(
        block_cipher_config.clone(),
        leader_vm.new_thread("block_cipher").await.unwrap(),
    );
    let follower_block_cipher = MpcBlockCipher::<Aes128, _>::new(
        block_cipher_config,
        follower_vm.new_thread("block_cipher").await.unwrap(),
    );

    let stream_cipher_config = StreamCipherConfig::builder()
        .id("aes-ctr")
        .transcript_id("tx")
        .build()
        .unwrap();
    let leader_stream_cipher = MpcStreamCipher::<Aes128Ctr, _>::new(
        stream_cipher_config.clone(),
        leader_vm.new_thread_pool("aes-ctr", 4).await.unwrap(),
    );
    let follower_stream_cipher = MpcStreamCipher::<Aes128Ctr, _>::new(
        stream_cipher_config,
        follower_vm.new_thread_pool("aes-ctr", 4).await.unwrap(),
    );

    let mut leader_gf2 = ff::ConverterSender::<Gf2_128, _>::new(
        ff::SenderConfig::builder()
            .id("gf2")
            .record()
            .build()
            .unwrap(),
        leader_ot_sender.clone(),
        leader_mux.get_channel("gf2").await.unwrap(),
    );

    let mut follower_gf2 = ff::ConverterReceiver::<Gf2_128, _>::new(
        ff::ReceiverConfig::builder()
            .id("gf2")
            .record()
            .build()
            .unwrap(),
        follower_ot_recvr.clone(),
        follower_mux.get_channel("gf2").await.unwrap(),
    );

    let ghash_config = GhashConfig::builder()
        .id("aes_gcm/ghash")
        .initial_block_count(64)
        .build()
        .unwrap();

    let leader_ghash = Ghash::new(ghash_config.clone(), leader_gf2.handle().unwrap());
    let follower_ghash = Ghash::new(ghash_config, follower_gf2.handle().unwrap());

    let mut leader_aead = MpcAesGcm::new(
        AesGcmConfig::builder()
            .id("aes_gcm")
            .role(AesGcmRole::Leader)
            .build()
            .unwrap(),
        leader_mux.get_channel("aes_gcm").await.unwrap(),
        Box::new(leader_block_cipher),
        Box::new(leader_stream_cipher),
        Box::new(leader_ghash),
    );

    let mut follower_aead = MpcAesGcm::new(
        AesGcmConfig::builder()
            .id("aes_gcm")
            .role(AesGcmRole::Follower)
            .build()
            .unwrap(),
        follower_mux.get_channel("aes_gcm").await.unwrap(),
        Box::new(follower_block_cipher),
        Box::new(follower_stream_cipher),
        Box::new(follower_ghash),
    );

    let leader_private_key = SecretKey::random(&mut rng);
    let follower_private_key = SecretKey::random(&mut rng);
    let server_public_key = PublicKey::from_secret_scalar(&NonZeroScalar::random(&mut rng));

    // Setup complete

    tokio::try_join!(leader_ot_sender.setup(), follower_ot_recvr.setup()).unwrap();
    tokio::try_join!(follower_ot_sender.setup(), leader_ot_recvr.setup()).unwrap();

    let _ = tokio::try_join!(
        leader_ke.compute_client_key(leader_private_key),
        follower_ke.compute_client_key(follower_private_key)
    )
    .unwrap();

    leader_ke.set_server_key(server_public_key);

    let (leader_pms, follower_pms) =
        tokio::try_join!(leader_ke.compute_pms(), follower_ke.compute_pms()).unwrap();

    let (leader_session_keys, follower_session_keys) = tokio::try_join!(
        leader_prf.compute_session_keys_private([0u8; 32], [0u8; 32], leader_pms.into_value()),
        follower_prf.compute_session_keys_blind(follower_pms.into_value())
    )
    .unwrap();

    let SessionKeys {
        client_write_key: leader_key,
        client_iv: leader_iv,
        ..
    } = leader_session_keys;

    let SessionKeys {
        client_write_key: follower_key,
        client_iv: follower_iv,
        ..
    } = follower_session_keys;

    tokio::try_join!(
        leader_aead.set_key(leader_key, leader_iv),
        follower_aead.set_key(follower_key, follower_iv)
    )
    .unwrap();

    let msg = vec![0u8; 128];

    let _ = tokio::try_join!(
        leader_aead.encrypt_private(vec![0u8; 8], msg.clone(), vec![]),
        follower_aead.encrypt_blind(vec![0u8; 8], msg.len(), vec![])
    )
    .unwrap();

    follower_ot_sender.reveal().await.unwrap();

    tokio::try_join!(leader_vm.finalize(), follower_vm.finalize()).unwrap();
    tokio::try_join!(leader_gf2.reveal(), follower_gf2.verify()).unwrap();
}
