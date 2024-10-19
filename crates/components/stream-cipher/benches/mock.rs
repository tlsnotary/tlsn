use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use mpz_garble::{protocol::deap::mock::create_mock_deap_vm, Memory};
use tlsn_stream_cipher::{
    Aes128Ctr, CtrCircuit, MpcStreamCipher, StreamCipher, StreamCipherConfigBuilder,
};

async fn bench_stream_cipher_encrypt(len: usize) {
    let (leader_vm, follower_vm) = create_mock_deap_vm();

    let leader_key = leader_vm.new_public_input::<[u8; 16]>("key").unwrap();
    let leader_iv = leader_vm.new_public_input::<[u8; 4]>("iv").unwrap();

    leader_vm.assign(&leader_key, [0u8; 16]).unwrap();
    leader_vm.assign(&leader_iv, [0u8; 4]).unwrap();

    let follower_key = follower_vm.new_public_input::<[u8; 16]>("key").unwrap();
    let follower_iv = follower_vm.new_public_input::<[u8; 4]>("iv").unwrap();

    follower_vm.assign(&follower_key, [0u8; 16]).unwrap();
    follower_vm.assign(&follower_iv, [0u8; 4]).unwrap();

    let leader_config = StreamCipherConfigBuilder::default()
        .id("test".to_string())
        .build()
        .unwrap();

    let follower_config = StreamCipherConfigBuilder::default()
        .id("test".to_string())
        .build()
        .unwrap();

    let mut leader = MpcStreamCipher::<Aes128Ctr, _>::new(leader_config, leader_vm);
    leader.set_key(leader_key, leader_iv);

    let mut follower = MpcStreamCipher::<Aes128Ctr, _>::new(follower_config, follower_vm);
    follower.set_key(follower_key, follower_iv);

    let plaintext = vec![0u8; len];
    let explicit_nonce = vec![0u8; 8];

    _ = tokio::try_join!(
        leader.encrypt_private(explicit_nonce.clone(), plaintext),
        follower.encrypt_blind(explicit_nonce, len)
    )
    .unwrap();

    _ = tokio::try_join!(
        leader.thread_mut().finalize(),
        follower.thread_mut().finalize()
    )
    .unwrap();
}

async fn bench_stream_cipher_zk(len: usize) {
    let (leader_vm, follower_vm) = create_mock_deap_vm();

    let key = [0u8; 16];
    let iv = [0u8; 4];

    let leader_key = leader_vm.new_public_input::<[u8; 16]>("key").unwrap();
    let leader_iv = leader_vm.new_public_input::<[u8; 4]>("iv").unwrap();

    leader_vm.assign(&leader_key, key).unwrap();
    leader_vm.assign(&leader_iv, iv).unwrap();

    let follower_key = follower_vm.new_public_input::<[u8; 16]>("key").unwrap();
    let follower_iv = follower_vm.new_public_input::<[u8; 4]>("iv").unwrap();

    follower_vm.assign(&follower_key, key).unwrap();
    follower_vm.assign(&follower_iv, iv).unwrap();

    let leader_config = StreamCipherConfigBuilder::default()
        .id("test".to_string())
        .build()
        .unwrap();

    let follower_config = StreamCipherConfigBuilder::default()
        .id("test".to_string())
        .build()
        .unwrap();

    let mut leader = MpcStreamCipher::<Aes128Ctr, _>::new(leader_config, leader_vm);
    leader.set_key(leader_key, leader_iv);

    let mut follower = MpcStreamCipher::<Aes128Ctr, _>::new(follower_config, follower_vm);
    follower.set_key(follower_key, follower_iv);

    futures::try_join!(leader.decode_key_private(), follower.decode_key_blind()).unwrap();

    let plaintext = vec![0u8; len];
    let explicit_nonce = [0u8; 8];
    let ciphertext = Aes128Ctr::apply_keystream(&key, &iv, 2, &explicit_nonce, &plaintext).unwrap();

    _ = tokio::try_join!(
        leader.prove_plaintext(explicit_nonce.to_vec(), plaintext),
        follower.verify_plaintext(explicit_nonce.to_vec(), ciphertext)
    )
    .unwrap();

    _ = tokio::try_join!(
        leader.thread_mut().finalize(),
        follower.thread_mut().finalize()
    )
    .unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let len = 1024;

    let mut group = c.benchmark_group("stream_cipher/encrypt_private");
    group.throughput(Throughput::Bytes(len as u64));
    group.bench_function(BenchmarkId::from_parameter(len), |b| {
        b.to_async(&rt)
            .iter(|| async { bench_stream_cipher_encrypt(len).await })
    });

    drop(group);

    let mut group = c.benchmark_group("stream_cipher/zk");
    group.throughput(Throughput::Bytes(len as u64));
    group.bench_function(BenchmarkId::from_parameter(len), |b| {
        b.to_async(&rt)
            .iter(|| async { bench_stream_cipher_zk(len).await })
    });

    drop(group);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
