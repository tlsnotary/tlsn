use criterion::{criterion_group, criterion_main, Criterion, Throughput};

use mpz_garble::{protocol::deap::mock::create_mock_deap_vm, Memory, Vm};
use tlsn_stream_cipher::{Aes128Ctr, MpcStreamCipher, StreamCipher, StreamCipherConfigBuilder};

async fn bench_stream_cipher_encrypt(thread_count: usize, len: usize) {
    let (mut leader_vm, mut follower_vm) = create_mock_deap_vm("test").await;

    let leader_thread = leader_vm.new_thread("key_config").await.unwrap();
    let leader_key = leader_thread.new_public_input::<[u8; 16]>("key").unwrap();
    let leader_iv = leader_thread.new_public_input::<[u8; 4]>("iv").unwrap();

    leader_thread.assign(&leader_key, [0u8; 16]).unwrap();
    leader_thread.assign(&leader_iv, [0u8; 4]).unwrap();

    let follower_thread = follower_vm.new_thread("key_config").await.unwrap();
    let follower_key = follower_thread.new_public_input::<[u8; 16]>("key").unwrap();
    let follower_iv = follower_thread.new_public_input::<[u8; 4]>("iv").unwrap();

    follower_thread.assign(&follower_key, [0u8; 16]).unwrap();
    follower_thread.assign(&follower_iv, [0u8; 4]).unwrap();

    let leader_thread_pool = leader_vm
        .new_thread_pool("mock", thread_count)
        .await
        .unwrap();
    let follower_thread_pool = follower_vm
        .new_thread_pool("mock", thread_count)
        .await
        .unwrap();

    let leader_config = StreamCipherConfigBuilder::default()
        .id("test".to_string())
        .build()
        .unwrap();

    let follower_config = StreamCipherConfigBuilder::default()
        .id("test".to_string())
        .build()
        .unwrap();

    let mut leader = MpcStreamCipher::<Aes128Ctr, _>::new(leader_config, leader_thread_pool);
    leader.set_key(leader_key, leader_iv);

    let mut follower = MpcStreamCipher::<Aes128Ctr, _>::new(follower_config, follower_thread_pool);
    follower.set_key(follower_key, follower_iv);

    let plaintext = vec![0u8; len];
    let explicit_nonce = vec![0u8; 8];

    _ = tokio::try_join!(
        leader.encrypt_private(explicit_nonce.clone(), plaintext),
        follower.encrypt_blind(explicit_nonce, len)
    )
    .unwrap();

    _ = tokio::try_join!(leader_vm.finalize(), follower_vm.finalize()).unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("stream_cipher/encrypt_private");
    let rt = tokio::runtime::Runtime::new().unwrap();

    let thread_count = 8;
    let len = 128;

    group.throughput(Throughput::Bytes(len as u64));
    group.bench_function(format!("{}", len), |b| {
        b.to_async(&rt)
            .iter(|| async { bench_stream_cipher_encrypt(thread_count, len).await })
    });

    drop(group);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
