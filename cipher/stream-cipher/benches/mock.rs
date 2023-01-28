use std::sync::Arc;

use futures::lock::Mutex;

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

use tlsn_stream_cipher::{
    cipher::{Aes128Ctr, CtrCircuitSuite},
    mock::{create_mock_labels, create_mock_stream_cipher_pair},
    StreamCipherFollower, StreamCipherFollowerConfigBuilder, StreamCipherLeader,
    StreamCipherLeaderConfigBuilder,
};

async fn bench_stream_cipher<C: CtrCircuitSuite + 'static>(msg: Vec<u8>) {
    let explicit_nonce = [0u8; 8];

    let leader_config = StreamCipherLeaderConfigBuilder::default()
        .id("bench".to_string())
        .build()
        .unwrap();
    let follower_config = StreamCipherFollowerConfigBuilder::default()
        .id("bench".to_string())
        .build()
        .unwrap();

    let msg_len = msg.len();

    let (mut leader, mut follower) =
        create_mock_stream_cipher_pair::<C>(leader_config, follower_config);
    let ((leader_encoder, leader_labels), (follower_encoder, follower_labels)) =
        create_mock_labels(vec![0u8; 16], vec![0u8; 4]);

    let follower_task = tokio::spawn(async move {
        follower.set_keys(follower_labels);
        follower.set_encoder(Arc::new(Mutex::new(follower_encoder)));

        follower
            .apply_key_stream(explicit_nonce.to_vec(), msg_len, false)
            .await
            .unwrap();

        follower.finalize().await.unwrap();
    });

    leader.set_keys(leader_labels);
    leader.set_encoder(Arc::new(Mutex::new(leader_encoder)));

    let _ = leader
        .apply_key_stream(explicit_nonce.to_vec(), msg, false)
        .await
        .unwrap();

    leader.finalize().await.unwrap();

    follower_task.await.unwrap();
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("stream_cipher");

    let len = 128;

    group.throughput(Throughput::Bytes(len as u64));

    group.bench_function(format!("{}", len), |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async { black_box(bench_stream_cipher::<Aes128Ctr>(vec![0; len]).await) })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
