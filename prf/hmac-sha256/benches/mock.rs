use std::sync::Arc;

use futures::lock::Mutex;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use hmac_sha256::mock;
use hmac_sha256_core::{PRFFollowerConfigBuilder, PRFLeaderConfigBuilder};

async fn bench_prf() {
    let leader_config = PRFLeaderConfigBuilder::default()
        .id("test".to_string())
        .build()
        .unwrap();
    let follower_config = PRFFollowerConfigBuilder::default()
        .id("test".to_string())
        .build()
        .unwrap();

    let (mut leader, mut follower) = mock::create_mock_prf_pair(leader_config, follower_config);

    let pms = [42u8; 32];

    let client_random = [0u8; 32];
    let server_random = [1u8; 32];

    let ((leader_share, follower_share), (leader_encoder, follower_encoder)) =
        mock::create_mock_pms_labels(pms);

    leader.set_encoder(Arc::new(Mutex::new(leader_encoder)));
    follower.set_encoder(Arc::new(Mutex::new(follower_encoder)));

    futures::join!(
        async move {
            leader
                .compute_session_keys(client_random, server_random, leader_share)
                .await
                .unwrap();
            _ = leader.compute_client_finished_vd([0u8; 32]).await.unwrap();
            _ = leader.compute_server_finished_vd([0u8; 32]).await.unwrap();
        },
        async move {
            follower.compute_session_keys(follower_share).await.unwrap();
            _ = follower.compute_client_finished_vd().await.unwrap();
            _ = follower.compute_server_finished_vd().await.unwrap();
        }
    );
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("prf");

    group.bench_function("prf", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async { black_box(bench_prf().await) })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
