use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mpc_aio::protocol::garble::exec::dual::mock_dualex_pair;
use mpc_circuits::{Circuit, WireGroup, AES_128_REVERSE};
use mpc_core::garble::{exec::dual::DualExConfigBuilder, FullInputSet};
use rand::SeedableRng;
use rand_chacha::ChaCha12Rng;
use std::sync::Arc;

async fn bench_dualex(circ: Arc<Circuit>) {
    let mut rng = ChaCha12Rng::seed_from_u64(0);
    let config = DualExConfigBuilder::default()
        .id("bench".to_string())
        .build()
        .unwrap();
    let (leader, follower) = mock_dualex_pair(config, circ.clone());

    let leader_input = circ.input(0).unwrap().to_value(vec![0u8; 16]).unwrap();
    let follower_input = circ.input(1).unwrap().to_value(vec![0u8; 16]).unwrap();

    let leader_labels = FullInputSet::generate(&mut rng, &circ, None);
    let follower_labels = FullInputSet::generate(&mut rng, &circ, None);

    let leader_task = {
        let leader_input = leader_input.clone();
        let follower_input = follower_input.clone();
        tokio::spawn(async move {
            leader
                .setup_inputs(
                    leader_labels,
                    vec![leader_input.clone()],
                    vec![follower_input.group().clone()],
                    vec![leader_input.clone()],
                    vec![],
                )
                .await
                .unwrap()
                .execute()
                .await
                .unwrap()
        })
    };

    let follower_task = tokio::spawn(async move {
        follower
            .setup_inputs(
                follower_labels,
                vec![follower_input.clone()],
                vec![leader_input.group().clone()],
                vec![follower_input],
                vec![],
            )
            .await
            .unwrap()
            .execute()
            .await
            .unwrap()
    });

    _ = tokio::join!(leader_task, follower_task);
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("dualex");

    let circ = Circuit::load_bytes(AES_128_REVERSE).unwrap();
    group.bench_function(circ.id().clone().to_string(), |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async { black_box(bench_dualex(circ.clone()).await) })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
