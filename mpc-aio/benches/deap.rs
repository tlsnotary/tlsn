use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mpc_aio::protocol::garble::exec::deap::mock_deap_pair;
use mpc_circuits::{Circuit, WireGroup, AES_128_REVERSE};
use mpc_core::garble::config::GarbleConfigBuilder;
use rand_chacha::ChaCha12Rng;
use rand_core::SeedableRng;

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("deap");

    let circ = Arc::new(Circuit::load_bytes(AES_128_REVERSE).unwrap());
    group.bench_function(circ.name(), |b| {
        b.iter(|| {
            black_box({
                let (leader, follower) = mock_deap_pair();

                let leader_input = circ.input(0).unwrap().to_value(vec![0u8; 16]).unwrap();
                let follower_input = circ.input(1).unwrap().to_value(vec![0u8; 16]).unwrap();

                let leader_circ = circ.clone();
                let leader_fut = async move {
                    let config = GarbleConfigBuilder::default_dual_with_rng(
                        &mut ChaCha12Rng::seed_from_u64(0),
                        leader_circ,
                    )
                    .build()
                    .unwrap();

                    let (leader_output, leader) =
                        leader.execute(config, vec![leader_input]).await.unwrap();
                    leader.verify().await.unwrap();
                    leader_output
                };

                let follower_circ = circ.clone();
                let follower_fut = async move {
                    let config = GarbleConfigBuilder::default_dual_with_rng(
                        &mut ChaCha12Rng::seed_from_u64(0),
                        follower_circ,
                    )
                    .build()
                    .unwrap();

                    let (follower_output, follower) = follower
                        .execute(config, vec![follower_input])
                        .await
                        .unwrap();
                    follower.verify().await.unwrap();
                    follower_output
                };

                let _ =
                    futures::executor::block_on(
                        async move { futures::join!(leader_fut, follower_fut) },
                    );
            })
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
