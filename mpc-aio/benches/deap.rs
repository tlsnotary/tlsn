use std::sync::Arc;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mpc_aio::protocol::garble::exec::deap::mock_deap_pair;
use mpc_circuits::{Circuit, WireGroup, AES_128_REVERSE};
use mpc_core::garble::FullInputLabels;
use rand::thread_rng;

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("deap");

    let circ = Arc::new(Circuit::load_bytes(AES_128_REVERSE).unwrap());
    group.bench_function(circ.name(), |b| {
        let mut rng = thread_rng();
        b.iter(|| {
            black_box({
                let (leader, follower) = mock_deap_pair();

                let leader_input = circ.input(0).unwrap().to_value(vec![0u8; 16]).unwrap();
                let follower_input = circ.input(1).unwrap().to_value(vec![0u8; 16]).unwrap();

                let leader_circ = circ.clone();
                let (leader_labels, leader_delta) =
                    FullInputLabels::generate_set(&mut rng, &leader_circ, None);
                let leader_fut = async move {
                    let (_, leader) = leader
                        .execute(leader_circ, &[leader_input], &leader_labels, leader_delta)
                        .await
                        .unwrap();
                    leader.verify().await.unwrap();
                };

                let follower_circ = circ.clone();
                let (follower_labels, follower_delta) =
                    FullInputLabels::generate_set(&mut rng, &follower_circ, None);
                let follower_fut = async move {
                    let (_, follower) = follower
                        .execute(
                            follower_circ,
                            &[follower_input],
                            &follower_labels,
                            follower_delta,
                        )
                        .await
                        .unwrap();
                    follower.verify().await.unwrap();
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
