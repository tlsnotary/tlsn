use criterion::{black_box, criterion_group, criterion_main, Criterion};
use mpc_aio::protocol::{garble::exec::dual::mock_dualex_pair, point_addition::P256SecretShare};
use tls_2pc_aio::prf::{PRFFollower, PRFLeader, PRFMessage};
use tokio::runtime::Runtime;
use utils_aio::duplex::DuplexChannel;

async fn run_prf() {
    let (leader_channel, follower_channel) = DuplexChannel::<PRFMessage>::new();
    let (gc_leader, gc_follower) = mock_dualex_pair();
    let leader = PRFLeader::new(Box::new(leader_channel), gc_leader);
    let follower = PRFFollower::new(Box::new(follower_channel), gc_follower);

    let (task_leader, task_follower) = tokio::join!(
        tokio::task::spawn_blocking(move || {
            futures::executor::block_on(leader.compute_session_keys(
                [0u8; 32],
                [0u8; 32],
                P256SecretShare::new([0u8; 32]),
            ))
        }),
        tokio::task::spawn_blocking(move || {
            futures::executor::block_on(
                follower.compute_session_keys(P256SecretShare::new([0u8; 32])),
            )
        })
    );

    let leader_keys = task_leader.unwrap().unwrap();
    let follower_keys = task_follower.unwrap().unwrap();

    black_box((leader_keys, follower_keys));
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("prf");

    group.bench_function("run_prf", |b| {
        b.to_async(Runtime::new().unwrap()).iter(|| run_prf());
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
