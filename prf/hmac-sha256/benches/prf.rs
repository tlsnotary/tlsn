use criterion::{black_box, criterion_group, criterion_main, Criterion};

use hmac_sha256::{MpcPrf, Prf};
use mpc_garble::{protocol::deap::mock::create_mock_deap_vm, Memory, Vm};

async fn bench_prf() {
    let (mut leader_vm, mut follower_vm) = create_mock_deap_vm("bench").await;

    let mut leader = MpcPrf::new(leader_vm.new_thread("bench_thread").await.unwrap());
    let mut follower = MpcPrf::new(follower_vm.new_thread("bench_thread").await.unwrap());

    let pms = [42u8; 32];

    let client_random = [0u8; 32];
    let server_random = [1u8; 32];
    let cf_hs_hash = [2u8; 32];
    let sf_hs_hash = [3u8; 32];

    let leader_thread = leader_vm.new_thread("setup").await.unwrap();
    let follower_thread = follower_vm.new_thread("setup").await.unwrap();

    let leader_pms = leader_thread.new_public_input("pms", pms).unwrap();
    let follower_pms = follower_thread.new_public_input("pms", pms).unwrap();

    let (_leader_keys, _follower_keys) = futures::try_join!(
        leader.compute_session_keys_private(client_random, server_random, leader_pms),
        follower.compute_session_keys_blind(follower_pms)
    )
    .unwrap();

    let _ = futures::try_join!(
        leader.compute_client_finished_vd_private(cf_hs_hash),
        follower.compute_client_finished_vd_blind()
    )
    .unwrap();

    let _ = futures::try_join!(
        leader.compute_server_finished_vd_private(sf_hs_hash),
        follower.compute_server_finished_vd_blind()
    )
    .unwrap();

    futures::try_join!(leader_vm.finalize(), follower_vm.finalize()).unwrap();
}

#[allow(clippy::unit_arg)]
fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("prf");
    group.sample_size(10);
    let rt = tokio::runtime::Runtime::new().unwrap();
    group.bench_function("prf", |b| {
        b.to_async(&rt)
            .iter(|| async { black_box(bench_prf().await) })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
