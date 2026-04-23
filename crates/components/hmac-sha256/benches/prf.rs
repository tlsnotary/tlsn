#![allow(clippy::let_underscore_future)]

use criterion::{Criterion, criterion_group, criterion_main};

use hmac_sha256::{MSMode, NetworkMode, Prf, PrfConfig};
use mpz_common::context::test_mt_context;
use mpz_ideal_vm::IdealVm;
use mpz_vm_core::{
    Execute,
    memory::{Array, binary::U8},
    prelude::*,
};

#[allow(clippy::unit_arg)]
fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("prf");
    group.sample_size(10);
    let rt = tokio::runtime::Runtime::new().unwrap();

    group.bench_function("prf_normal", |b| {
        let config = PrfConfig::new(NetworkMode::Normal, MSMode::Standard);
        b.to_async(&rt).iter(|| prf(config))
    });
    group.bench_function("prf_reduced", |b| {
        let config = PrfConfig::new(NetworkMode::Reduced, MSMode::Standard);
        b.to_async(&rt).iter(|| prf(config))
    });
    group.bench_function("prf_ems_normal", |b| {
        let config = PrfConfig::new(NetworkMode::Normal, MSMode::Extended);
        b.to_async(&rt).iter(|| prf(config))
    });
    group.bench_function("prf_ems_reduced", |b| {
        let config = PrfConfig::new(NetworkMode::Reduced, MSMode::Extended);
        b.to_async(&rt).iter(|| prf(config))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

async fn prf(config: PrfConfig) {
    let pms = [42u8; 32];
    let client_random = [69u8; 32];
    let server_random: [u8; 32] = [96u8; 32];
    let session_hash = [55u8; 32];

    let (mut leader_exec, mut follower_exec) = test_mt_context(8);
    let mut leader_ctx = leader_exec.new_context().unwrap();
    let mut follower_ctx = follower_exec.new_context().unwrap();

    let mut leader_vm = IdealVm::new();
    let mut follower_vm = IdealVm::new();

    let leader_pms: Array<U8, 32> = leader_vm.alloc().unwrap();
    leader_vm.mark_public(leader_pms).unwrap();
    leader_vm.assign(leader_pms, pms).unwrap();
    leader_vm.commit(leader_pms).unwrap();

    let follower_pms: Array<U8, 32> = follower_vm.alloc().unwrap();
    follower_vm.mark_public(follower_pms).unwrap();
    follower_vm.assign(follower_pms, pms).unwrap();
    follower_vm.commit(follower_pms).unwrap();

    let mut leader = Prf::new(config);
    let mut follower = Prf::new(config);

    let leader_output = leader.alloc_pms(&mut leader_vm, leader_pms).unwrap();
    let follower_output = follower.alloc_pms(&mut follower_vm, follower_pms).unwrap();

    if matches!(config.ms, MSMode::Extended) {
        leader.set_session_hash(session_hash.to_vec()).unwrap();
        follower.set_session_hash(session_hash.to_vec()).unwrap();
    }

    leader.set_client_random(client_random);
    follower.set_client_random(client_random);

    leader.set_server_random(server_random).unwrap();
    follower.set_server_random(server_random).unwrap();

    let _ = leader_vm
        .decode(leader_output.keys.client_write_key)
        .unwrap();
    let _ = leader_vm
        .decode(leader_output.keys.server_write_key)
        .unwrap();
    let _ = leader_vm.decode(leader_output.keys.client_iv).unwrap();
    let _ = leader_vm.decode(leader_output.keys.server_iv).unwrap();

    let _ = follower_vm
        .decode(follower_output.keys.client_write_key)
        .unwrap();
    let _ = follower_vm
        .decode(follower_output.keys.server_write_key)
        .unwrap();
    let _ = follower_vm.decode(follower_output.keys.client_iv).unwrap();
    let _ = follower_vm.decode(follower_output.keys.server_iv).unwrap();

    while leader.wants_flush() || follower.wants_flush() {
        tokio::try_join!(
            async {
                leader.flush(&mut leader_vm).unwrap();
                leader_vm.execute_all(&mut leader_ctx).await
            },
            async {
                follower.flush(&mut follower_vm).unwrap();
                follower_vm.execute_all(&mut follower_ctx).await
            }
        )
        .unwrap();
    }

    let cf_hs_hash = [1u8; 32];

    leader.set_cf_hash(cf_hs_hash).unwrap();
    follower.set_cf_hash(cf_hs_hash).unwrap();

    while leader.wants_flush() || follower.wants_flush() {
        tokio::try_join!(
            async {
                leader.flush(&mut leader_vm).unwrap();
                leader_vm.execute_all(&mut leader_ctx).await
            },
            async {
                follower.flush(&mut follower_vm).unwrap();
                follower_vm.execute_all(&mut follower_ctx).await
            }
        )
        .unwrap();
    }

    let _ = leader_vm.decode(leader_output.cf_vd).unwrap();
    let _ = follower_vm.decode(follower_output.cf_vd).unwrap();

    let sf_hs_hash = [2u8; 32];

    leader.set_sf_hash(sf_hs_hash).unwrap();
    follower.set_sf_hash(sf_hs_hash).unwrap();

    while leader.wants_flush() || follower.wants_flush() {
        tokio::try_join!(
            async {
                leader.flush(&mut leader_vm).unwrap();
                leader_vm.execute_all(&mut leader_ctx).await
            },
            async {
                follower.flush(&mut follower_vm).unwrap();
                follower_vm.execute_all(&mut follower_ctx).await
            }
        )
        .unwrap();
    }

    let _ = leader_vm.decode(leader_output.sf_vd).unwrap();
    let _ = follower_vm.decode(follower_output.sf_vd).unwrap();
}
