#![allow(clippy::let_underscore_future)]

use criterion::{criterion_group, criterion_main, Criterion};

use hmac_sha256::{Mode, MpcPrf};
use mpz_common::context::test_mt_context;
use mpz_garble::protocol::semihonest::{Evaluator, Garbler};
use mpz_ot::ideal::cot::ideal_cot;
use mpz_vm_core::{
    memory::{binary::U8, correlated::Delta, Array},
    prelude::*,
    Execute,
};
use rand::{rngs::StdRng, SeedableRng};

#[allow(clippy::unit_arg)]
fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("prf");
    group.sample_size(10);
    let rt = tokio::runtime::Runtime::new().unwrap();

    group.bench_function("prf_normal", |b| b.to_async(&rt).iter(|| prf(Mode::Normal)));
    group.bench_function("prf_reduced", |b| {
        b.to_async(&rt).iter(|| prf(Mode::Reduced))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

async fn prf(mode: Mode) {
    let mut rng = StdRng::seed_from_u64(0);

    let pms = [42u8; 32];
    let client_random = [69u8; 32];
    let server_random: [u8; 32] = [96u8; 32];

    let (mut leader_exec, mut follower_exec) = test_mt_context(8);
    let mut leader_ctx = leader_exec.new_context().await.unwrap();
    let mut follower_ctx = follower_exec.new_context().await.unwrap();

    let delta = Delta::random(&mut rng);
    let (ot_send, ot_recv) = ideal_cot(delta.into_inner());

    let mut leader_vm = Garbler::new(ot_send, [0u8; 16], delta);
    let mut follower_vm = Evaluator::new(ot_recv);

    let leader_pms: Array<U8, 32> = leader_vm.alloc().unwrap();
    leader_vm.mark_public(leader_pms).unwrap();
    leader_vm.assign(leader_pms, pms).unwrap();
    leader_vm.commit(leader_pms).unwrap();

    let follower_pms: Array<U8, 32> = follower_vm.alloc().unwrap();
    follower_vm.mark_public(follower_pms).unwrap();
    follower_vm.assign(follower_pms, pms).unwrap();
    follower_vm.commit(follower_pms).unwrap();

    let mut leader = MpcPrf::new(mode);
    let mut follower = MpcPrf::new(mode);

    let leader_output = leader.alloc(&mut leader_vm, leader_pms).unwrap();
    let follower_output = follower.alloc(&mut follower_vm, follower_pms).unwrap();

    leader.set_client_random(client_random).unwrap();
    follower.set_client_random(client_random).unwrap();

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
