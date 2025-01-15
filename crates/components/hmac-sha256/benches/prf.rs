use criterion::{criterion_group, criterion_main, Criterion};

use hmac_sha256::{MpcPrf, Prf, PrfConfig, Role};
use mpz_common::executor::{mt::MTConfig, test_mt_executor};
use mpz_garble::protocol::semihonest::{Evaluator, Generator};
use mpz_ot::ideal::cot::ideal_cot;
use mpz_vm_core::{
    memory::{binary::U8, correlated::Delta, Array},
    prelude::*,
};
use rand::{rngs::StdRng, SeedableRng};

#[allow(clippy::unit_arg)]
fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("prf");
    group.sample_size(10);
    let rt = tokio::runtime::Runtime::new().unwrap();

    group.bench_function("prf", |b| b.to_async(&rt).iter(prf));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

async fn prf() {
    let mut rng = StdRng::seed_from_u64(0);

    let pms = [42u8; 32];
    let client_random = [69u8; 32];
    let server_random: [u8; 32] = [96u8; 32];

    let (mut leader_exec, mut follower_exec) = test_mt_executor(128, MTConfig::default());
    let mut leader_ctx = leader_exec.new_thread().await.unwrap();
    let mut follower_ctx = follower_exec.new_thread().await.unwrap();

    let delta = Delta::random(&mut rng);
    let (ot_send, ot_recv) = ideal_cot(delta.into_inner());

    let mut leader_vm = Generator::new(ot_send, [0u8; 16], delta);
    let mut follower_vm = Evaluator::new(ot_recv);

    let leader_pms: Array<U8, 32> = leader_vm.alloc().unwrap();
    leader_vm.mark_public(leader_pms).unwrap();
    leader_vm.assign(leader_pms, pms).unwrap();
    leader_vm.commit(leader_pms).unwrap();

    let follower_pms: Array<U8, 32> = follower_vm.alloc().unwrap();
    follower_vm.mark_public(follower_pms).unwrap();
    follower_vm.assign(follower_pms, pms).unwrap();
    follower_vm.commit(follower_pms).unwrap();

    let mut leader = MpcPrf::new(PrfConfig::builder().role(Role::Leader).build().unwrap());
    let mut follower = MpcPrf::new(PrfConfig::builder().role(Role::Follower).build().unwrap());

    let leader_output = leader.setup(&mut leader_vm, leader_pms).unwrap();
    let follower_output = follower.setup(&mut follower_vm, follower_pms).unwrap();

    leader
        .set_client_random(&mut leader_vm, Some(client_random))
        .unwrap();
    follower.set_client_random(&mut follower_vm, None).unwrap();

    leader
        .set_server_random(&mut leader_vm, server_random)
        .unwrap();
    follower
        .set_server_random(&mut follower_vm, server_random)
        .unwrap();

    #[allow(clippy::let_underscore_future)]
    let _ = leader_vm
        .decode(leader_output.keys.client_write_key)
        .unwrap();
    #[allow(clippy::let_underscore_future)]
    let _ = leader_vm
        .decode(leader_output.keys.server_write_key)
        .unwrap();
    #[allow(clippy::let_underscore_future)]
    let _ = leader_vm.decode(leader_output.keys.client_iv).unwrap();
    #[allow(clippy::let_underscore_future)]
    let _ = leader_vm.decode(leader_output.keys.server_iv).unwrap();

    #[allow(clippy::let_underscore_future)]
    let _ = follower_vm
        .decode(follower_output.keys.client_write_key)
        .unwrap();
    #[allow(clippy::let_underscore_future)]
    let _ = follower_vm
        .decode(follower_output.keys.server_write_key)
        .unwrap();
    #[allow(clippy::let_underscore_future)]
    let _ = follower_vm.decode(follower_output.keys.client_iv).unwrap();
    #[allow(clippy::let_underscore_future)]
    let _ = follower_vm.decode(follower_output.keys.server_iv).unwrap();

    futures::join!(
        async {
            leader_vm.flush(&mut leader_ctx).await.unwrap();
            leader_vm.execute(&mut leader_ctx).await.unwrap();
            leader_vm.flush(&mut leader_ctx).await.unwrap();
        },
        async {
            follower_vm.flush(&mut follower_ctx).await.unwrap();
            follower_vm.execute(&mut follower_ctx).await.unwrap();
            follower_vm.flush(&mut follower_ctx).await.unwrap();
        }
    );

    let cf_hs_hash = [1u8; 32];
    let sf_hs_hash = [2u8; 32];

    leader.set_cf_hash(&mut leader_vm, cf_hs_hash).unwrap();
    leader.set_sf_hash(&mut leader_vm, sf_hs_hash).unwrap();

    follower.set_cf_hash(&mut follower_vm, cf_hs_hash).unwrap();
    follower.set_sf_hash(&mut follower_vm, sf_hs_hash).unwrap();

    #[allow(clippy::let_underscore_future)]
    let _ = leader_vm.decode(leader_output.cf_vd).unwrap();
    #[allow(clippy::let_underscore_future)]
    let _ = leader_vm.decode(leader_output.sf_vd).unwrap();

    #[allow(clippy::let_underscore_future)]
    let _ = follower_vm.decode(follower_output.cf_vd).unwrap();
    #[allow(clippy::let_underscore_future)]
    let _ = follower_vm.decode(follower_output.sf_vd).unwrap();

    futures::join!(
        async {
            leader_vm.flush(&mut leader_ctx).await.unwrap();
            leader_vm.execute(&mut leader_ctx).await.unwrap();
            leader_vm.flush(&mut leader_ctx).await.unwrap();
        },
        async {
            follower_vm.flush(&mut follower_ctx).await.unwrap();
            follower_vm.execute(&mut follower_ctx).await.unwrap();
            follower_vm.flush(&mut follower_ctx).await.unwrap();
        }
    );
}
