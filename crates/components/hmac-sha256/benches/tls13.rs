#![allow(clippy::let_underscore_future)]

use criterion::{criterion_group, criterion_main, Criterion};

use hmac_sha256::{Mode, Role, Tls13KeySched};
use mpz_common::context::test_mt_context;
use mpz_garble::protocol::semihonest::{Evaluator, Garbler};
use mpz_ot::ideal::cot::ideal_cot;
use mpz_vm_core::{
    memory::{
        binary::{Binary, U8},
        correlated::Delta,
        Array,
    },
    prelude::*,
    Execute, Vm,
};
use rand::{rngs::StdRng, SeedableRng};

#[allow(clippy::unit_arg)]
fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("tls13");
    group.sample_size(10);
    let rt = tokio::runtime::Runtime::new().unwrap();

    group.bench_function("tls13_normal", |b| {
        b.to_async(&rt).iter(|| tls13(Mode::Normal))
    });
    group.bench_function("tls13_reduced", |b| {
        b.to_async(&rt).iter(|| tls13(Mode::Reduced))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

async fn tls13(mode: Mode) {
    let mut rng = StdRng::seed_from_u64(0);

    let pms = [42u8; 32];

    let (mut leader_exec, mut follower_exec) = test_mt_context(8);
    let mut leader_ctx = leader_exec.new_context().await.unwrap();
    let mut follower_ctx = follower_exec.new_context().await.unwrap();

    let delta = Delta::random(&mut rng);
    let (ot_send, ot_recv) = ideal_cot(delta.into_inner());

    let mut leader_vm = Garbler::new(ot_send, [0u8; 16], delta);
    let mut follower_vm = Evaluator::new(ot_recv);

    fn setup_ks(
        vm: &mut (dyn Vm<Binary> + Send),
        pms: [u8; 32],
        mode: Mode,
        role: Role,
    ) -> Tls13KeySched {
        let secret: Array<U8, 32> = vm.alloc().unwrap();
        vm.mark_public(secret).unwrap();
        vm.assign(secret, pms).unwrap();
        vm.commit(secret).unwrap();

        let mut ks = Tls13KeySched::new(mode, role);
        ks.alloc(vm, secret).unwrap();
        ks
    }

    let mut leader_ks = setup_ks(&mut leader_vm, pms, mode, Role::Leader);
    let mut follower_ks = setup_ks(&mut follower_vm, pms, mode, Role::Follower);

    while leader_ks.wants_flush() || follower_ks.wants_flush() {
        tokio::try_join!(
            async {
                leader_ks.flush(&mut leader_vm).unwrap();
                leader_vm.execute_all(&mut leader_ctx).await
            },
            async {
                follower_ks.flush(&mut follower_vm).unwrap();
                follower_vm.execute_all(&mut follower_ctx).await
            }
        )
        .unwrap();
    }

    let hello_hash = [1u8; 32];

    leader_ks.set_hello_hash(hello_hash).unwrap();
    follower_ks.set_hello_hash(hello_hash).unwrap();

    while leader_ks.wants_flush() || follower_ks.wants_flush() {
        tokio::try_join!(
            async {
                leader_ks.flush(&mut leader_vm).unwrap();
                leader_vm.execute_all(&mut leader_ctx).await
            },
            async {
                follower_ks.flush(&mut follower_vm).unwrap();
                follower_vm.execute_all(&mut follower_ctx).await
            }
        )
        .unwrap();
    }

    leader_ks.continue_to_app_keys().unwrap();
    follower_ks.continue_to_app_keys().unwrap();

    while leader_ks.wants_flush() || follower_ks.wants_flush() {
        tokio::try_join!(
            async {
                leader_ks.flush(&mut leader_vm).unwrap();
                leader_vm.execute_all(&mut leader_ctx).await
            },
            async {
                follower_ks.flush(&mut follower_vm).unwrap();
                follower_vm.execute_all(&mut follower_ctx).await
            }
        )
        .unwrap();
    }

    let handshake_hash = [2u8; 32];

    leader_ks.set_handshake_hash(handshake_hash).unwrap();
    follower_ks.set_handshake_hash(handshake_hash).unwrap();

    while leader_ks.wants_flush() || follower_ks.wants_flush() {
        tokio::try_join!(
            async {
                leader_ks.flush(&mut leader_vm).unwrap();
                leader_vm.execute_all(&mut leader_ctx).await
            },
            async {
                follower_ks.flush(&mut follower_vm).unwrap();
                follower_vm.execute_all(&mut follower_ctx).await
            }
        )
        .unwrap();
    }
}
