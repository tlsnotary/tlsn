use criterion::{criterion_group, criterion_main, Criterion};

use hmac_sha256::{MpcPrf, Prf, PrfConfig, Role};
use mpz_common::executor::test_mt_executor;
use mpz_garble::{config::Role as DEAPRole, protocol::deap::DEAPThread, Memory};
use mpz_ot::ideal::ot::ideal_ot;

#[allow(clippy::unit_arg)]
fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("prf");
    group.sample_size(10);
    let rt = tokio::runtime::Runtime::new().unwrap();

    group.bench_function("prf_preprocess", |b| b.to_async(&rt).iter(preprocess));
    group.bench_function("prf", |b| b.to_async(&rt).iter(prf));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

async fn preprocess() {
    let (mut leader_exec, mut follower_exec) = test_mt_executor(128);

    let (leader_ot_send_0, follower_ot_recv_0) = ideal_ot();
    let (follower_ot_send_0, leader_ot_recv_0) = ideal_ot();
    let (leader_ot_send_1, follower_ot_recv_1) = ideal_ot();
    let (follower_ot_send_1, leader_ot_recv_1) = ideal_ot();

    let leader_thread_0 = DEAPThread::new(
        DEAPRole::Leader,
        [0u8; 32],
        leader_exec.new_thread().await.unwrap(),
        leader_ot_send_0,
        leader_ot_recv_0,
    );
    let leader_thread_1 = leader_thread_0
        .new_thread(
            leader_exec.new_thread().await.unwrap(),
            leader_ot_send_1,
            leader_ot_recv_1,
        )
        .unwrap();

    let follower_thread_0 = DEAPThread::new(
        DEAPRole::Follower,
        [0u8; 32],
        follower_exec.new_thread().await.unwrap(),
        follower_ot_send_0,
        follower_ot_recv_0,
    );
    let follower_thread_1 = follower_thread_0
        .new_thread(
            follower_exec.new_thread().await.unwrap(),
            follower_ot_send_1,
            follower_ot_recv_1,
        )
        .unwrap();

    let leader_pms = leader_thread_0.new_public_input::<[u8; 32]>("pms").unwrap();
    let follower_pms = follower_thread_0
        .new_public_input::<[u8; 32]>("pms")
        .unwrap();

    let mut leader = MpcPrf::new(
        PrfConfig::builder().role(Role::Leader).build().unwrap(),
        leader_thread_0,
        leader_thread_1,
    );
    let mut follower = MpcPrf::new(
        PrfConfig::builder().role(Role::Follower).build().unwrap(),
        follower_thread_0,
        follower_thread_1,
    );

    futures::join!(
        async {
            leader.setup(leader_pms).await.unwrap();
            leader.set_client_random(Some([0u8; 32])).await.unwrap();
            leader.preprocess().await.unwrap();
        },
        async {
            follower.setup(follower_pms).await.unwrap();
            follower.set_client_random(None).await.unwrap();
            follower.preprocess().await.unwrap();
        }
    );
}

async fn prf() {
    let (mut leader_exec, mut follower_exec) = test_mt_executor(128);

    let (leader_ot_send_0, follower_ot_recv_0) = ideal_ot();
    let (follower_ot_send_0, leader_ot_recv_0) = ideal_ot();
    let (leader_ot_send_1, follower_ot_recv_1) = ideal_ot();
    let (follower_ot_send_1, leader_ot_recv_1) = ideal_ot();

    let leader_thread_0 = DEAPThread::new(
        DEAPRole::Leader,
        [0u8; 32],
        leader_exec.new_thread().await.unwrap(),
        leader_ot_send_0,
        leader_ot_recv_0,
    );
    let leader_thread_1 = leader_thread_0
        .new_thread(
            leader_exec.new_thread().await.unwrap(),
            leader_ot_send_1,
            leader_ot_recv_1,
        )
        .unwrap();

    let follower_thread_0 = DEAPThread::new(
        DEAPRole::Follower,
        [0u8; 32],
        follower_exec.new_thread().await.unwrap(),
        follower_ot_send_0,
        follower_ot_recv_0,
    );
    let follower_thread_1 = follower_thread_0
        .new_thread(
            follower_exec.new_thread().await.unwrap(),
            follower_ot_send_1,
            follower_ot_recv_1,
        )
        .unwrap();

    let leader_pms = leader_thread_0.new_public_input::<[u8; 32]>("pms").unwrap();
    let follower_pms = follower_thread_0
        .new_public_input::<[u8; 32]>("pms")
        .unwrap();

    let mut leader = MpcPrf::new(
        PrfConfig::builder().role(Role::Leader).build().unwrap(),
        leader_thread_0,
        leader_thread_1,
    );
    let mut follower = MpcPrf::new(
        PrfConfig::builder().role(Role::Follower).build().unwrap(),
        follower_thread_0,
        follower_thread_1,
    );

    let pms = [42u8; 32];
    let client_random = [0u8; 32];
    let server_random = [1u8; 32];
    let cf_hs_hash = [2u8; 32];
    let sf_hs_hash = [3u8; 32];

    futures::join!(
        async {
            leader.setup(leader_pms.clone()).await.unwrap();
            leader.set_client_random(Some(client_random)).await.unwrap();
            leader.preprocess().await.unwrap();
        },
        async {
            follower.setup(follower_pms.clone()).await.unwrap();
            follower.set_client_random(None).await.unwrap();
            follower.preprocess().await.unwrap();
        }
    );

    leader.thread_mut().assign(&leader_pms, pms).unwrap();
    follower.thread_mut().assign(&follower_pms, pms).unwrap();

    let (_leader_keys, _follower_keys) = futures::try_join!(
        leader.compute_session_keys(server_random),
        follower.compute_session_keys(server_random)
    )
    .unwrap();

    let _ = futures::try_join!(
        leader.compute_client_finished_vd(cf_hs_hash),
        follower.compute_client_finished_vd(cf_hs_hash)
    )
    .unwrap();

    let _ = futures::try_join!(
        leader.compute_server_finished_vd(sf_hs_hash),
        follower.compute_server_finished_vd(sf_hs_hash)
    )
    .unwrap();

    futures::try_join!(
        leader.thread_mut().finalize(),
        follower.thread_mut().finalize()
    )
    .unwrap();
}
