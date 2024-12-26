use hmac_sha256::{MpcPrf, Prf, PrfConfig, Role};
use mpz_common::executor::test_st_executor;
use mpz_garble::{config::Role as DEAPRole, protocol::deap::DEAPThread, Memory};
use mpz_ot::ideal::ot::ideal_ot;

pub async fn preprocess_prf_circuits() {
    let pms = [42u8; 32];
    let client_random = [69u8; 32];

    let (leader_ctx_0, follower_ctx_0) = test_st_executor(128);
    let (leader_ctx_1, follower_ctx_1) = test_st_executor(128);

    let (leader_ot_send_0, follower_ot_recv_0) = ideal_ot();
    let (follower_ot_send_0, leader_ot_recv_0) = ideal_ot();
    let (leader_ot_send_1, follower_ot_recv_1) = ideal_ot();
    let (follower_ot_send_1, leader_ot_recv_1) = ideal_ot();

    let leader_thread_0 = DEAPThread::new(
        DEAPRole::Leader,
        [0u8; 32],
        leader_ctx_0,
        leader_ot_send_0,
        leader_ot_recv_0,
    );
    let leader_thread_1 = leader_thread_0
        .new_thread(leader_ctx_1, leader_ot_send_1, leader_ot_recv_1)
        .unwrap();

    let follower_thread_0 = DEAPThread::new(
        DEAPRole::Follower,
        [0u8; 32],
        follower_ctx_0,
        follower_ot_send_0,
        follower_ot_recv_0,
    );
    let follower_thread_1 = follower_thread_0
        .new_thread(follower_ctx_1, follower_ot_send_1, follower_ot_recv_1)
        .unwrap();

    // Set up public PMS for testing.
    let leader_pms = leader_thread_0.new_public_input::<[u8; 32]>("pms").unwrap();
    let follower_pms = follower_thread_0
        .new_public_input::<[u8; 32]>("pms")
        .unwrap();

    leader_thread_0.assign(&leader_pms, pms).unwrap();

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
            leader.set_client_random(Some(client_random)).await.unwrap();
            leader.preprocess().await.unwrap();
        },
        async {
            follower.setup(follower_pms).await.unwrap();
            follower.set_client_random(None).await.unwrap();
            follower.preprocess().await.unwrap();
        }
    );
}
