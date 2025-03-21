use std::sync::Arc;

use futures::{AsyncReadExt, AsyncWriteExt};
use mpc_tls::{Config, MpcTlsFollower, MpcTlsLeader};
use mpz_common::context::test_mt_context;
use mpz_core::Block;
use mpz_garble::protocol::semihonest::{Evaluator, Generator};
use mpz_memory_core::correlated::Delta;
use mpz_ot::{
    cot::{DerandCOTReceiver, DerandCOTSender},
    ideal::rcot::ideal_rcot,
    rcot::shared::{SharedRCOTReceiver, SharedRCOTSender},
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use rand06_compat::Rand0_6CompatExt;
use tls_client::Certificate;
use tls_client_async::bind_client;
use tls_server_fixture::{bind_test_server_hyper, CA_CERT_DER, SERVER_DOMAIN};
use tokio::sync::Mutex;
use tokio_util::compat::TokioAsyncReadCompatExt;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "expensive"]
async fn mpc_tls_test() {
    tracing_subscriber::fmt::init();

    let config = Config::builder()
        .defer_decryption(false)
        .max_sent(1 << 13)
        .max_recv_online(1 << 13)
        .build()
        .unwrap();

    let (leader, follower) = build_pair(config);

    tokio::try_join!(
        tokio::spawn(leader_task(leader)),
        tokio::spawn(follower_task(follower))
    )
    .unwrap();
}

async fn leader_task(mut leader: MpcTlsLeader) {
    leader.alloc().unwrap();
    leader.preprocess().await.unwrap();

    let (leader_ctrl, leader_fut) = leader.run();
    tokio::spawn(async { leader_fut.await.unwrap() });

    let mut root_store = tls_client::RootCertStore::empty();
    root_store.add(&Certificate(CA_CERT_DER.to_vec())).unwrap();
    let config = tls_client::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = SERVER_DOMAIN.try_into().unwrap();

    let client = tls_client::ClientConnection::new(
        Arc::new(config),
        Box::new(leader_ctrl.clone()),
        server_name,
    )
    .unwrap();

    let (client_socket, server_socket) = tokio::io::duplex(1 << 16);
    tokio::spawn(bind_test_server_hyper(server_socket.compat()));

    let (mut conn, conn_fut) = bind_client(client_socket.compat(), client);
    let handle = tokio::spawn(async { conn_fut.await.unwrap() });

    let msg = concat!(
        "POST /echo HTTP/1.1\r\n",
        "Host: test-server.io\r\n",
        "Connection: keep-alive\r\n",
        "Accept-Encoding: identity\r\n",
        "Content-Length: 5\r\n",
        "\r\n",
        "hello",
        "\r\n"
    );

    conn.write_all(msg.as_bytes()).await.unwrap();

    let mut buf = vec![0u8; 48];
    conn.read_exact(&mut buf).await.unwrap();

    leader_ctrl.defer_decryption().await.unwrap();

    let msg = concat!(
        "POST /echo HTTP/1.1\r\n",
        "Host: test-server.io\r\n",
        "Connection: close\r\n",
        "Accept-Encoding: identity\r\n",
        "Content-Length: 5\r\n",
        "\r\n",
        "hello",
        "\r\n"
    );

    conn.write_all(msg.as_bytes()).await.unwrap();
    conn.close().await.unwrap();

    let mut buf = vec![0u8; 1024];
    conn.read_to_end(&mut buf).await.unwrap();

    leader_ctrl.stop().await.unwrap();

    handle.await.unwrap();
}

async fn follower_task(mut follower: MpcTlsFollower) {
    follower.alloc().unwrap();
    follower.preprocess().await.unwrap();
    follower.run().await.unwrap();
}

fn build_pair(config: Config) -> (MpcTlsLeader, MpcTlsFollower) {
    let mut rng = StdRng::seed_from_u64(0).compat();

    let (mut mt_a, mut mt_b) = test_mt_context(8);

    let ctx_a = futures::executor::block_on(mt_a.new_context()).unwrap();
    let ctx_b = futures::executor::block_on(mt_b.new_context()).unwrap();

    let delta_a = Delta::new(Block::random(&mut rng));
    let delta_b = Delta::new(Block::random(&mut rng));

    let (rcot_send_a, rcot_recv_b) = ideal_rcot(Block::random(&mut rng), delta_a.into_inner());
    let (rcot_send_b, rcot_recv_a) = ideal_rcot(Block::random(&mut rng), delta_b.into_inner());

    let mut rcot_send_a = SharedRCOTSender::new(4, rcot_send_a);
    let mut rcot_send_b = SharedRCOTSender::new(1, rcot_send_b);
    let mut rcot_recv_a = SharedRCOTReceiver::new(1, rcot_recv_a);
    let mut rcot_recv_b = SharedRCOTReceiver::new(4, rcot_recv_b);

    let mpc_a = Arc::new(Mutex::new(Generator::new(
        DerandCOTSender::new(rcot_send_a.next().unwrap()),
        rand::rng().random(),
        delta_a,
    )));
    let mpc_b = Arc::new(Mutex::new(Evaluator::new(DerandCOTReceiver::new(
        rcot_recv_b.next().unwrap(),
    ))));

    let leader = MpcTlsLeader::new(
        config.clone(),
        ctx_a,
        mpc_a,
        (
            rcot_send_a.next().unwrap(),
            rcot_send_a.next().unwrap(),
            rcot_send_a.next().unwrap(),
        ),
        rcot_recv_a.next().unwrap(),
    );

    let follower = MpcTlsFollower::new(
        config,
        ctx_b,
        mpc_b,
        rcot_send_b.next().unwrap(),
        (
            rcot_recv_b.next().unwrap(),
            rcot_recv_b.next().unwrap(),
            rcot_recv_b.next().unwrap(),
        ),
    );

    (leader, follower)
}
