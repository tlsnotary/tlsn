use std::{
    io::{Read, Write},
    sync::Arc,
};

use crate::prover::client::bind_client;
use mpc_tls::{Config, MpcTlsFollower, MpcTlsLeader};
use mpz_common::context::test_mt_context;
use mpz_core::Block;
use mpz_garble::protocol::semihonest::{Evaluator, Garbler};
use mpz_memory_core::correlated::Delta;
use mpz_ot::{
    cot::{DerandCOTReceiver, DerandCOTSender},
    ideal::rcot::ideal_rcot,
    rcot::shared::{SharedRCOTReceiver, SharedRCOTSender},
};
use rand::{Rng, SeedableRng, rngs::StdRng};
use rustls_pki_types::CertificateDer;
use tls_client::RootCertStore;
use tls_server_fixture::{CA_CERT_DER, SERVER_DOMAIN, bind_test_server_hyper};
use tokio::sync::Mutex;
use tokio_util::compat::TokioAsyncReadCompatExt;
use webpki::anchor_from_trusted_cert;

const CA_CERT: CertificateDer = CertificateDer::from_slice(CA_CERT_DER);

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "expensive"]
async fn mpc_tls_test() {
    tracing_subscriber::fmt::init();

    let config = Config::builder()
        .defer_decryption(false)
        .max_sent(1 << 13)
        .max_recv_online(1 << 13)
        .max_recv(1 << 13)
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

    let config = tls_client::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(RootCertStore {
            roots: vec![anchor_from_trusted_cert(&CA_CERT).unwrap().to_owned()],
        })
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

    let (mut client, mut server, conn_fut) = bind_client(client);
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

    client.write_all(msg.as_bytes()).unwrap();

    let mut buf = vec![0u8; 48];
    client.read_exact(&mut buf).unwrap();

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

    client.write_all(msg.as_bytes()).unwrap();
    client.close();

    let mut buf = vec![0u8; 1024];
    client.read_to_end(&mut buf).unwrap();

    leader_ctrl.stop().await.unwrap();

    handle.await.unwrap();
}

async fn follower_task(mut follower: MpcTlsFollower) {
    follower.alloc().unwrap();
    follower.preprocess().await.unwrap();
    follower.run().await.unwrap();
}

fn build_pair(config: Config) -> (MpcTlsLeader, MpcTlsFollower) {
    let mut rng = StdRng::seed_from_u64(0);

    let (mut mt_a, mut mt_b) = test_mt_context(8);

    let ctx_a = futures::executor::block_on(mt_a.new_context()).unwrap();
    let ctx_b = futures::executor::block_on(mt_b.new_context()).unwrap();

    let delta_a = Delta::new(Block::random(&mut rng));
    let delta_b = Delta::new(Block::random(&mut rng));

    let (rcot_send_a, rcot_recv_b) = ideal_rcot(Block::random(&mut rng), delta_a.into_inner());
    let (rcot_send_b, rcot_recv_a) = ideal_rcot(Block::random(&mut rng), delta_b.into_inner());

    let rcot_send_a = SharedRCOTSender::new(rcot_send_a);
    let rcot_send_b = SharedRCOTSender::new(rcot_send_b);
    let rcot_recv_a = SharedRCOTReceiver::new(rcot_recv_a);
    let rcot_recv_b = SharedRCOTReceiver::new(rcot_recv_b);

    let mpc_a = Arc::new(Mutex::new(Garbler::new(
        DerandCOTSender::new(rcot_send_a.clone()),
        rand::rng().random(),
        delta_a,
    )));
    let mpc_b = Arc::new(Mutex::new(Evaluator::new(DerandCOTReceiver::new(
        rcot_recv_b.clone(),
    ))));

    let leader = MpcTlsLeader::new(
        config.clone(),
        ctx_a,
        mpc_a,
        (rcot_send_a.clone(), rcot_send_a.clone(), rcot_send_a),
        rcot_recv_a,
    );

    let follower = MpcTlsFollower::new(
        config,
        ctx_b,
        mpc_b,
        rcot_send_b,
        (rcot_recv_b.clone(), rcot_recv_b.clone(), rcot_recv_b),
    );

    (leader, follower)
}
