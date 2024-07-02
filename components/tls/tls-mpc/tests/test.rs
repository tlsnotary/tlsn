use std::{sync::Arc, time::Duration};

use futures::{AsyncReadExt, AsyncWriteExt};
use mpz_common::{executor::MTExecutor, Allocate};
use mpz_garble::{config::Role as GarbleRole, protocol::deap::DEAPThread};
use mpz_ot::{
    chou_orlandi::{
        Receiver as BaseReceiver, ReceiverConfig as BaseReceiverConfig, Sender as BaseSender,
        SenderConfig as BaseSenderConfig,
    },
    kos::{Receiver, ReceiverConfig, Sender, SenderConfig, SharedReceiver, SharedSender},
    CommittedOTSender, VerifiableOTReceiver,
};
use serio::StreamExt;
use tls_client::Certificate;
use tls_client_async::bind_client;
use tls_mpc::{
    build_components, MpcTlsCommonConfig, MpcTlsFollower, MpcTlsFollowerConfig, MpcTlsLeader,
    MpcTlsLeaderConfig, TlsRole,
};
use tls_server_fixture::{bind_test_server_hyper, CA_CERT_DER, SERVER_DOMAIN};
use tokio_util::compat::TokioAsyncReadCompatExt;
use uid_mux::{
    test_utils::{test_framed_mux, TestFramedMux},
    FramedUidMux,
};

const OT_SETUP_COUNT: usize = 1_000_000;

async fn leader(config: MpcTlsCommonConfig, mux: TestFramedMux) {
    let mut exec = MTExecutor::new(mux.clone(), 8);

    let mut ot_sender = Sender::new(
        SenderConfig::default(),
        BaseReceiver::new(BaseReceiverConfig::default()),
    );
    ot_sender.alloc(OT_SETUP_COUNT);

    let mut ot_receiver = Receiver::new(
        ReceiverConfig::builder().sender_commit().build().unwrap(),
        BaseSender::new(
            BaseSenderConfig::builder()
                .receiver_commit()
                .build()
                .unwrap(),
        ),
    );
    ot_receiver.alloc(OT_SETUP_COUNT);

    let ot_sender = SharedSender::new(ot_sender);
    let mut ot_receiver = SharedReceiver::new(ot_receiver);

    let mut vm = DEAPThread::new(
        GarbleRole::Leader,
        [0u8; 32],
        exec.new_thread().await.unwrap(),
        ot_sender.clone(),
        ot_receiver.clone(),
    );

    let (ke, prf, encrypter, decrypter) = build_components(
        TlsRole::Leader,
        &config,
        exec.new_thread().await.unwrap(),
        exec.new_thread().await.unwrap(),
        exec.new_thread().await.unwrap(),
        exec.new_thread().await.unwrap(),
        exec.new_thread().await.unwrap(),
        vm.new_thread(
            exec.new_thread().await.unwrap(),
            ot_sender.clone(),
            ot_receiver.clone(),
        )
        .unwrap(),
        vm.new_thread(
            exec.new_thread().await.unwrap(),
            ot_sender.clone(),
            ot_receiver.clone(),
        )
        .unwrap(),
        vm.new_thread(
            exec.new_thread().await.unwrap(),
            ot_sender.clone(),
            ot_receiver.clone(),
        )
        .unwrap(),
        vm.new_thread(
            exec.new_thread().await.unwrap(),
            ot_sender.clone(),
            ot_receiver.clone(),
        )
        .unwrap(),
        vm.new_thread(
            exec.new_thread().await.unwrap(),
            ot_sender.clone(),
            ot_receiver.clone(),
        )
        .unwrap(),
        vm.new_thread(
            exec.new_thread().await.unwrap(),
            ot_sender.clone(),
            ot_receiver.clone(),
        )
        .unwrap(),
        vm.new_thread(
            exec.new_thread().await.unwrap(),
            ot_sender.clone(),
            ot_receiver.clone(),
        )
        .unwrap(),
        ot_sender.clone(),
        ot_receiver.clone(),
    );

    let mut leader = MpcTlsLeader::new(
        MpcTlsLeaderConfig::builder()
            .common(config)
            .build()
            .unwrap(),
        Box::new(StreamExt::compat_stream(
            mux.open_framed(b"mpc_tls").await.unwrap(),
        )),
        ke,
        prf,
        encrypter,
        decrypter,
    );

    leader.setup().await.unwrap();

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

    tokio::spawn(async { conn_fut.await.unwrap() });

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

    println!("{}", String::from_utf8_lossy(&buf));

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

    // Wait for the server to reply.
    tokio::time::sleep(Duration::from_millis(100)).await;

    leader_ctrl.commit().await.unwrap();

    let mut buf = vec![0u8; 1024];
    conn.read_to_end(&mut buf).await.unwrap();

    leader_ctrl.close_connection().await.unwrap();
    conn.close().await.unwrap();

    let mut ctx = exec.new_thread().await.unwrap();

    ot_receiver.accept_reveal(&mut ctx).await.unwrap();

    vm.finalize().await.unwrap();
}

async fn follower(config: MpcTlsCommonConfig, mux: TestFramedMux) {
    let mut exec = MTExecutor::new(mux.clone(), 8);

    let mut ot_sender = Sender::new(
        SenderConfig::builder().sender_commit().build().unwrap(),
        BaseReceiver::new(
            BaseReceiverConfig::builder()
                .receiver_commit()
                .build()
                .unwrap(),
        ),
    );
    ot_sender.alloc(OT_SETUP_COUNT);

    let mut ot_receiver = Receiver::new(
        ReceiverConfig::default(),
        BaseSender::new(BaseSenderConfig::default()),
    );
    ot_receiver.alloc(OT_SETUP_COUNT);

    let mut ot_sender = SharedSender::new(ot_sender);
    let ot_receiver = SharedReceiver::new(ot_receiver);

    let mut vm = DEAPThread::new(
        GarbleRole::Follower,
        [0u8; 32],
        exec.new_thread().await.unwrap(),
        ot_sender.clone(),
        ot_receiver.clone(),
    );

    let (ke, prf, encrypter, decrypter) = build_components(
        TlsRole::Follower,
        &config,
        exec.new_thread().await.unwrap(),
        exec.new_thread().await.unwrap(),
        exec.new_thread().await.unwrap(),
        exec.new_thread().await.unwrap(),
        exec.new_thread().await.unwrap(),
        vm.new_thread(
            exec.new_thread().await.unwrap(),
            ot_sender.clone(),
            ot_receiver.clone(),
        )
        .unwrap(),
        vm.new_thread(
            exec.new_thread().await.unwrap(),
            ot_sender.clone(),
            ot_receiver.clone(),
        )
        .unwrap(),
        vm.new_thread(
            exec.new_thread().await.unwrap(),
            ot_sender.clone(),
            ot_receiver.clone(),
        )
        .unwrap(),
        vm.new_thread(
            exec.new_thread().await.unwrap(),
            ot_sender.clone(),
            ot_receiver.clone(),
        )
        .unwrap(),
        vm.new_thread(
            exec.new_thread().await.unwrap(),
            ot_sender.clone(),
            ot_receiver.clone(),
        )
        .unwrap(),
        vm.new_thread(
            exec.new_thread().await.unwrap(),
            ot_sender.clone(),
            ot_receiver.clone(),
        )
        .unwrap(),
        vm.new_thread(
            exec.new_thread().await.unwrap(),
            ot_sender.clone(),
            ot_receiver.clone(),
        )
        .unwrap(),
        ot_sender.clone(),
        ot_receiver.clone(),
    );

    let mut follower = MpcTlsFollower::new(
        MpcTlsFollowerConfig::builder()
            .common(config)
            .build()
            .unwrap(),
        Box::new(StreamExt::compat_stream(
            mux.open_framed(b"mpc_tls").await.unwrap(),
        )),
        ke,
        prf,
        encrypter,
        decrypter,
    );

    follower.setup().await.unwrap();

    let (_, fut) = follower.run();
    fut.await.unwrap();

    let mut ctx = exec.new_thread().await.unwrap();

    ot_sender.reveal(&mut ctx).await.unwrap();

    vm.finalize().await.unwrap();
}

#[tokio::test]
#[ignore]
async fn test() {
    tracing_subscriber::fmt::init();

    let (leader_mux, follower_mux) = test_framed_mux(8);

    let common_config = MpcTlsCommonConfig::builder().id("test").build().unwrap();

    tokio::join!(
        leader(common_config.clone(), leader_mux),
        follower(common_config.clone(), follower_mux)
    );
}
