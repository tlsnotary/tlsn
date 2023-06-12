use std::sync::Arc;

use actor_ot::{create_ot_pair, OTActorReceiverConfig, OTActorSenderConfig, ObliviousReveal};
use futures::{AsyncReadExt, AsyncWriteExt};
use mpc_garble::{config::Role as GarbleRole, protocol::deap::DEAPVm};
use mpc_share_conversion as ff;
use tls_client::Certificate;
use tls_client_async::bind_client;
use tls_mpc::{
    setup_components, MpcTlsCommonConfig, MpcTlsFollower, MpcTlsFollowerConfig, MpcTlsLeader,
    MpcTlsLeaderConfig, TlsRole,
};
use tls_server_fixture::{bind_test_server, CA_CERT_DER, SERVER_DOMAIN};
use tokio_util::compat::TokioAsyncReadCompatExt;
use uid_mux::{yamux, UidYamux};
use utils_aio::{codec::BincodeMux, mux::MuxChannel};

#[tokio::test]
#[ignore]
async fn test() {
    let (leader_socket, follower_socket) = tokio::io::duplex(1 << 25);

    let mut leader_mux = UidYamux::new(
        yamux::Config::default(),
        leader_socket.compat(),
        yamux::Mode::Client,
    );
    let mut follower_mux = UidYamux::new(
        yamux::Config::default(),
        follower_socket.compat(),
        yamux::Mode::Server,
    );

    let leader_mux_control = leader_mux.control();
    let follower_mux_control = follower_mux.control();

    tokio::spawn(async move { leader_mux.run().await.unwrap() });
    tokio::spawn(async move { follower_mux.run().await.unwrap() });

    let mut leader_mux = BincodeMux::new(leader_mux_control);
    let mut follower_mux = BincodeMux::new(follower_mux_control);

    let leader_ot_send_config = OTActorSenderConfig::builder()
        .id("ot/0")
        .initial_count(200_000)
        .build()
        .unwrap();
    let follower_ot_recv_config = OTActorReceiverConfig::builder()
        .id("ot/0")
        .initial_count(200_000)
        .build()
        .unwrap();

    let follower_ot_send_config = OTActorSenderConfig::builder()
        .id("ot/1")
        .initial_count(200_000)
        .committed()
        .build()
        .unwrap();
    let leader_ot_recv_config = OTActorReceiverConfig::builder()
        .id("ot/1")
        .initial_count(200_000)
        .committed()
        .build()
        .unwrap();

    let ((mut leader_ot_send, leader_ot_send_fut), (mut follower_ot_recv, follower_ot_recv_fut)) =
        create_ot_pair(
            leader_mux.clone(),
            follower_mux.clone(),
            leader_ot_send_config,
            follower_ot_recv_config,
        )
        .await
        .unwrap();

    tokio::spawn(leader_ot_send_fut);
    tokio::spawn(follower_ot_recv_fut);

    let ((mut follower_ot_send, follower_ot_send_fut), (mut leader_ot_recv, leader_ot_recv_fut)) =
        create_ot_pair(
            follower_mux.clone(),
            leader_mux.clone(),
            follower_ot_send_config,
            leader_ot_recv_config,
        )
        .await
        .unwrap();

    tokio::spawn(follower_ot_send_fut);
    tokio::spawn(leader_ot_recv_fut);

    tokio::try_join!(leader_ot_send.setup(), follower_ot_recv.setup()).unwrap();
    tokio::try_join!(follower_ot_send.setup(), leader_ot_recv.setup()).unwrap();

    let mut leader_vm = DEAPVm::new(
        "vm",
        GarbleRole::Leader,
        [0u8; 32],
        leader_mux.get_channel("vm").await.unwrap(),
        Box::new(leader_mux.clone()),
        leader_ot_send.clone(),
        leader_ot_recv.clone(),
    );

    let mut follower_vm = DEAPVm::new(
        "vm",
        GarbleRole::Follower,
        [1u8; 32],
        follower_mux.get_channel("vm").await.unwrap(),
        Box::new(follower_mux.clone()),
        follower_ot_send.clone(),
        follower_ot_recv.clone(),
    );

    let leader_p256_send = ff::ConverterSender::<ff::P256, _>::new(
        ff::SenderConfig::builder().id("p256/0").build().unwrap(),
        leader_ot_send.clone(),
        leader_mux.get_channel("p256/0").await.unwrap(),
    );

    let leader_p256_recv = ff::ConverterReceiver::<ff::P256, _>::new(
        ff::ReceiverConfig::builder().id("p256/1").build().unwrap(),
        leader_ot_recv.clone(),
        leader_mux.get_channel("p256/1").await.unwrap(),
    );

    let follower_p256_send = ff::ConverterSender::<ff::P256, _>::new(
        ff::SenderConfig::builder().id("p256/1").build().unwrap(),
        follower_ot_send.clone(),
        follower_mux.get_channel("p256/1").await.unwrap(),
    );

    let follower_p256_recv = ff::ConverterReceiver::<ff::P256, _>::new(
        ff::ReceiverConfig::builder().id("p256/0").build().unwrap(),
        follower_ot_recv.clone(),
        follower_mux.get_channel("p256/0").await.unwrap(),
    );

    let mut leader_gf2 = ff::ConverterSender::<ff::Gf2_128, _>::new(
        ff::SenderConfig::builder()
            .id("gf2")
            .record()
            .build()
            .unwrap(),
        leader_ot_send.clone(),
        leader_mux.get_channel("gf2").await.unwrap(),
    );

    let mut follower_gf2 = ff::ConverterReceiver::<ff::Gf2_128, _>::new(
        ff::ReceiverConfig::builder()
            .id("gf2")
            .record()
            .build()
            .unwrap(),
        follower_ot_recv.clone(),
        follower_mux.get_channel("gf2").await.unwrap(),
    );

    let common_config = MpcTlsCommonConfig::builder().id("test").build().unwrap();

    let (leader_ke, leader_prf, leader_encrypter, leader_decrypter) = setup_components(
        &common_config,
        TlsRole::Leader,
        &mut leader_mux,
        &mut leader_vm,
        leader_p256_send,
        leader_p256_recv,
        leader_gf2.handle().unwrap(),
    )
    .await
    .unwrap();

    let leader = MpcTlsLeader::new(
        MpcTlsLeaderConfig::builder()
            .common(common_config.clone())
            .build()
            .unwrap(),
        leader_mux.get_channel("test").await.unwrap(),
        leader_ke,
        leader_prf,
        leader_encrypter,
        leader_decrypter,
    );

    let (follower_ke, follower_prf, follower_encrypter, follower_decrypter) = setup_components(
        &common_config,
        TlsRole::Follower,
        &mut follower_mux,
        &mut follower_vm,
        follower_p256_send,
        follower_p256_recv,
        follower_gf2.handle().unwrap(),
    )
    .await
    .unwrap();

    let mut follower = MpcTlsFollower::new(
        MpcTlsFollowerConfig::builder()
            .common(common_config)
            .build()
            .unwrap(),
        follower_mux.get_channel("test").await.unwrap(),
        follower_ke,
        follower_prf,
        follower_encrypter,
        follower_decrypter,
    );

    tokio::spawn(async move { follower.run().await.unwrap() });

    let mut root_store = tls_client::RootCertStore::empty();
    root_store.add(&Certificate(CA_CERT_DER.to_vec())).unwrap();
    let config = tls_client::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = SERVER_DOMAIN.try_into().unwrap();

    let client =
        tls_client::ClientConnection::new(Arc::new(config), Box::new(leader), server_name).unwrap();

    let (client_socket, server_socket) = tokio::io::duplex(1 << 16);

    tokio::spawn(bind_test_server(server_socket.compat()));

    let (mut conn, conn_fut) = bind_client(client_socket.compat(), client);

    let conn_task = tokio::spawn(conn_fut);

    let msg = concat!(
        "POST /echo HTTP/1.1\r\n",
        "Host: test-server.io\r\n",
        "Connection: close\r\n",
        "Accept-Encoding: identity\r\n",
        "\r\n"
    );

    conn.write_all(msg.as_bytes()).await.unwrap();

    let mut buf = Vec::new();
    conn.read_to_end(&mut buf).await.unwrap();

    println!("response: {}", String::from_utf8_lossy(&buf));

    follower_ot_send.reveal().await.unwrap();

    tokio::try_join!(leader_vm.finalize(), follower_vm.finalize()).unwrap();

    tokio::try_join!(leader_gf2.reveal(), follower_gf2.verify()).unwrap();

    conn_task.await.unwrap().unwrap();
}
