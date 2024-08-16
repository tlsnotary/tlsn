use std::{sync::Arc, time::Duration};

use futures::{AsyncReadExt, AsyncWriteExt};
use serio::StreamExt;
use tls_client::Certificate;
use tls_client_async::bind_client;
use tls_server_fixture::{bind_test_server_hyper, CA_CERT_DER, SERVER_DOMAIN};
use tls_tee::{TeeTlsCommonConfig, TeeTlsFollower, TeeTlsLeader};
use tokio_util::compat::TokioAsyncReadCompatExt;
use uid_mux::{
    test_utils::{test_framed_mux, TestFramedMux},
    FramedUidMux,
};

async fn leader(_config: TeeTlsCommonConfig, mux: TestFramedMux) {
    println!("leader");

    let mut leader = TeeTlsLeader::new(Box::new(StreamExt::compat_stream(
        mux.open_framed(b"tee_tls").await.unwrap(),
    )));

    leader.setup().await.unwrap();
    println!("leader");

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

    let mut buf = vec![0u8; 80];
    conn.read_exact(&mut buf).await.unwrap();

    println!("{}", String::from_utf8_lossy(&buf));

    let msg = concat!(
        "POST /echo/reversed HTTP/1.1\r\n",
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

    let mut buf = vec![0u8; 1024];
    conn.read_to_end(&mut buf).await.unwrap();
    println!("{}", String::from_utf8_lossy(&buf));

    conn.close().await.unwrap();
    
}

async fn follower(_config: TeeTlsCommonConfig, mux: TestFramedMux) {
    println!("follower");

    let mut follower = TeeTlsFollower::new(Box::new(StreamExt::compat_stream(
        mux.open_framed(b"tee_tls").await.unwrap(),
    )));

    follower.setup().await.unwrap();

    let (_follower_ctrl, follower_future) = follower.run();
    tokio::spawn(async { follower_future.await.unwrap() });

    // follower_ctrl
}

#[tokio::test]
// #[ignore]
async fn test() {
    tracing_subscriber::fmt::init();

    let (leader_mux, follower_mux) = test_framed_mux(8);

    let common_config = TeeTlsCommonConfig::builder().id("test").build().unwrap();

    tokio::join!(
        leader(common_config.clone(), leader_mux),
        follower(common_config.clone(), follower_mux)
    );
}
