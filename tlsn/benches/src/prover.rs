use std::time::Instant;

use futures::{AsyncReadExt, AsyncWriteExt};
use tlsn_core::Direction;
use tlsn_server_fixture::{CA_CERT_DER, SERVER_DOMAIN};
use tokio_util::compat::TokioAsyncReadCompatExt;

use tlsn_prover::tls::{Prover, ProverConfig};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let (client_conn, server_conn) = tokio::io::duplex(2 << 16);
    let server_task = tokio::spawn(tlsn_server_fixture::bind(server_conn.compat()));

    let ip = std::env::var("VERIFIER_IP").unwrap_or_else(|_| "10.10.1.1".to_string());
    let port: u16 = std::env::var("VERIFIER_PORT")
        .map(|port| port.parse().expect("port is valid u16"))
        .unwrap_or(8000);
    let verifier_host = (ip.as_str(), port);
    let verifier_conn = tokio::net::TcpStream::connect(verifier_host).await.unwrap();

    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    let start_time = Instant::now();

    let prover = Prover::new(
        ProverConfig::builder()
            .id("test")
            .server_dns(SERVER_DOMAIN)
            .root_cert_store(root_store)
            .build()
            .unwrap(),
    )
    .setup(verifier_conn.compat())
    .await
    .unwrap();
    let (mut mpc_tls_connection, prover_fut) = prover.connect(client_conn.compat()).await.unwrap();
    let prover_task = tokio::spawn(async { prover_fut.await.unwrap() });

    mpc_tls_connection
        .write_all(b"GET /formats/json?size=8 HTTP/1.1\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    mpc_tls_connection.close().await.unwrap();

    let mut response = vec![0u8; 1024];
    mpc_tls_connection.read_to_end(&mut response).await.unwrap();

    server_task.await.unwrap();

    let mut prover = prover_task.await.unwrap().start_prove();

    prover
        .reveal(0..prover.sent_transcript().data().len(), Direction::Sent)
        .unwrap();
    prover
        .reveal(
            0..prover.recv_transcript().data().len(),
            Direction::Received,
        )
        .unwrap();
    prover.prove().await.unwrap();
    prover.finalize().await.unwrap();

    println!(
        "completed: {} seconds",
        Instant::now().duration_since(start_time).as_secs()
    );
}
