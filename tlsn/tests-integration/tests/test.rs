use futures::AsyncWriteExt;
use hyper::{body::to_bytes, Body, Request, StatusCode};
use tlsn_notary::{attach_notary, NotaryConfig};
use tlsn_prover::{attach_prover, ProverConfig};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

#[tokio::test]
async fn test() {
    let (socket_0, socket_1) = tokio::io::duplex(2 << 23);

    tokio::join!(prover(socket_0), notary(socket_1));
}

async fn prover<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(notary_socket: T) {
    let dns = "tlsnotary.org";
    let server_socket = tokio::net::TcpStream::connect(dns.to_string() + ":443")
        .await
        .unwrap();
    let server_socket = server_socket.compat();

    let (server_socket, prover, prover_fut) = attach_prover(
        ProverConfig::builder()
            .id("test")
            .server_dns(dns)
            .build()
            .unwrap(),
        server_socket,
        notary_socket.compat(),
    )
    .unwrap();

    tokio::spawn(prover_fut);
    let prover_task = tokio::spawn(prover.run_tls());

    let (mut request_sender, mut connection) =
        hyper::client::conn::handshake(server_socket.compat())
            .await
            .unwrap();

    let request = Request::builder()
        .header("Host", "tlsnotary.org")
        .method("GET")
        .body(Body::from(""))
        .unwrap();

    let response = tokio::select! {
        response = request_sender.send_request(request) => response.unwrap(),
        _ = &mut connection => panic!("connection closed"),
    };

    assert!(response.status() == StatusCode::OK);

    _ = tokio::select! {
        data = to_bytes(response.into_body()) => data.unwrap(),
        _ = &mut connection => panic!("connection closed"),
    };

    let mut server_socket = connection.into_parts().io.into_inner();

    server_socket.close().await.unwrap();

    let mut prover = prover_task.await.unwrap().unwrap();

    let sent_len = prover.sent_transcript().data().len();
    let recv_len = prover.recv_transcript().data().len();

    prover.add_commitment_sent(0..sent_len as u32).unwrap();
    prover.add_commitment_recv(0..recv_len as u32).unwrap();

    _ = prover.finalize().await.unwrap();
}

async fn notary<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(socket: T) {
    let (notary, notary_fut) = attach_notary(
        NotaryConfig::builder().id("test").build().unwrap(),
        socket.compat(),
    )
    .unwrap();

    tokio::spawn(notary_fut);

    let signing_key = p256::ecdsa::SigningKey::from_bytes(&[1u8; 32].into()).unwrap();

    notary
        .notarize::<p256::ecdsa::Signature>(&signing_key)
        .await
        .unwrap();
}
