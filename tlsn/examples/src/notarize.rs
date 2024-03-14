use crate::print_with_time;
use http_body_util::{BodyExt as _, Either, Empty, Full};
use hyper::{client::conn::http1::Parts, Request, StatusCode};
use hyper_util::rt::TokioIo;
use notary_server::{ClientType, NotarizationSessionRequest, NotarizationSessionResponse};
use rustls::{ClientConfig, OwnedTrustAnchor, RootCertStore};
use std::{sync::Arc, time::Instant};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_util::bytes::Bytes;
use webpki_roots::TLS_SERVER_ROOTS;

pub async fn request_notarization(
    host: &str,
    port: u16,
    max_sent_data: Option<usize>,
    max_recv_data: Option<usize>,
    time: Instant,
) -> (tokio_rustls::client::TlsStream<TcpStream>, String) {
    let mut cert_store = RootCertStore::empty();
    cert_store.add_trust_anchors(TLS_SERVER_ROOTS.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject.to_vec(),
            ta.subject_public_key_info.to_vec(),
            ta.name_constraints.clone().map(|v| v.to_vec()),
        )
    }));

    let client_notary_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(cert_store)
        .with_no_client_auth();
    let notary_connector = TlsConnector::from(Arc::new(client_notary_config));

    print_with_time("Connecting to notary server", time);
    let notary_socket = tokio::net::TcpStream::connect((host, port)).await.unwrap();

    let notary_tls_socket = notary_connector
        .connect(host.try_into().unwrap(), notary_socket)
        .await
        .unwrap();

    // Attach the hyper HTTP client to the notary TLS connection to send request to the /session endpoint
    print_with_time("Doing handshake with notary", time);
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(notary_tls_socket))
            .await
            .unwrap();

    // Spawn the HTTP task to be run concurrently
    let connection_task = tokio::spawn(connection.without_shutdown());

    // Build the HTTP request to configure notarization
    print_with_time("Sending configuration request", time);
    let payload = serde_json::to_string(&NotarizationSessionRequest {
        client_type: ClientType::Tcp,
        max_sent_data,
        max_recv_data,
    })
    .unwrap();

    let request = Request::builder()
        .uri(format!("https://{host}:{port}/nightly/session"))
        .method("POST")
        .header("Host", host)
        // Need to specify application/json for axum to parse it as json
        .header("Content-Type", "application/json")
        .body(Either::Left(Full::new(Bytes::from(payload))))
        .unwrap();

    let configuration_response = request_sender.send_request(request).await.unwrap();
    print_with_time(
        "Got configuration response. Sending notarization request",
        time,
    );

    assert!(
        configuration_response.status() == StatusCode::OK,
        "Response was not OK: {}",
        configuration_response.status()
    );

    let payload = configuration_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let notarization_response =
        serde_json::from_str::<NotarizationSessionResponse>(&String::from_utf8_lossy(&payload))
            .unwrap();

    // Send notarization request via HTTP, where the underlying TCP connection will be extracted later
    let request = Request::builder()
        .uri(format!(
            "https://{host}:{port}/nightly/notarize?sessionId={}",
            notarization_response.session_id.clone()
        ))
        .method("GET")
        .header("Host", host)
        .header("Connection", "Upgrade")
        .header("Upgrade", "TCP")
        .body(Either::Right(Empty::<Bytes>::new()))
        .unwrap();

    let response = request_sender.send_request(request).await.unwrap();
    print_with_time("Got notarization response", time);

    assert!(
        response.status() == StatusCode::SWITCHING_PROTOCOLS,
        "Response was not OK: {}",
        response.status()
    );

    // Claim back the TLS socket after HTTP exchange is done
    let Parts {
        io: notary_tls_socket,
        ..
    } = connection_task.await.unwrap().unwrap();
    print_with_time("Notary is set up and ready", time);

    (
        notary_tls_socket.into_inner(),
        notarization_response.session_id,
    )
}
