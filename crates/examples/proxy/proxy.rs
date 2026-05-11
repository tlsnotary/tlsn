use std::{
    env,
    future::IntoFuture,
    net::{IpAddr, SocketAddr},
};

use anyhow::Result;
use http_body_util::Empty;
use hyper::{Request, StatusCode, Uri, body::Bytes};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::instrument;

use tlsn::{
    Session,
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::proxy::ProxyTlsConfig, verifier::VerifierConfig,
    },
    connection::{DnsName, ServerName},
    transcript::PartialTranscript,
    verifier::{VerifierCommitStart, VerifierOutput},
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_server_fixture::DEFAULT_FIXTURE_PORT;
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};

const SECRET: &str = "TLSNotary's private key 🤡";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let server_host: String = env::var("SERVER_HOST").unwrap_or("127.0.0.1".into());
    let server_port: u16 = env::var("SERVER_PORT")
        .map(|port| port.parse().expect("port should be valid integer"))
        .unwrap_or(DEFAULT_FIXTURE_PORT);

    // We use SERVER_DOMAIN here to make sure it matches the domain in the test
    // server's certificate.
    let uri = format!("https://{SERVER_DOMAIN}:{server_port}/formats/html");
    let server_ip: IpAddr = server_host.parse().expect("Invalid IP address");
    let server_addr = SocketAddr::from((server_ip, server_port));

    // Connect prover and verifier.
    let (prover_socket, verifier_socket) = tokio::io::duplex(1 << 23);

    let prover = prover(prover_socket, &uri);
    let verifier = verifier(verifier_socket, server_addr);
    let (_, transcript) = tokio::try_join!(prover, verifier).unwrap();

    println!("Successfully verified {}", uri);
    println!(
        "Verified sent data:\n{}",
        bytes_to_redacted_string(transcript.sent_unsafe())
    );
    println!(
        "Verified received data:\n{}",
        bytes_to_redacted_string(transcript.received_unsafe())
    );
}

#[instrument(skip(verifier_socket))]
async fn prover<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    verifier_socket: T,
    uri: &str,
) -> Result<()> {
    let uri = uri.parse::<Uri>().unwrap();
    assert_eq!(uri.scheme().unwrap().as_str(), "https");
    let server_domain = uri.authority().unwrap().host();

    // Create a session with the verifier.
    let session = Session::new(verifier_socket.compat());
    let (driver, mut handle) = session.split();

    // Spawn the session driver to run in the background.
    let driver_task = tokio::spawn(driver);

    // Create a new prover and perform necessary setup.
    // In proxy mode, we use ProxyTlsConfig instead of MpcTlsConfig.
    // The server_name is required so the verifier knows which server to expect.
    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(
            ProxyTlsConfig::builder()
                .server_name(DnsName::try_from(server_domain)?)
                .build()?,
        )
        .await?;

    // In proxy mode, connect TLS through the proxy instead of directly
    // to the server via TCP. The verifier will forward traffic to the actual
    // server.
    let (tls_connection, prover) = prover.connect(
        TlsClientConfig::builder()
            .server_name(ServerName::Dns(SERVER_DOMAIN.try_into()?))
            // Create a root certificate store with the server-fixture's self-signed
            // certificate. This is only required for offline testing with the
            // server-fixture.
            .root_store(RootCertStore {
                roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
            })
            .build()?,
    )?;
    let tls_connection = TokioIo::new(tls_connection.compat());

    // Spawn the Prover to run in the background.
    let prover_task = tokio::spawn(prover.into_future());

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(tls_connection).await?;

    // Spawn the connection to run in the background.
    tokio::spawn(connection);

    // Send Request and wait for Response.
    let request = Request::builder()
        .uri(uri.clone())
        .header("Host", server_domain)
        .header("Connection", "close")
        .header("Secret", SECRET)
        .method("GET")
        .body(Empty::<Bytes>::new())?;
    let response = request_sender.send_request(request).await?;

    assert!(response.status() == StatusCode::OK);

    // Create proof for the Verifier.
    let mut prover = prover_task.await??;

    let mut builder = ProveConfig::builder(prover.transcript());

    // Reveal the DNS name.
    builder.server_identity();

    // Find the secret in the request.
    let pos = prover
        .transcript()
        .sent()
        .windows(SECRET.len())
        .position(|w| w == SECRET.as_bytes())
        .expect("the secret should be in the sent data");

    // Reveal everything except for the secret.
    builder.reveal_sent(&(0..pos))?;
    builder.reveal_sent(&(pos + SECRET.len()..prover.transcript().sent().len()))?;

    // Find the substring "Dick".
    let pos = prover
        .transcript()
        .received()
        .windows(4)
        .position(|w| w == b"Dick")
        .expect("the substring 'Dick' should be in the received data");

    // Reveal everything except for the substring.
    builder.reveal_recv(&(0..pos))?;
    builder.reveal_recv(&(pos + 4..prover.transcript().received().len()))?;

    let config = builder.build()?;

    prover.prove(&config).await?;
    prover.close().await?;

    // Close the session and wait for the driver to complete.
    handle.close();
    driver_task.await??;

    Ok(())
}

#[instrument(skip(prover_socket))]
async fn verifier<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    prover_socket: T,
    server_addr: SocketAddr,
) -> Result<PartialTranscript> {
    // Create a session with the prover.
    let session = Session::new(prover_socket.compat());
    let (driver, mut handle) = session.split();

    // Spawn the session driver to run in the background.
    let driver_task = tokio::spawn(driver);

    // Create a root certificate store with the server-fixture's self-signed
    // certificate. This is only required for offline testing with the
    // server-fixture.
    //
    // In proxy mode, the verifier must be configured with `.proxy()`.
    let verifier_config = VerifierConfig::builder()
        .root_store(RootCertStore {
            roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
        })
        .build()?;
    let verifier = handle.new_verifier(verifier_config)?;

    // Validate the proposed configuration and then accept it.
    //
    // We match here explicitly (although we know that in this example the prover
    // sent a protocol config for proxy mode) to demonstrate dynamic protocol
    // execution.
    //
    // The verifier can inspect the protocol configuration requested by the prover
    // and decide what he wants to do. Here we decide to support both, requests
    // for mpc mode and proxy mode.
    let verifier = match verifier.commit().await? {
        VerifierCommitStart::Mpc(verifier) => verifier.accept().await?.run().await?,
        VerifierCommitStart::Proxy(verifier) => {
            // In proxy mode, the verifier needs to connect to the server and set up
            // sockets to forward traffic between the prover and the server.
            //
            // In a real-world scenario, the verifier would resolve the server name
            // to obtain the server address, but since this is an example we use the
            // fixed `server_addr`.
            let client_socket = tokio::net::TcpStream::connect(server_addr).await.unwrap();
            verifier.accept().await?.run(client_socket.compat()).await?
        }
    };

    // Validate the proving request and then verify.
    let verifier = verifier.verify().await?;

    if !verifier.request().server_identity() {
        let verifier = verifier
            .reject(Some("expecting to verify the server name"))
            .await?;
        verifier.close().await?;
        return Err(anyhow::anyhow!("prover did not reveal the server name"));
    }

    let (
        VerifierOutput {
            server_name,
            transcript,
            ..
        },
        verifier,
    ) = verifier.accept().await?;

    verifier.close().await?;

    // Close the session and wait for the driver to complete.
    handle.close();
    driver_task.await??;

    let server_name = server_name.expect("prover should have revealed server name");
    let transcript = transcript.expect("prover should have revealed transcript data");

    // Check sent data.
    let sent = transcript.sent_unsafe().to_vec();
    let sent_data = String::from_utf8(sent.clone()).expect("Verifier expected sent data");
    sent_data
        .find(SERVER_DOMAIN)
        .unwrap_or_else(|| panic!("Verification failed: Expected host {SERVER_DOMAIN}"));

    // Check received data.
    let received = transcript.received_unsafe().to_vec();
    let response = String::from_utf8(received.clone()).expect("Verifier expected received data");
    response
        .find("Herman Melville")
        .unwrap_or_else(|| panic!("Expected valid data from {SERVER_DOMAIN}"));

    // Check Session info: server name.
    let ServerName::Dns(server_name) = server_name;
    assert_eq!(server_name.as_str(), SERVER_DOMAIN);

    Ok(transcript)
}

/// Render redacted bytes as `🙈`.
fn bytes_to_redacted_string(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec())
        .unwrap()
        .replace('\0', "🙈")
}
