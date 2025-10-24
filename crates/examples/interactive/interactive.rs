use std::{
    env,
    net::{IpAddr, SocketAddr},
};

use anyhow::Result;
use http_body_util::Empty;
use hyper::{body::Bytes, Request, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::instrument;

use tlsn::{
    config::{
        prove::ProveConfig,
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::{mpc::MpcTlsConfig, TlsCommitConfig, TlsCommitProtocolConfig},
        verifier::VerifierConfig,
    },
    connection::ServerName,
    prover::Prover,
    transcript::PartialTranscript,
    verifier::{Verifier, VerifierOutput},
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_server_fixture::DEFAULT_FIXTURE_PORT;
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};

const SECRET: &str = "TLSNotary's private key 🤡";

// Maximum number of bytes that can be sent from prover to server.
const MAX_SENT_DATA: usize = 1 << 12;
// Maximum number of bytes that can be received by prover from server.
const MAX_RECV_DATA: usize = 1 << 14;

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
    let prover = prover(prover_socket, &server_addr, &uri);
    let verifier = verifier(verifier_socket);
    let (_, transcript) = tokio::try_join!(prover, verifier).unwrap();

    println!("Successfully verified {}", &uri);
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
    server_addr: &SocketAddr,
    uri: &str,
) -> Result<()> {
    let uri = uri.parse::<Uri>().unwrap();
    assert_eq!(uri.scheme().unwrap().as_str(), "https");
    let server_domain = uri.authority().unwrap().host();

    // Create a new prover and perform necessary setup.
    let prover = Prover::new(ProverConfig::builder().build()?)
        .commit(
            TlsCommitConfig::builder()
                // Select the TLS commitment protocol.
                .protocol(
                    MpcTlsConfig::builder()
                        // We must configure the amount of data we expect to exchange beforehand,
                        // which will be preprocessed prior to the
                        // connection. Reducing these limits will improve
                        // performance.
                        .max_sent_data(tlsn_examples::MAX_SENT_DATA)
                        .max_recv_data(tlsn_examples::MAX_RECV_DATA)
                        .build()?,
                )
                .build()?,
            verifier_socket.compat(),
        )
        .await?;

    // Open a TCP connection to the server.
    let client_socket = tokio::net::TcpStream::connect(server_addr).await?;

    // Bind the prover to the server connection.
    let (tls_connection, prover_fut) = prover
        .connect(
            TlsClientConfig::builder()
                .server_name(ServerName::Dns(SERVER_DOMAIN.try_into()?))
                // Create a root certificate store with the server-fixture's self-signed
                // certificate. This is only required for offline testing with the
                // server-fixture.
                .root_store(RootCertStore {
                    roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
                })
                .build()?,
            client_socket.compat(),
        )
        .await?;
    let tls_connection = TokioIo::new(tls_connection.compat());

    // Spawn the Prover to run in the background.
    let prover_task = tokio::spawn(prover_fut);

    // MPC-TLS Handshake.
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(tls_connection).await?;

    // Spawn the connection to run in the background.
    tokio::spawn(connection);

    // MPC-TLS: Send Request and wait for Response.
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

    Ok(())
}

#[instrument(skip(socket))]
async fn verifier<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: T,
) -> Result<PartialTranscript> {
    // Create a root certificate store with the server-fixture's self-signed
    // certificate. This is only required for offline testing with the
    // server-fixture.
    let verifier_config = VerifierConfig::builder()
        .root_store(RootCertStore {
            roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
        })
        .build()?;
    let verifier = Verifier::new(verifier_config);

    // Validate the proposed configuration and then run the TLS commitment protocol.
    let verifier = verifier.commit(socket.compat()).await?;

    // This is the opportunity to ensure the prover does not attempt to overload the
    // verifier.
    let reject = if let TlsCommitProtocolConfig::Mpc(mpc_tls_config) = verifier.request().protocol()
    {
        if mpc_tls_config.max_sent_data() > MAX_SENT_DATA {
            Some("max_sent_data is too large")
        } else if mpc_tls_config.max_recv_data() > MAX_RECV_DATA {
            Some("max_recv_data is too large")
        } else {
            None
        }
    } else {
        Some("expecting to use MPC-TLS")
    };

    if reject.is_some() {
        verifier.reject(reject).await?;
        return Err(anyhow::anyhow!("protocol configuration rejected"));
    }

    // Runs the TLS commitment protocol to completion.
    let verifier = verifier.accept().await?.run().await?;

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
