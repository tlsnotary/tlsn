// This example demonstrates how to use the Prover to acquire an attestation for
// an HTTP request sent to a server fixture. The attestation and secrets are
// saved to disk.

use std::env;

use anyhow::Result;
use clap::Parser;
use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use http_body_util::Empty;
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::info;

use tlsn::{
    attestation::{
        request::{Request as AttestationRequest, RequestConfig},
        signing::Secp256k1Signer,
        Attestation, AttestationConfig, CryptoProvider, Secrets,
    },
    config::{
        prove::ProveConfig,
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::{mpc::MpcTlsConfig, TlsCommitConfig},
        verifier::VerifierConfig,
    },
    connection::{ConnectionInfo, HandshakeData, ServerName, TranscriptLength},
    prover::{state::Committed, Prover, ProverOutput},
    transcript::{ContentType, TranscriptCommitConfig},
    verifier::VerifierOutput,
    webpki::{CertificateDer, PrivateKeyDer, RootCertStore},
    Session,
};
use tlsn_examples::ExampleType;
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};
use tlsn_server_fixture::DEFAULT_FIXTURE_PORT;
use tlsn_server_fixture_certs::{CA_CERT_DER, CLIENT_CERT_DER, CLIENT_KEY_DER, SERVER_DOMAIN};

// Setting of the application server.
const USER_AGENT: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36";

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// What data to notarize.
    #[clap(default_value_t, value_enum)]
    example_type: ExampleType,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let (uri, extra_headers) = match args.example_type {
        ExampleType::Json => ("/formats/json", vec![]),
        ExampleType::Html => ("/formats/html", vec![]),
        ExampleType::Authenticated => ("/protected", vec![("Authorization", "random_auth_token")]),
    };

    let (notary_socket, prover_socket) = tokio::io::duplex(1 << 23);

    tokio::spawn(async move { notary(notary_socket).await.unwrap() });

    prover(prover_socket, uri, extra_headers, &args.example_type).await?;

    Ok(())
}

async fn prover<S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: S,
    uri: &str,
    extra_headers: Vec<(&str, &str)>,
    example_type: &ExampleType,
) -> Result<()> {
    let server_host: String = env::var("SERVER_HOST").unwrap_or("127.0.0.1".into());
    let server_port: u16 = env::var("SERVER_PORT")
        .map(|port| port.parse().expect("port should be valid integer"))
        .unwrap_or(DEFAULT_FIXTURE_PORT);

    // Create a session with the notary.
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();

    // Spawn the session driver to run in the background.
    let driver_task = tokio::spawn(driver);

    // Create a new prover and perform necessary setup.
    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
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
        )
        .await?;

    // Open a TCP connection to the server.
    let client_socket = tokio::net::TcpStream::connect((server_host, server_port)).await?;

    // Bind the prover to the server connection.
    let (tls_connection, prover_fut) = prover.connect(
        TlsClientConfig::builder()
            .server_name(ServerName::Dns(SERVER_DOMAIN.try_into()?))
            // Create a root certificate store with the server-fixture's self-signed
            // certificate. This is only required for offline testing with the
            // server-fixture.
            .root_store(RootCertStore {
                roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
            })
            // (Optional) Set up TLS client authentication if required by the server.
            .client_auth((
                vec![CertificateDer(CLIENT_CERT_DER.to_vec())],
                PrivateKeyDer(CLIENT_KEY_DER.to_vec()),
            ))
            .build()?,
        client_socket.compat(),
    )?;
    let tls_connection = TokioIo::new(tls_connection.compat());

    // Spawn the prover task to be run concurrently in the background.
    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the connection.
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(tls_connection).await?;

    // Spawn the HTTP task to be run concurrently in the background.
    tokio::spawn(connection);

    // Build a simple HTTP request with common headers.
    let request_builder = Request::builder()
        .uri(uri)
        .header("Host", SERVER_DOMAIN)
        .header("Accept", "*/*")
        // Using "identity" instructs the Server not to use compression for its HTTP response.
        // TLSNotary tooling does not support compression.
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("User-Agent", USER_AGENT);
    let mut request_builder = request_builder;
    for (key, value) in extra_headers {
        request_builder = request_builder.header(key, value);
    }
    let request = request_builder.body(Empty::<Bytes>::new())?;

    info!("Starting connection with the server");

    // Send the request to the server and wait for the response.
    let response = request_sender.send_request(request).await?;

    info!("Got a response from the server: {}", response.status());

    assert!(response.status() == StatusCode::OK);

    // The prover task should be done now, so we can await it.
    let prover = prover_task.await??;

    // Parse the HTTP transcript.
    let transcript = HttpTranscript::parse(prover.transcript())?;

    let response_body = transcript.responses[0].body.as_ref().unwrap();
    let body_bytes = response_body.content_data();
    let body_str = String::from_utf8_lossy(&body_bytes);
    match &response_body.content {
        tlsn_formats::http::BodyContent::Json(_json) => {
            let parsed = serde_json::from_str::<serde_json::Value>(&body_str)?;
            info!("{}", serde_json::to_string_pretty(&parsed)?);
        }
        _ => {
            info!("{}", &body_str);
        }
    }

    // Commit to the transcript.
    let mut builder = TranscriptCommitConfig::builder(prover.transcript());

    // This commits to various parts of the transcript separately (e.g. request
    // headers, response headers, response body and more). See https://docs.tlsnotary.org//protocol/commit_strategy.html
    // for other strategies that can be used to generate commitments.
    DefaultHttpCommitter::default().commit_transcript(&mut builder, &transcript)?;

    let transcript_commit = builder.build()?;

    // Build an attestation request.
    let mut builder = RequestConfig::builder();

    builder.transcript_commit(transcript_commit);

    // Optionally, add an extension to the attestation if the notary supports it.
    // builder.extension(Extension {
    //     id: b"example.name".to_vec(),
    //     value: b"Bobert".to_vec(),
    // });

    let request_config = builder.build()?;

    // Notarize the session, exchanging the attestation request/response over the
    // wire.
    let (attestation, secrets) =
        notarize(prover, &request_config, &mut handle, driver_task).await?;

    // Write the attestation to disk.
    let attestation_path = tlsn_examples::get_file_path(example_type, "attestation");
    let secrets_path = tlsn_examples::get_file_path(example_type, "secrets");

    tokio::fs::write(&attestation_path, bincode::serialize(&attestation)?).await?;

    // Write the secrets to disk.
    tokio::fs::write(&secrets_path, bincode::serialize(&secrets)?).await?;

    println!("Notarization completed successfully!");
    println!(
        "The attestation has been written to `{attestation_path}` and the \
        corresponding secrets to `{secrets_path}`."
    );

    Ok(())
}

/// Performs the notarization step, sending the attestation request and
/// receiving the attestation over the wire.
async fn notarize<S: futures::io::AsyncRead + futures::io::AsyncWrite + Send + Unpin + 'static>(
    mut prover: Prover<Committed>,
    config: &RequestConfig,
    handle: &mut tlsn::SessionHandle,
    driver_task: tokio::task::JoinHandle<tlsn::Result<S>>,
) -> Result<(Attestation, Secrets)> {
    // Build the prove config.
    let mut builder = ProveConfig::builder(prover.transcript());

    if let Some(config) = config.transcript_commit() {
        builder.transcript_commit(config.clone());
    }

    let disclosure_config = builder.build()?;

    let ProverOutput {
        transcript_commitments,
        transcript_secrets,
        ..
    } = prover.prove(&disclosure_config).await?;

    let transcript = prover.transcript().clone();
    let tls_transcript = prover.tls_transcript().clone();
    prover.close().await?;

    // Build an attestation request.
    let mut builder = AttestationRequest::builder(config);

    builder
        .server_name(ServerName::Dns(SERVER_DOMAIN.try_into().unwrap()))
        .handshake_data(HandshakeData {
            certs: tls_transcript
                .server_cert_chain()
                .expect("server cert chain is present")
                .to_vec(),
            sig: tls_transcript
                .server_signature()
                .expect("server signature is present")
                .clone(),
            binding: tls_transcript.certificate_binding().clone(),
        })
        .transcript(transcript)
        .transcript_commitments(transcript_secrets, transcript_commitments);

    let (request, secrets) = builder.build(&CryptoProvider::default())?;

    // Close the session and wait for the driver to complete, reclaiming the socket.
    handle.close();
    let mut socket = driver_task.await??;

    // Send attestation request to notary over the wire.
    let request_bytes = bincode::serialize(&request)?;
    socket.write_all(&request_bytes).await?;
    socket.close().await?;

    // Receive attestation from notary over the wire.
    let mut attestation_bytes = Vec::new();
    socket.read_to_end(&mut attestation_bytes).await?;
    let attestation: Attestation = bincode::deserialize(&attestation_bytes)?;

    // Signature verifier for the signature algorithm in the request.
    let provider = CryptoProvider::default();

    // Check the attestation is consistent with the Prover's view.
    request.validate(&attestation, &provider)?;

    Ok((attestation, secrets))
}

async fn notary<S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: S,
) -> Result<()> {
    // Create a session with the prover.
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();

    // Spawn the session driver to run in the background.
    let driver_task = tokio::spawn(driver);

    // Create a root certificate store with the server-fixture's self-signed
    // certificate. This is only required for offline testing with the
    // server-fixture.
    let verifier_config = VerifierConfig::builder()
        .root_store(RootCertStore {
            roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
        })
        .build()
        .unwrap();

    let verifier = handle
        .new_verifier(verifier_config)?
        .commit()
        .await?
        .accept()
        .await?
        .run()
        .await?;

    let (
        VerifierOutput {
            transcript_commitments,
            ..
        },
        verifier,
    ) = verifier.verify().await?.accept().await?;

    let tls_transcript = verifier.tls_transcript().clone();

    verifier.close().await?;

    let sent_len = tls_transcript
        .sent()
        .iter()
        .filter_map(|record| {
            if let ContentType::ApplicationData = record.typ {
                Some(record.ciphertext.len())
            } else {
                None
            }
        })
        .sum::<usize>();

    let recv_len = tls_transcript
        .recv()
        .iter()
        .filter_map(|record| {
            if let ContentType::ApplicationData = record.typ {
                Some(record.ciphertext.len())
            } else {
                None
            }
        })
        .sum::<usize>();

    // Close the session and wait for the driver to complete, reclaiming the socket.
    handle.close();
    let mut socket = driver_task.await??;

    // Receive attestation request from prover.
    let mut request_bytes = Vec::new();
    socket.read_to_end(&mut request_bytes).await?;
    let request: AttestationRequest = bincode::deserialize(&request_bytes)?;

    // Load a dummy signing key.
    let signing_key = k256::ecdsa::SigningKey::from_bytes(&[1u8; 32].into())?;
    let signer = Box::new(Secp256k1Signer::new(&signing_key.to_bytes())?);
    let mut provider = CryptoProvider::default();
    provider.signer.set_signer(signer);

    // Build an attestation.
    let mut att_config_builder = AttestationConfig::builder();
    att_config_builder.supported_signature_algs(Vec::from_iter(provider.signer.supported_algs()));
    let att_config = att_config_builder.build()?;

    let mut builder = Attestation::builder(&att_config).accept_request(request)?;
    builder
        .connection_info(ConnectionInfo {
            time: tls_transcript.time(),
            version: (*tls_transcript.version()),
            transcript_length: TranscriptLength {
                sent: sent_len as u32,
                received: recv_len as u32,
            },
        })
        .server_ephemeral_key(tls_transcript.server_ephemeral_key().clone())
        .transcript_commitments(transcript_commitments);

    let attestation = builder.build(&provider)?;

    // Send attestation to prover.
    let attestation_bytes = bincode::serialize(&attestation)?;
    socket.write_all(&attestation_bytes).await?;
    socket.close().await?;

    Ok(())
}
