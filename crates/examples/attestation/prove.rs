// This example demonstrates how to use the Prover to acquire an attestation for
// an HTTP request sent to example.com. The attestation and secrets are saved to
// disk.

use std::env;

use http_body_util::Empty;
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use spansy::Spanned;
use tlsn_examples::ExampleType;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use notary_client::{Accepted, NotarizationRequest, NotaryClient};
use tls_server_fixture::SERVER_DOMAIN;
use tlsn_common::config::ProtocolConfig;
use tlsn_core::{request::RequestConfig, transcript::TranscriptCommitConfig};
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};
use tlsn_prover::{Prover, ProverConfig};
use tlsn_server_fixture::DEFAULT_FIXTURE_PORT;
use tracing::debug;

use clap::Parser;

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
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let (uri, extra_headers) = match args.example_type {
        ExampleType::Json => ("/formats/json", vec![]),
        ExampleType::Html => ("/formats/html", vec![]),
        ExampleType::Authenticated => ("/protected", vec![("Authorization", "random_auth_token")]),
    };

    notarize(uri, extra_headers, &args.example_type).await
}

async fn notarize(
    uri: &str,
    extra_headers: Vec<(&str, &str)>,
    example_type: &ExampleType,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let notary_host: String = env::var("NOTARY_HOST").unwrap_or("127.0.0.1".into());
    let notary_port: u16 = env::var("NOTARY_PORT")
        .map(|port| port.parse().expect("port should be valid integer"))
        .unwrap_or(7047);
    let server_host: String = env::var("SERVER_HOST").unwrap_or("127.0.0.1".into());
    let server_port: u16 = env::var("SERVER_PORT")
        .map(|port| port.parse().expect("port should be valid integer"))
        .unwrap_or(DEFAULT_FIXTURE_PORT);

    // Build a client to connect to the notary server.
    let notary_client = NotaryClient::builder()
        .host(notary_host)
        .port(notary_port)
        // WARNING: Always use TLS to connect to notary server, except if notary is running locally
        // e.g. this example, hence `enable_tls` is set to False (else it always defaults to True).
        .enable_tls(false)
        .build()
        .unwrap();

    // Send requests for configuration and notarization to the notary server.
    let notarization_request = NotarizationRequest::builder()
        // We must configure the amount of data we expect to exchange beforehand, which will
        // be preprocessed prior to the connection. Reducing these limits will improve
        // performance.
        .max_sent_data(tlsn_examples::MAX_SENT_DATA)
        .max_recv_data(tlsn_examples::MAX_RECV_DATA)
        .build()?;

    let Accepted {
        io: notary_connection,
        id: _session_id,
        ..
    } = notary_client
        .request_notarization(notarization_request)
        .await
        .expect("Could not connect to notary. Make sure it is running.");

    // Set up protocol configuration for prover.
    // Prover configuration.
    let prover_config = ProverConfig::builder()
        .server_name(SERVER_DOMAIN)
        .protocol_config(
            ProtocolConfig::builder()
                // We must configure the amount of data we expect to exchange beforehand, which will
                // be preprocessed prior to the connection. Reducing these limits will improve
                // performance.
                .max_sent_data(tlsn_examples::MAX_SENT_DATA)
                .max_recv_data(tlsn_examples::MAX_RECV_DATA)
                .build()?,
        )
        .crypto_provider(tlsn_examples::get_crypto_provider_with_server_fixture())
        .build()?;

    // Create a new prover and perform necessary setup.
    let prover = Prover::new(prover_config)
        .setup(notary_connection.compat())
        .await?;

    // Open a TCP connection to the server.
    let client_socket = tokio::net::TcpStream::connect((server_host, server_port)).await?;

    // Bind the prover to the server connection.
    // The returned `mpc_tls_connection` is an MPC TLS connection to the server: all
    // data written to/read from it will be encrypted/decrypted using MPC with
    // the notary.
    let (mpc_tls_connection, prover_fut) = prover.connect(client_socket.compat()).await?;
    let mpc_tls_connection = TokioIo::new(mpc_tls_connection.compat());

    // Spawn the prover task to be run concurrently in the background.
    let prover_task = tokio::spawn(prover_fut);

    // Attach the hyper HTTP client to the connection.
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection).await?;

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

    println!("Starting an MPC TLS connection with the server");

    // Send the request to the server and wait for the response.
    let response = request_sender.send_request(request).await?;

    println!("Got a response from the server: {}", response.status());

    assert!(response.status() == StatusCode::OK);

    // The prover task should be done now, so we can await it.
    let prover = prover_task.await??;

    // Prepare for notarization.
    let mut prover = prover.start_notarize();

    // Parse the HTTP transcript.
    let transcript = HttpTranscript::parse(prover.transcript())?;

    let body_content = &transcript.responses[0].body.as_ref().unwrap().content;
    let body = String::from_utf8_lossy(body_content.span().as_bytes());

    match body_content {
        tlsn_formats::http::BodyContent::Json(_json) => {
            let parsed = serde_json::from_str::<serde_json::Value>(&body)?;
            debug!("{}", serde_json::to_string_pretty(&parsed)?);
        }
        tlsn_formats::http::BodyContent::Unknown(_span) => {
            debug!("{}", &body);
        }
        _ => {}
    }

    // Commit to the transcript.
    let mut builder = TranscriptCommitConfig::builder(prover.transcript());

    // This commits to various parts of the transcript separately (e.g. request
    // headers, response headers, response body and more). See https://docs.tlsnotary.org//protocol/commit_strategy.html
    // for other strategies that can be used to generate commitments.
    DefaultHttpCommitter::default().commit_transcript(&mut builder, &transcript)?;

    prover.transcript_commit(builder.build()?);

    // Build an attestation request.
    let builder = RequestConfig::builder();

    // Optionally, add an extension to the attestation if the notary supports it.
    // builder.extension(Extension {
    //     id: b"example.name".to_vec(),
    //     value: b"Bobert".to_vec(),
    // });

    let request_config = builder.build()?;

    let (attestation, secrets) = prover.finalize(&request_config).await?;

    println!("Notarization complete!");

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
