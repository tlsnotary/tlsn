//! Example demonstrating predicate proving over transcript data.
//!
//! This example shows how a prover can prove a predicate (boolean constraint)
//! over transcript bytes in zero knowledge, without revealing the actual data.
//!
//! In this example:
//! - The server returns JSON data containing a "name" field with a string value
//! - The prover proves that the name value is a valid JSON string without
//!   revealing it
//! - The verifier learns that the string is valid JSON, but not the actual
//!   content

use std::{
    env,
    net::{IpAddr, SocketAddr},
};

use anyhow::Result;
use http_body_util::Empty;
use hyper::{body::Bytes, Request, StatusCode, Uri};
use hyper_util::rt::TokioIo;
use mpz_predicate::{json::validate_string, Pred};
use rangeset::prelude::RangeSet;
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
    transcript::Direction,
    verifier::{Verifier, VerifierOutput},
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_server_fixture::DEFAULT_FIXTURE_PORT;
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};

/// Predicate name for JSON string validation (both parties agree on this
/// out-of-band).
const JSON_STRING_PREDICATE: &str = "valid_json_string";

// Maximum number of bytes that can be sent from prover to server.
const MAX_SENT_DATA: usize = 1 << 12;
// Maximum number of bytes that can be received by prover from server.
const MAX_RECV_DATA: usize = 1 << 14;

/// Builds a predicate that validates a JSON string at the given indices.
///
/// Uses mpz_predicate's `validate_string` to ensure the bytes form a valid
/// JSON string (proper escaping, valid UTF-8, no control characters, etc.).
fn build_json_string_predicate(indices: &RangeSet<usize>) -> Pred {
    validate_string(indices.clone())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let server_host: String = env::var("SERVER_HOST").unwrap_or("127.0.0.1".into());
    let server_port: u16 = env::var("SERVER_PORT")
        .map(|port| port.parse().expect("port should be valid integer"))
        .unwrap_or(DEFAULT_FIXTURE_PORT);

    // Use the JSON endpoint that returns data.
    let uri = format!("https://{SERVER_DOMAIN}:{server_port}/formats/json");
    let server_ip: IpAddr = server_host.parse().expect("Invalid IP address");
    let server_addr = SocketAddr::from((server_ip, server_port));

    // Connect prover and verifier.
    let (prover_socket, verifier_socket) = tokio::io::duplex(1 << 23);
    let prover = prover(prover_socket, &server_addr, &uri);
    let verifier = verifier(verifier_socket);

    match tokio::try_join!(prover, verifier) {
        Ok(_) => println!("\nSuccess! The prover proved that a JSON field contains a valid string without revealing it."),
        Err(e) => eprintln!("Error: {e}"),
    }
}

/// Finds the value of a JSON field in the response body.
/// Returns (start_index, end_index) of the value (excluding quotes for
/// strings).
fn find_json_string_value(data: &[u8], field_name: &str) -> Option<(usize, usize)> {
    let search_pattern = format!("\"{}\":", field_name);
    let pattern_bytes = search_pattern.as_bytes();

    // Find the field name
    let field_pos = data
        .windows(pattern_bytes.len())
        .position(|w| w == pattern_bytes)?;

    // Skip past the field name and colon
    let mut pos = field_pos + pattern_bytes.len();

    // Skip whitespace
    while pos < data.len() && (data[pos] == b' ' || data[pos] == b'\n' || data[pos] == b'\r') {
        pos += 1;
    }

    // Check if it's a string (starts with quote)
    if pos >= data.len() || data[pos] != b'"' {
        return None;
    }

    // Skip opening quote
    let start = pos + 1;

    // Find closing quote (handling escapes)
    let mut end = start;
    while end < data.len() {
        if data[end] == b'\\' {
            // Skip escaped character
            end += 2;
        } else if data[end] == b'"' {
            break;
        } else {
            end += 1;
        }
    }

    Some((start, end))
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
                .protocol(
                    MpcTlsConfig::builder()
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

    // Send request for JSON data.
    let request = Request::builder()
        .uri(uri.clone())
        .header("Host", server_domain)
        .header("Connection", "close")
        .method("GET")
        .body(Empty::<Bytes>::new())?;
    let response = request_sender.send_request(request).await?;

    assert!(response.status() == StatusCode::OK);

    // Create proof for the Verifier.
    let mut prover = prover_task.await??;

    // Find the "name" field value in the JSON response
    let received = prover.transcript().received();

    // Find the HTTP body (after \r\n\r\n)
    let body_start = received
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(0);

    // Find the "name" field's string value
    let (value_start, value_end) =
        find_json_string_value(&received[body_start..], "name").expect("should find name field");

    // Adjust to absolute positions in transcript
    let value_start = body_start + value_start;
    let value_end = body_start + value_end;

    let value_bytes = &received[value_start..value_end];
    println!(
        "Prover: Found 'name' field value: \"{}\" at positions {}..{}",
        String::from_utf8_lossy(value_bytes),
        value_start,
        value_end
    );
    println!("Prover: Will prove this is a valid JSON string without revealing the actual content");

    // Build indices for the predicate as a RangeSet
    let indices: RangeSet<usize> = (value_start..value_end).into();

    // Build the predicate using mpz_predicate
    let predicate = build_json_string_predicate(&indices);

    let mut builder = ProveConfig::builder(prover.transcript());

    // Reveal the server identity.
    builder.server_identity();

    // Reveal the sent data (the request).
    builder.reveal_sent(&(0..prover.transcript().sent().len()))?;

    // Reveal everything EXCEPT the string value we're proving the predicate over.
    if value_start > 0 {
        builder.reveal_recv(&(0..value_start))?;
    }
    if value_end < prover.transcript().received().len() {
        builder.reveal_recv(&(value_end..prover.transcript().received().len()))?;
    }

    // Add the predicate to prove the string is valid JSON without revealing the
    // value.
    builder.predicate(JSON_STRING_PREDICATE, Direction::Received, predicate)?;

    let config = builder.build()?;

    prover.prove(&config).await?;
    prover.close().await?;

    println!("Prover: Successfully proved the predicate!");

    Ok(())
}

#[instrument(skip(socket))]
async fn verifier<T: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: T,
) -> Result<()> {
    let verifier_config = VerifierConfig::builder()
        .root_store(RootCertStore {
            roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
        })
        .build()?;
    let verifier = Verifier::new(verifier_config);

    // Validate the proposed configuration and run the TLS commitment protocol.
    let verifier = verifier.commit(socket.compat()).await?;

    // Validate configuration.
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

    // Run the TLS commitment protocol.
    let verifier = verifier.accept().await?.run().await?;

    // Validate the proving request.
    let verifier = verifier.verify().await?;

    // Check that server identity is being proven.
    if !verifier.request().server_identity() {
        let verifier = verifier
            .reject(Some("expecting to verify the server name"))
            .await?;
        verifier.close().await?;
        return Err(anyhow::anyhow!("prover did not reveal the server name"));
    }

    // Check if predicates are requested and validate them.
    let predicates = verifier.request().predicates();
    if !predicates.is_empty() {
        println!(
            "Verifier: Prover requested {} predicate(s):",
            predicates.len()
        );
        for pred in predicates {
            println!(
                "  - '{}' on {:?} at {} indices",
                pred.name(),
                pred.direction(),
                pred.indices().len()
            );
        }
    }

    // Define the predicate resolver - this maps predicate names to predicates.
    // The resolver receives the predicate name and the indices from the prover's
    // request.
    let predicate_resolver = |name: &str, indices: &RangeSet<usize>| -> Option<Pred> {
        match name {
            JSON_STRING_PREDICATE => {
                // Build the JSON string validation predicate with the provided indices
                Some(build_json_string_predicate(indices))
            }
            _ => None,
        }
    };

    // Accept with predicate verification.
    let (
        VerifierOutput {
            server_name,
            transcript,
            ..
        },
        verifier,
    ) = verifier
        .accept_with_predicates(Some(&predicate_resolver))
        .await?;

    verifier.close().await?;

    let server_name = server_name.expect("prover should have revealed server name");
    let transcript = transcript.expect("prover should have revealed transcript data");

    // Verify server name.
    let ServerName::Dns(server_name) = server_name;
    assert_eq!(server_name.as_str(), SERVER_DOMAIN);

    // The verifier can see the response but with the predicated string redacted.
    let received = transcript.received_unsafe();
    let redacted = String::from_utf8_lossy(received).replace('\0', "[REDACTED]");
    println!("Verifier: Received data (string value redacted):\n{redacted}");

    println!("Verifier: Predicate verified successfully!");
    println!("Verifier: The hidden value is proven to be a valid JSON string");

    Ok(())
}
