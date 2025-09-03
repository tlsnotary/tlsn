mod prover;
mod types;
mod verifier;

use prover::prover;
use std::{
    env,
    net::{IpAddr, SocketAddr},
};
use tlsn_server_fixture::DEFAULT_FIXTURE_PORT;
use tlsn_server_fixture_certs::SERVER_DOMAIN;
use verifier::verifier;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let server_host: String = env::var("SERVER_HOST").unwrap_or("127.0.0.1".into());
    let server_port: u16 = env::var("SERVER_PORT")
        .map(|port| port.parse().expect("port should be valid integer"))
        .unwrap_or(DEFAULT_FIXTURE_PORT);

    // We use SERVER_DOMAIN here to make sure it matches the domain in the test
    // server's certificate.
    let uri = format!("https://{SERVER_DOMAIN}:{server_port}/elster");
    let server_ip: IpAddr = server_host.parse().expect("Invalid IP address");
    let server_addr = SocketAddr::from((server_ip, server_port));

    // Connect prover and verifier.
    let (prover_socket, verifier_socket) = tokio::io::duplex(1 << 23);
    let (prover_extra_socket, verifier_extra_socket) = tokio::io::duplex(1 << 23);
    let prover = prover(prover_socket, prover_extra_socket, &server_addr, &uri);
    let verifier = verifier(verifier_socket, verifier_extra_socket);
    let (_, transcript) = tokio::join!(prover, verifier);

    println!("---");
    println!("Successfully verified {}", &uri);
    println!("Age verified in ZK: 18+ ✅\n");
    println!(
        "Verified sent data:\n{}",
        bytes_to_redacted_string(transcript.sent_unsafe())
    );
    println!(
        "Verified received data:\n{}",
        bytes_to_redacted_string(transcript.received_unsafe())
    );
}

/// Render redacted bytes as `🙈`.
pub fn bytes_to_redacted_string(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec())
        .unwrap()
        .replace('\0', "🙈")
}
