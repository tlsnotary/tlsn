use elliptic_curve::pkcs8::DecodePrivateKey;
use futures::{AsyncRead, AsyncWrite};
use tlsn_notary_client::client::NotaryClient;
use tlsn_prover::tls::{state::Setup, Prover};
use tlsn_verifier::tls::{Verifier, VerifierConfig};

/// Runs a simple Notary with the provided connection to the Prover.
pub async fn run_notary<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(conn: T) {
    // Load the notary signing key
    let signing_key_str = std::str::from_utf8(include_bytes!(
        "../../../notary-server/fixture/notary/notary.key"
    ))
    .unwrap();
    let signing_key = p256::ecdsa::SigningKey::from_pkcs8_pem(signing_key_str).unwrap();

    // Setup default config. Normally a different ID would be generated
    // for each notarization.
    let config = VerifierConfig::builder().id("example").build().unwrap();

    Verifier::new(config)
        .notarize::<_, p256::ecdsa::Signature>(conn, &signing_key)
        .await
        .unwrap();
}

/// Requests notarization from the Notary server.
pub async fn request_notarization(
    host: &str,
    port: u16,
    max_sent_data: Option<usize>,
    max_recv_data: Option<usize>,
    server_dns: &str,
) -> Prover<Setup> {
    let mut notary_client_builder = NotaryClient::builder();

    notary_client_builder
        .host(host)
        .port(port)
        .server_dns(server_dns);

    if let Some(max_sent_data) = max_sent_data {
        notary_client_builder.max_sent_data(max_sent_data);
    }

    if let Some(max_recv_data) = max_recv_data {
        notary_client_builder.max_recv_data(max_recv_data);
    }

    let notary_client = notary_client_builder.build().unwrap();

    // Setup tls connection to the notary server
    notary_client.setup_tls_prover().await.unwrap()
}
