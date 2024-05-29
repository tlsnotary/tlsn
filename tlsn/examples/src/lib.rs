use elliptic_curve::pkcs8::DecodePrivateKey;
use futures::{AsyncRead, AsyncWrite};
use std::io::BufReader;
use tls_core::key::Certificate;
use tlsn_verifier::tls::{Verifier, VerifierConfig};
use tokio::fs::File;

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

/// Parse certificate as tls-core's Certificate struct, so that one can use tls-client's RootCertStore to add the cert
pub async fn parse_cert(file_path: &str) -> Certificate {
    let key_file = File::open(file_path).await.unwrap().into_std().await;
    let mut certificate_file_reader = BufReader::new(key_file);
    let mut certificates: Vec<Certificate> = rustls_pemfile::certs(&mut certificate_file_reader)
        .unwrap()
        .into_iter()
        .map(Certificate)
        .collect();
    certificates.remove(0)
}
