use elliptic_curve::pkcs8::DecodePrivateKey;
use futures::{AsyncRead, AsyncWrite};
use tlsn_common::config::ProtocolConfigValidator;
use tlsn_verifier::tls::{Verifier, VerifierConfig};

// Maximum number of bytes that can be sent from prover to server
const MAX_SENT_DATA: usize = 1 << 12;
// Maximum number of bytes that can be received by prover from server
const MAX_RECV_DATA: usize = 1 << 14;

/// Runs a simple Notary with the provided connection to the Prover.
pub async fn run_notary<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(conn: T) {
    // Load the notary signing key
    let signing_key_str = std::str::from_utf8(include_bytes!(
        "../../notary/server/fixture/notary/notary.key"
    ))
    .unwrap();
    let signing_key = p256::ecdsa::SigningKey::from_pkcs8_pem(signing_key_str).unwrap();

    // Setup the config. Normally a different ID would be generated
    // for each notarization.
    let config_validator = ProtocolConfigValidator::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .build()
        .unwrap();

    let config = VerifierConfig::builder()
        .id("example")
        .protocol_config_validator(config_validator)
        .build()
        .unwrap();

    Verifier::new(config)
        .notarize::<_, p256::ecdsa::Signature>(conn, &signing_key)
        .await
        .unwrap();
}
