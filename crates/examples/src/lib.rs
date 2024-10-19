use futures::{AsyncRead, AsyncWrite};
use k256::{pkcs8::DecodePrivateKey, SecretKey};
use tlsn_common::config::ProtocolConfigValidator;
use tlsn_core::{attestation::AttestationConfig, signing::SignatureAlgId, CryptoProvider};
use tlsn_verifier::{Verifier, VerifierConfig};

/// The private key used by the Notary for signing attestations.
pub const NOTARY_PRIVATE_KEY: &[u8] = &[1u8; 32];

// Maximum number of bytes that can be sent from prover to server
const MAX_SENT_DATA: usize = 1 << 12;
// Maximum number of bytes that can be received by prover from server
const MAX_RECV_DATA: usize = 1 << 14;

/// Runs a simple Notary with the provided connection to the Prover.
pub async fn run_notary<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(conn: T) {
    let pem_data = include_str!("../../notary/server/fixture/notary/notary.key");
    let secret_key = SecretKey::from_pkcs8_pem(pem_data).unwrap().to_bytes();

    let mut provider = CryptoProvider::default();
    provider.signer.set_secp256k1(&secret_key).unwrap();

    // Setup the config. Normally a different ID would be generated
    // for each notarization.
    let config_validator = ProtocolConfigValidator::builder()
        .max_sent_data(MAX_SENT_DATA)
        .max_recv_data(MAX_RECV_DATA)
        .build()
        .unwrap();

    let config = VerifierConfig::builder()
        .protocol_config_validator(config_validator)
        .crypto_provider(provider)
        .build()
        .unwrap();

    let attestation_config = AttestationConfig::builder()
        .supported_signature_algs(vec![SignatureAlgId::SECP256K1])
        .build()
        .unwrap();

    Verifier::new(config)
        .notarize(conn, &attestation_config)
        .await
        .unwrap();
}
