use futures::{AsyncRead, AsyncWrite};
use tlsn_core::{attestation::AttestationConfig, signing::SignatureAlgId, CryptoProvider};
use tlsn_verifier::{Verifier, VerifierConfig};

/// The private key used by the Notary for signing attestations.
pub const NOTARY_PRIVATE_KEY: &[u8] = &[1u8; 32];

/// Runs a simple Notary with the provided connection to the Prover.
pub async fn run_notary<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(conn: T) {
    let mut provider = CryptoProvider::default();
    provider.signer.set_secp256k1(NOTARY_PRIVATE_KEY).unwrap();

    // Setup default config. Normally a different ID would be generated
    // for each notarization.
    let config = VerifierConfig::builder()
        .id("example")
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
