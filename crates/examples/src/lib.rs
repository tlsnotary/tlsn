use std::fmt;
use tls_core::verify::WebPkiVerifier;
use tls_server_fixture::CA_CERT_DER;
use tlsn_core::CryptoProvider;

// Maximum number of bytes that can be sent from prover to server
pub const MAX_SENT_DATA: usize = 1 << 12;
// Maximum number of bytes that can be received by prover from server
pub const MAX_RECV_DATA: usize = 1 << 14;

/// crypto provider accepting the server-fixture's self-signed certificate
///
/// This is only required for offline testing with the server-fixture. In
/// production, use `CryptoProvider::default()` instead.
pub fn get_crypto_provider_with_server_fixture() -> CryptoProvider {
    // custom root store with server-fixture
    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    CryptoProvider {
        cert: WebPkiVerifier::new(root_store, None),
        ..Default::default()
    }
}

#[derive(clap::ValueEnum, Clone, Default, Debug)]
pub enum ExampleType {
    #[default]
    Json,
    Html,
    Authenticated,
}

impl fmt::Display for ExampleType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub fn get_file_path(example_type: &ExampleType, content_type: &str) -> String {
    let example_type = example_type.to_string().to_ascii_lowercase();
    format!("example-{}.{}.tlsn", example_type, content_type)
}
