use tls_core::verify::WebPkiVerifier;
use tlsn_server_fixture::CA_CERT_DER;
use tokio_util::compat::TokioAsyncReadCompatExt;

use tlsn_verifier::tls::{Verifier, VerifierConfig};
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .init();

    let ip = std::env::var("VERIFIER_IP").unwrap_or_else(|_| "10.10.1.1".to_string());
    let port: u16 = std::env::var("VERIFIER_PORT")
        .map(|port| port.parse().expect("port is valid u16"))
        .unwrap_or(8000);
    let host = (ip.as_str(), port);

    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    let verifier = Verifier::new(
        VerifierConfig::builder()
            .id("test")
            .cert_verifier(WebPkiVerifier::new(root_store, None))
            .build()
            .unwrap(),
    );

    let listener = tokio::net::TcpListener::bind(host).await.unwrap();

    let (prover_conn, _) = listener.accept().await.unwrap();

    println!("connected to prover");

    verifier.verify(prover_conn.compat()).await.unwrap();

    println!("success");
}
