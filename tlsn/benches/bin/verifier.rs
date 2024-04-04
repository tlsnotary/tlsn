use anyhow::Context;
use tls_core::verify::WebPkiVerifier;
use tlsn_benches::{
    config::{BenchInstance, Config},
    set_interface, VERIFIER_INTERFACE,
};
use tlsn_server_fixture::CA_CERT_DER;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::TokioAsyncReadCompatExt;

use tlsn_verifier::tls::{Verifier, VerifierConfig};
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config_path = std::env::var("CFG").unwrap_or_else(|_| "bench.toml".to_string());
    let config: Config = toml::from_str(
        &std::fs::read_to_string(config_path).context("failed to read config file")?,
    )
    .context("failed to parse config")?;

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .init();

    let ip = std::env::var("VERIFIER_IP").unwrap_or_else(|_| "10.10.1.1".to_string());
    let port: u16 = std::env::var("VERIFIER_PORT")
        .map(|port| port.parse().expect("port is valid u16"))
        .unwrap_or(8000);
    let host = (ip.as_str(), port);

    let listener = tokio::net::TcpListener::bind(host)
        .await
        .context("failed to bind to port")?;

    for bench in config.benches {
        for instance in bench.flatten() {
            let (io, _) = listener
                .accept()
                .await
                .context("failed to accept connection")?;
            run_instance(instance, io)
                .await
                .context("failed to run instance")?;
        }
    }

    Ok(())
}

async fn run_instance<S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    instance: BenchInstance,
    io: S,
) -> anyhow::Result<()> {
    let BenchInstance {
        download,
        download_delay,
        upload_size,
        download_size,
        ..
    } = instance;

    set_interface(VERIFIER_INTERFACE, download, 1, download_delay)?;

    let verifier = Verifier::new(
        VerifierConfig::builder()
            .id("test")
            .cert_verifier(cert_verifier())
            .max_sent_data(upload_size + 256)
            .max_recv_data(download_size + 256)
            .build()?,
    );

    _ = verifier.verify(io.compat()).await?;

    println!("verifier done");

    Ok(())
}

fn cert_verifier() -> WebPkiVerifier {
    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    WebPkiVerifier::new(root_store, None)
}
