//! Contains the actual main() function of the verifier binary. It is moved here
//! in order to enable cargo to build two verifier binaries - with and without
//! memory profiling.

use crate::{
    config::{BenchInstance, Config},
    set_interface, VERIFIER_INTERFACE,
};
use tls_core::verify::WebPkiVerifier;
use tlsn_common::config::ProtocolConfigValidator;
use tlsn_core::CryptoProvider;
use tlsn_server_fixture_certs::CA_CERT_DER;
use tlsn_verifier::{Verifier, VerifierConfig};

use anyhow::Context;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};

pub async fn verifier_main(is_memory_profiling: bool) -> anyhow::Result<()> {
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
            if is_memory_profiling && !instance.memory_profile {
                continue;
            }

            let (io, _) = listener
                .accept()
                .await
                .context("failed to accept connection")?;
            run_instance(instance, io, is_memory_profiling)
                .await
                .context("failed to run instance")?;
        }
    }

    Ok(())
}

async fn run_instance<S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    instance: BenchInstance,
    io: S,
    is_memory_profiling: bool,
) -> anyhow::Result<()> {
    let BenchInstance {
        download,
        download_delay,
        upload_size,
        download_size,
        memory_profile,
        ..
    } = instance;

    set_interface(VERIFIER_INTERFACE, download, 1, download_delay)?;

    let _profiler = if is_memory_profiling {
        assert!(memory_profile, "Instance doesn't have `memory_profile` set");
        // Build a testing profiler as it won't output to stderr.
        Some(dhat::Profiler::builder().testing().build())
    } else {
        None
    };

    let provider = CryptoProvider {
        cert: cert_verifier(),
        ..Default::default()
    };

    let config_validator = ProtocolConfigValidator::builder()
        .max_sent_data(upload_size + 256)
        .max_recv_data(download_size + 256)
        .build()
        .unwrap();

    let verifier = Verifier::new(
        VerifierConfig::builder()
            .protocol_config_validator(config_validator)
            .crypto_provider(provider)
            .build()?,
    );

    verifier.verify(io.compat()).await?;

    println!("verifier done");

    if is_memory_profiling {
        // XXX: we may want to profile the Verifier's memory usage at a future
        // point.
        // println!(
        //     "verifier peak heap memory usage: {}",
        //     dhat::HeapStats::get().max_bytes
        // );
    }

    Ok(())
}

fn cert_verifier() -> WebPkiVerifier {
    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    WebPkiVerifier::new(root_store, None)
}
