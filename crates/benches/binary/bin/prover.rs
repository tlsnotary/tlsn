use std::{
    fs::metadata,
    io::Write,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use tlsn_benches::{
    config::{BenchInstance, Config},
    metrics::Metrics,
    set_interface, PROVER_INTERFACE,
};
use tlsn_benches_library::{AsyncIo, ProverTrait};
use tlsn_server_fixture::bind;

use anyhow::Context;
use csv::WriterBuilder;
use tokio_util::{
    compat::TokioAsyncReadCompatExt,
    io::{InspectReader, InspectWriter},
};
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};

#[cfg(not(feature = "browser-bench"))]
use tlsn_benches::prover::NativeProver as BenchProver;
#[cfg(feature = "browser-bench")]
use tlsn_benches_browser_native::BrowserProver as BenchProver;

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
    let verifier_host = (ip.as_str(), port);

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("metrics.csv")
        .context("failed to open metrics file")?;

    {
        let mut metric_wtr = WriterBuilder::new()
            // If file is not empty, assume that the CSV header is already present in the file.
            .has_headers(metadata("metrics.csv")?.len() == 0)
            .from_writer(&mut file);
        for bench in config.benches {
            let instances = bench.flatten();
            for instance in instances {
                println!("{:?}", &instance);

                let io = tokio::net::TcpStream::connect(verifier_host)
                    .await
                    .context("failed to open tcp connection")?;
                metric_wtr.serialize(
                    run_instance(instance, io)
                        .await
                        .context("failed to run instance")?,
                )?;
                metric_wtr.flush()?;
            }
        }
    }

    file.flush()?;

    Ok(())
}

async fn run_instance(instance: BenchInstance, io: impl AsyncIo) -> anyhow::Result<Metrics> {
    let uploaded = Arc::new(AtomicU64::new(0));
    let downloaded = Arc::new(AtomicU64::new(0));
    let io = InspectWriter::new(
        InspectReader::new(io, {
            let downloaded = downloaded.clone();
            move |data| {
                downloaded.fetch_add(data.len() as u64, Ordering::Relaxed);
            }
        }),
        {
            let uploaded = uploaded.clone();
            move |data| {
                uploaded.fetch_add(data.len() as u64, Ordering::Relaxed);
            }
        },
    );

    let BenchInstance {
        name,
        upload,
        upload_delay,
        download,
        download_delay,
        upload_size,
        download_size,
        defer_decryption,
    } = instance.clone();

    set_interface(PROVER_INTERFACE, upload, 1, upload_delay)?;

    let (client_conn, server_conn) = tokio::io::duplex(1 << 16);
    tokio::spawn(bind(server_conn.compat()));

    let mut prover = BenchProver::setup(
        upload_size,
        download_size,
        defer_decryption,
        Box::new(io),
        Box::new(client_conn),
    )
    .await?;

    let runtime = prover.run().await?;

    Ok(Metrics {
        name,
        kind: prover.kind(),
        upload,
        upload_delay,
        download,
        download_delay,
        upload_size,
        download_size,
        defer_decryption,
        runtime,
        uploaded: uploaded.load(Ordering::SeqCst),
        downloaded: downloaded.load(Ordering::SeqCst),
    })
}
