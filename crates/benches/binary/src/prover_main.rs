//! Contains the actual main() function of the prover binary. It is moved here
//! in order to enable cargo to build two prover binaries - with and without
//! memory profiling.

use std::{
    fs::metadata,
    io::Write,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use crate::{
    config::{BenchInstance, Config},
    metrics::Metrics,
    preprocess::preprocess_prf_circuits,
    set_interface, PROVER_INTERFACE,
};
use anyhow::Context;
use tlsn_benches_library::{AsyncIo, ProverTrait};
use tlsn_server_fixture::bind;

use csv::WriterBuilder;

use tokio_util::{
    compat::TokioAsyncReadCompatExt,
    io::{InspectReader, InspectWriter},
};
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};

#[cfg(not(feature = "browser-bench"))]
use crate::prover::NativeProver as BenchProver;
#[cfg(feature = "browser-bench")]
use tlsn_benches_browser_native::BrowserProver as BenchProver;

pub async fn prover_main(is_memory_profiling: bool) -> anyhow::Result<()> {
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

    // Preprocess the PRF circuits as they are allocating a lot of memory, which
    // don't need to be accounted for in the benchmarks.
    preprocess_prf_circuits().await;

    {
        let mut metric_wrt = WriterBuilder::new()
            // If file is not empty, assume that the CSV header is already present in the file.
            .has_headers(metadata("metrics.csv")?.len() == 0)
            .from_writer(&mut file);
        for bench in config.benches {
            let instances = bench.flatten();
            for instance in instances {
                if is_memory_profiling && !instance.memory_profile {
                    continue;
                }

                println!("{:?}", &instance);

                let io = tokio::net::TcpStream::connect(verifier_host)
                    .await
                    .context("failed to open tcp connection")?;
                metric_wrt.serialize(
                    run_instance(instance, io, is_memory_profiling)
                        .await
                        .context("failed to run instance")?,
                )?;
                metric_wrt.flush()?;
            }
        }
    }

    file.flush()?;

    Ok(())
}

async fn run_instance(
    instance: BenchInstance,
    io: impl AsyncIo,
    is_memory_profiling: bool,
) -> anyhow::Result<Metrics> {
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
        memory_profile,
    } = instance.clone();

    set_interface(PROVER_INTERFACE, upload, 1, upload_delay)?;

    let _profiler = if is_memory_profiling {
        assert!(memory_profile, "Instance doesn't have `memory_profile` set");
        // Build a testing profiler as it won't output to stderr.
        Some(dhat::Profiler::builder().testing().build())
    } else {
        None
    };

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

    let heap_max_bytes = if is_memory_profiling {
        Some(dhat::HeapStats::get().max_bytes)
    } else {
        None
    };

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
        heap_max_bytes,
    })
}
