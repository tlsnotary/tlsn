use std::{
    io::Write,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};

use anyhow::Context;
use futures::{AsyncReadExt, AsyncWriteExt};
use tlsn_benches::{
    config::{BenchInstance, Config},
    metrics::Metrics,
    set_interface, PROVER_INTERFACE,
};

use tlsn_core::Direction;
use tlsn_server_fixture::{CA_CERT_DER, SERVER_DOMAIN};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::{
    compat::TokioAsyncReadCompatExt,
    io::{InspectReader, InspectWriter},
};

use tlsn_prover::tls::{Prover, ProverConfig};
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
    let verifier_host = (ip.as_str(), port);

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("metrics.csv")
        .context("failed to open metrics file")?;

    {
        let mut metric_wtr = csv::Writer::from_writer(&mut file);
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

async fn run_instance<S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    instance: BenchInstance,
    io: S,
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
    } = instance.clone();

    set_interface(PROVER_INTERFACE, upload, 1, upload_delay)?;

    let (client_conn, server_conn) = tokio::io::duplex(2 << 16);
    tokio::spawn(tlsn_server_fixture::bind(server_conn.compat()));

    let start_time = Instant::now();

    let prover = Prover::new(
        ProverConfig::builder()
            .id("test")
            .server_dns(SERVER_DOMAIN)
            .root_cert_store(root_store())
            .max_sent_data(upload_size + 256)
            .max_recv_data(download_size + 256)
            .build()
            .context("invalid prover config")?,
    )
    .setup(io.compat())
    .await?;

    let (mut mpc_tls_connection, prover_fut) = prover.connect(client_conn.compat()).await.unwrap();

    let prover_ctrl = prover_fut.control();
    let prover_task = tokio::spawn(prover_fut);

    let request = format!(
        "GET /bytes?size={} HTTP/1.1\r\nConnection: close\r\nData: {}\r\n\r\n",
        download_size,
        String::from_utf8(vec![0x42u8; upload_size]).unwrap(),
    );

    if defer_decryption {
        prover_ctrl.defer_decryption().await?;
    }

    mpc_tls_connection.write_all(request.as_bytes()).await?;
    mpc_tls_connection.close().await?;

    let mut response = vec![];
    mpc_tls_connection.read_to_end(&mut response).await?;

    let mut prover = prover_task.await??.start_prove();

    prover.reveal(0..prover.sent_transcript().data().len(), Direction::Sent)?;
    prover.reveal(
        0..prover.recv_transcript().data().len(),
        Direction::Received,
    )?;
    prover.prove().await?;
    prover.finalize().await?;

    Ok(Metrics {
        name,
        upload,
        upload_delay,
        download,
        download_delay,
        upload_size,
        download_size,
        defer_decryption,
        runtime: Instant::now().duration_since(start_time).as_secs(),
        uploaded: uploaded.load(Ordering::SeqCst),
        downloaded: downloaded.load(Ordering::SeqCst),
    })
}

fn root_store() -> tls_core::anchors::RootCertStore {
    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();
    root_store
}
