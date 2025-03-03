use std::sync::atomic::Ordering;

use anyhow::Result;
use futures::{AsyncReadExt, AsyncWriteExt, FutureExt, TryFutureExt};
use futures_limit::*;
use tls_core::verify::WebPkiVerifier;
use tlsn_common::config::ProtocolConfig;
use tlsn_core::{transcript::Idx, CryptoProvider};
use tlsn_prover::{Prover, ProverConfig};
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};

use crate::{
    bench::{burst, BenchConfig, Meter, Metrics, PADDING},
    spawn::spawn,
    ProverProvider,
};

pub async fn bench_prover(provider: &mut ProverProvider, config: &BenchConfig) -> Result<Metrics> {
    let write_rate = config.upload * 1_000_000;
    let write_burst = burst(write_rate);

    let (verifier_io, delay_fut) = provider
        .provide_verifier()
        .await?
        .limit_rate(write_burst, write_rate)
        .delay(config.latency.div_ceil(2));

    let verifier_io = Meter::new(verifier_io);

    let sent = verifier_io.sent();
    let recv = verifier_io.recv();

    spawn(delay_fut.map(|_| ()));

    let mut builder = ProtocolConfig::builder();
    builder.max_sent_data(config.upload_size + PADDING);

    if !config.defer_decryption {
        builder.max_recv_data_online(config.download_size + PADDING);
    }
    builder.max_recv_data(config.download_size + PADDING);

    let protocol_config = builder.build()?;

    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    let crypto_provider = CryptoProvider {
        cert: WebPkiVerifier::new(root_store, None),
        ..Default::default()
    };

    let prover = Prover::new(
        ProverConfig::builder()
            .defer_decryption_from_start(config.defer_decryption)
            .protocol_config(protocol_config)
            .server_name(SERVER_DOMAIN)
            .crypto_provider(crypto_provider)
            .build()?,
    );

    let time_start = web_time::Instant::now();

    let prover = prover.setup(verifier_io).await?;

    let time_preprocess = time_start.elapsed().as_millis();
    let time_start_online = web_time::Instant::now();

    let (mut conn, prover_fut) = prover.connect(provider.provide_server().await?).await?;

    let (time_online, prover) = futures::try_join!(
        async {
            let request = format!(
                "GET /bytes?size={} HTTP/1.1\r\nConnection: close\r\nData: {}\r\n\r\n",
                config.download_size,
                String::from_utf8(vec![0x42u8; config.upload_size])?,
            );

            conn.write_all(request.as_bytes()).await?;
            conn.close().await?;

            let mut response = Vec::new();
            conn.read_to_end(&mut response).await?;

            let time_online = time_start_online.elapsed().as_millis();

            Ok(time_online)
        },
        prover_fut.map_err(anyhow::Error::from)
    )?;

    let mut prover = prover.start_prove();

    let (sent_len, recv_len) = prover.transcript().len();

    prover
        .prove_transcript(Idx::new(0..sent_len), Idx::new(0..recv_len))
        .await?;
    prover.finalize().await?;

    let time_total = time_start.elapsed().as_millis();

    Ok(Metrics {
        time_preprocess: time_preprocess as u64,
        time_online: time_online as u64,
        time_total: time_total as u64,
        uploaded: sent.load(Ordering::Relaxed),
        downloaded: recv.load(Ordering::Relaxed),
        heap_max_bytes: None,
    })
}
