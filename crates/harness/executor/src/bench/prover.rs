use std::sync::atomic::Ordering;

use anyhow::Result;
use futures::{AsyncReadExt, AsyncWriteExt, TryFutureExt};

use harness_core::bench::{Bench, ProverMetrics};
use tls_core::verify::WebPkiVerifier;
use tlsn_common::config::ProtocolConfig;
use tlsn_core::{CryptoProvider, ProveConfig};
use tlsn_prover::{Prover, ProverConfig};
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};

use crate::{
    IoProvider,
    bench::{Meter, RECV_PADDING},
};

pub async fn bench_prover(provider: &IoProvider, config: &Bench) -> Result<ProverMetrics> {
    let verifier_io = Meter::new(provider.provide_proto_io().await?);

    let sent = verifier_io.sent();
    let recv = verifier_io.recv();

    let mut builder = ProtocolConfig::builder();
    builder.max_sent_data(config.upload_size);

    builder.defer_decryption_from_start(config.defer_decryption);
    if !config.defer_decryption {
        builder.max_recv_data_online(config.download_size + RECV_PADDING);
    }
    builder.max_recv_data(config.download_size + RECV_PADDING);

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
            .protocol_config(protocol_config)
            .server_name(SERVER_DOMAIN)
            .crypto_provider(crypto_provider)
            .build()?,
    );

    let time_start = web_time::Instant::now();

    let prover = prover.setup(verifier_io).await?;

    let time_preprocess = time_start.elapsed().as_millis();
    let time_start_online = web_time::Instant::now();
    let uploaded_preprocess = sent.load(Ordering::Relaxed);
    let downloaded_preprocess = recv.load(Ordering::Relaxed);

    let (mut conn, prover_fut) = prover.connect(provider.provide_server_io().await?).await?;

    let (_, mut prover) = futures::try_join!(
        async {
            let request = format!(
                "GET /bytes?size={} HTTP/1.1\r\nConnection: close\r\nData: {}\r\n\r\n",
                config.download_size,
                // Subtract the 68 bytes already present in the request template.
                String::from_utf8(vec![0x42u8; config.upload_size.saturating_sub(68)])?,
            );

            conn.write_all(request.as_bytes()).await?;
            conn.close().await?;

            let mut response = Vec::new();
            conn.read_to_end(&mut response).await?;

            Ok(())
        },
        prover_fut.map_err(anyhow::Error::from)
    )?;

    let time_online = time_start_online.elapsed().as_millis();
    let uploaded_online = sent.load(Ordering::Relaxed) - uploaded_preprocess;
    let downloaded_online = recv.load(Ordering::Relaxed) - downloaded_preprocess;

    let (sent_len, recv_len) = prover.transcript().len();

    let mut builder = ProveConfig::builder(prover.transcript());

    builder
        .server_identity()
        .reveal_sent(&(0..sent_len))?
        .reveal_recv(&(0..recv_len))?;

    let config = builder.build()?;

    prover.prove(&config).await?;
    prover.close().await?;

    let time_total = time_start.elapsed().as_millis();

    Ok(ProverMetrics {
        time_preprocess: time_preprocess as u64,
        time_online: time_online as u64,
        time_total: time_total as u64,
        uploaded_preprocess,
        downloaded_preprocess,
        uploaded_online,
        downloaded_online,
        uploaded_total: sent.load(Ordering::Relaxed),
        downloaded_total: recv.load(Ordering::Relaxed),
        heap_max_bytes: None,
    })
}
