use std::sync::atomic::Ordering;

use anyhow::Result;
use futures::FutureExt;
use futures_limit::*;
use tls_core::verify::WebPkiVerifier;
use tlsn_common::config::ProtocolConfigValidator;
use tlsn_core::CryptoProvider;
use tlsn_server_fixture_certs::CA_CERT_DER;
use tlsn_verifier::{Verifier, VerifierConfig};

use crate::{
    bench::{burst, BenchConfig, Meter, Metrics, PADDING},
    spawn::spawn,
    VerifierProvider,
};

pub async fn bench_verifier(
    provider: &mut VerifierProvider,
    config: &BenchConfig,
) -> Result<Metrics> {
    let write_rate = config.download * 1_000_000;
    let write_burst = burst(write_rate);

    let (io, delay_fut) = provider
        .provide_prover()
        .await?
        .limit_rate(write_burst, write_rate)
        .delay(config.latency.div_ceil(2));

    let io = Meter::new(io);

    let sent = io.sent();
    let recv = io.recv();

    spawn(delay_fut.map(|_| ()));

    let mut builder = ProtocolConfigValidator::builder();
    builder
        .max_sent_data(config.upload_size + PADDING)
        .max_recv_data(config.download_size + PADDING);

    let protocol_config = builder.build()?;

    let mut root_store = tls_core::anchors::RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();

    let crypto_provider = CryptoProvider {
        cert: WebPkiVerifier::new(root_store, None),
        ..Default::default()
    };

    let verifier = Verifier::new(
        VerifierConfig::builder()
            .protocol_config_validator(protocol_config)
            .crypto_provider(crypto_provider)
            .build()?,
    );

    let time_start = web_time::Instant::now();

    let verifier = verifier.setup(io).await?;

    let time_preprocess = time_start.elapsed().as_secs();
    let time_start_online = web_time::Instant::now();

    let mut verifier = verifier.run().await?.start_verify();

    let time_online = time_start_online.elapsed().as_secs();

    verifier.receive().await?;
    verifier.finalize().await?;

    let time_total = time_start.elapsed().as_secs();

    Ok(Metrics {
        time_preprocess,
        time_online,
        time_total,
        uploaded: sent.load(Ordering::Relaxed),
        downloaded: recv.load(Ordering::Relaxed),
        heap_max_bytes: None,
    })
}
