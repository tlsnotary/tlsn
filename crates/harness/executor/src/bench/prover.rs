use std::sync::atomic::Ordering;

use anyhow::Result;
use futures::{AsyncReadExt, AsyncWriteExt, TryFutureExt};

use harness_core::bench::{Bench, ProverMetrics};
use tlsn::{
    Session,
    config::{
        prove::ProveConfig,
        prover::ProverConfig,
        tls::TlsClientConfig,
        tls_commit::{TlsCommitConfig, mpc::MpcTlsConfig},
    },
    connection::ServerName,
    webpki::{CertificateDer, RootCertStore},
};
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};

use crate::{
    IoProvider,
    bench::{Meter, RECV_PADDING},
    spawn,
};

pub async fn bench_prover(provider: &IoProvider, config: &Bench) -> Result<ProverMetrics> {
    let verifier_io = Meter::new(provider.provide_proto_io().await?);

    let sent = verifier_io.sent();
    let recv = verifier_io.recv();

    let mut session = Session::new(verifier_io);

    let prover = session.new_prover(ProverConfig::builder().build()?)?;
    let (session, handle) = session.split();

    _ = spawn(session);

    let time_start = web_time::Instant::now();

    let prover = prover
        .commit(
            TlsCommitConfig::builder()
                .protocol({
                    let mut builder = MpcTlsConfig::builder()
                        .max_sent_data(config.upload_size)
                        .defer_decryption_from_start(config.defer_decryption);

                    if !config.defer_decryption {
                        builder = builder.max_recv_data_online(config.download_size + RECV_PADDING);
                    }

                    builder
                        .max_recv_data(config.download_size + RECV_PADDING)
                        .build()
                }?)
                .build()?,
        )
        .await?;

    let time_preprocess = time_start.elapsed().as_millis();
    let time_start_online = web_time::Instant::now();
    let uploaded_preprocess = sent.load(Ordering::Relaxed);
    let downloaded_preprocess = recv.load(Ordering::Relaxed);

    let (mut conn, prover_fut) = prover.connect(
        TlsClientConfig::builder()
            .server_name(ServerName::Dns(SERVER_DOMAIN.try_into()?))
            .root_store(RootCertStore {
                roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
            })
            .build()?,
        provider.provide_server_io().await?,
    )?;

    let (_, mut prover) = futures::try_join!(
        async {
            let request = format!(
                "GET /bytes?size={} HTTP/1.1\r\nConnection: close\r\nData: {}\r\n\r\n",
                config.download_size,
                // Subtract the 68 bytes already present in the request template.
                String::from_utf8(vec![0x42u8; config.upload_size.saturating_sub(68)])?,
            );

            conn.write_all(request.as_bytes()).await?;

            let mut response = Vec::new();
            conn.read_to_end(&mut response).await?;
            conn.close().await?;

            Ok(())
        },
        prover_fut.map_err(anyhow::Error::from)
    )?;

    let time_online = time_start_online.elapsed().as_millis();
    let uploaded_online = sent.load(Ordering::Relaxed) - uploaded_preprocess;
    let downloaded_online = recv.load(Ordering::Relaxed) - downloaded_preprocess;

    let (sent_len, recv_len) = prover.transcript().len();

    let mut builder = ProveConfig::builder(prover.transcript());

    // When reveal_all is false (the default), we exclude 1 byte to avoid the
    // reveal-all optimization and benchmark the realistic ZK authentication path.
    let reveal_sent_range = if config.reveal_all {
        0..sent_len
    } else {
        0..sent_len.saturating_sub(1)
    };
    let reveal_recv_range = if config.reveal_all {
        0..recv_len
    } else {
        0..recv_len.saturating_sub(1)
    };

    builder
        .server_identity()
        .reveal_sent(&reveal_sent_range)?
        .reveal_recv(&reveal_recv_range)?;

    let prove_config = builder.build()?;

    prover.prove(&prove_config).await?;
    prover.close().await?;
    handle.close();

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
