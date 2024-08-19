use tls_core::anchors::RootCertStore;
use tlsn_common::config::ProtocolConfig;
use tlsn_core::Direction;
use tlsn_prover::tls::{Prover, ProverConfig};
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};

use anyhow::Context;
use async_trait::async_trait;
use futures::{future::join, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::TokioAsyncReadCompatExt;

pub trait AsyncIo: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {}
impl<T> AsyncIo for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {}

#[async_trait]
pub trait ProverTrait {
    /// Sets up the prover preparing it to be run. Returns a prover ready to be run.
    async fn setup(
        upload_size: usize,
        download_size: usize,
        defer_decryption: bool,
        verifier_io: Box<dyn AsyncIo>,
        server_io: Box<dyn AsyncIo>,
    ) -> anyhow::Result<Self>
    where
        Self: Sized;

    /// Runs the prover. Returns the total run time in seconds.
    async fn run(&mut self) -> anyhow::Result<u64>;
}

pub async fn run_prover(
    upload_size: usize,
    download_size: usize,
    defer_decryption: bool,
    io: Box<dyn AsyncIo>,
    client_conn: Box<dyn AsyncIo>,
) -> anyhow::Result<()> {
    let protocol_config = ProtocolConfig::builder()
        .max_sent_data(upload_size + 256)
        .max_recv_data(download_size + 256)
        .build()
        .unwrap();

    let prover = Prover::new(
        ProverConfig::builder()
            .id("bench")
            .server_dns(SERVER_DOMAIN)
            .root_cert_store(root_store())
            .protocol_config(protocol_config)
            .build()
            .context("invalid prover config")?,
    )
    .setup(io.compat())
    .await?;

    let (mut mpc_tls_connection, prover_fut) = prover.connect(client_conn.compat()).await?;

    let prover_ctrl = prover_fut.control();

    let tls_fut = async move {
        let request = format!(
            "GET /bytes?size={} HTTP/1.1\r\nConnection: close\r\nData: {}\r\n\r\n",
            download_size,
            String::from_utf8(vec![0x42u8; upload_size]).unwrap(),
        );

        if defer_decryption {
            prover_ctrl.defer_decryption().await.unwrap();
        }

        mpc_tls_connection
            .write_all(request.as_bytes())
            .await
            .unwrap();
        mpc_tls_connection.close().await.unwrap();

        let mut response = vec![];
        mpc_tls_connection.read_to_end(&mut response).await.unwrap();
    };

    let (prover_task, _) = join(prover_fut, tls_fut).await;

    let mut prover = prover_task?.start_prove();

    prover.reveal(0..prover.sent_transcript().data().len(), Direction::Sent)?;
    prover.reveal(
        0..prover.recv_transcript().data().len(),
        Direction::Received,
    )?;
    prover.prove().await?;
    prover.finalize().await?;

    Ok(())
}

fn root_store() -> RootCertStore {
    let mut root_store = RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();
    root_store
}
