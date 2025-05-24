use tls_core::{anchors::RootCertStore, verify::WebPkiVerifier};
use tlsn_common::config::ProtocolConfig;
use tlsn_core::{CryptoProvider, ProveConfig};
use tlsn_prover::{Prover, ProverConfig};
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_DOMAIN};

use anyhow::Context;
use async_trait::async_trait;
use futures::{future::try_join, AsyncReadExt as _, AsyncWriteExt as _, TryFutureExt};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::TokioAsyncReadCompatExt;

pub trait AsyncIo: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {}
impl<T> AsyncIo for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static {}

#[async_trait]
pub trait ProverTrait {
    /// Sets up the prover preparing it to be run. Returns a prover ready to be
    /// run.
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

    /// Returns the kind of the prover.
    fn kind(&self) -> ProverKind;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The kind of a prover.
pub enum ProverKind {
    /// The prover compiled into a native binary.
    Native,
    /// The prover compiled into a wasm binary.
    Browser,
}

impl From<ProverKind> for String {
    fn from(value: ProverKind) -> Self {
        match value {
            ProverKind::Native => "Native".to_string(),
            ProverKind::Browser => "Browser".to_string(),
        }
    }
}

pub async fn run_prover(
    upload_size: usize,
    download_size: usize,
    defer_decryption: bool,
    io: Box<dyn AsyncIo>,
    client_conn: Box<dyn AsyncIo>,
) -> anyhow::Result<()> {
    let provider = CryptoProvider {
        cert: WebPkiVerifier::new(root_store(), None),
        ..Default::default()
    };

    let mut protocol_config = ProtocolConfig::builder();
    if defer_decryption {
        protocol_config
            .max_sent_data(upload_size + 256)
            .max_recv_data(download_size + 256)
    } else {
        protocol_config
            .max_sent_data(upload_size + 256)
            .max_recv_data(download_size + 256)
            .max_recv_data_online(download_size + 256)
    };
    let protocol_config = protocol_config
        .defer_decryption_from_start(defer_decryption)
        .build()
        .unwrap();

    let prover = Prover::new(
        ProverConfig::builder()
            .server_name(SERVER_DOMAIN)
            .protocol_config(protocol_config)
            .crypto_provider(provider)
            .build()
            .context("invalid prover config")?,
    )
    .setup(io.compat())
    .await?;

    let (mut mpc_tls_connection, prover_fut) = prover.connect(client_conn.compat()).await?;
    let tls_fut = async move {
        let request = format!(
            "GET /bytes?size={} HTTP/1.1\r\nConnection: close\r\nData: {}\r\n\r\n",
            download_size,
            String::from_utf8(vec![0x42u8; upload_size]).unwrap(),
        );

        mpc_tls_connection.write_all(request.as_bytes()).await?;
        mpc_tls_connection.close().await?;

        let mut response = vec![];
        mpc_tls_connection.read_to_end(&mut response).await?;

        dbg!(response.len());

        Ok::<(), anyhow::Error>(())
    };

    let (mut prover, _) = try_join(prover_fut.map_err(anyhow::Error::from), tls_fut).await?;

    let (sent_len, recv_len) = prover.transcript().len();

    let mut builder = ProveConfig::builder(prover.transcript());

    builder.reveal_sent(&(0..sent_len)).unwrap();
    builder.reveal_recv(&(0..recv_len)).unwrap();

    let config = builder.build().unwrap();

    prover.prove(&config).await?;
    prover.close().await?;

    Ok(())
}

fn root_store() -> RootCertStore {
    let mut root_store = RootCertStore::empty();
    root_store
        .add(&tls_core::key::Certificate(CA_CERT_DER.to_vec()))
        .unwrap();
    root_store
}
