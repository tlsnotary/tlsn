mod config;

pub use config::ProverConfig;

use enum_try_as_inner::EnumTryAsInner;
use futures::TryFutureExt;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use tlsn::{
    config::{
        prove::ProveConfig,
        tls::TlsClientConfig,
        tls_commit::{mpc::MpcTlsConfig, TlsCommitConfig},
    },
    connection::ServerName,
    prover::{state, Prover, TlsConnection},
    webpki::{CertificateDer, PrivateKeyDer, RootCertStore},
};
use tracing::info;
use wasm_bindgen::{prelude::*, JsError};
use wasm_bindgen_futures::spawn_local;
use ws_stream_wasm::WsMeta;

use crate::{io::FuturesIo, types::*};

type Result<T> = std::result::Result<T, JsError>;

#[wasm_bindgen(js_name = Prover)]
pub struct JsProver {
    config: ProverConfig,
    state: State,
}

#[derive(Debug, EnumTryAsInner)]
#[derive_err(Debug)]
enum State {
    Initialized(Prover<state::Initialized>),
    CommitAccepted(Prover<state::CommitAccepted>),
    Committed(Prover<state::Committed>),
    Complete,
    Error,
}

impl State {
    fn take(&mut self) -> Self {
        std::mem::replace(self, State::Error)
    }
}

#[wasm_bindgen(js_class = Prover)]
impl JsProver {
    #[wasm_bindgen(constructor)]
    pub fn new(config: ProverConfig) -> Result<JsProver> {
        Ok(JsProver {
            config,
            state: State::Initialized(Prover::new(
                tlsn::config::prover::ProverConfig::builder().build()?,
            )),
        })
    }

    /// Set up the prover.
    ///
    /// This performs all MPC setup prior to establishing the connection to the
    /// application server.
    pub async fn setup(&mut self, verifier_url: &str) -> Result<()> {
        let prover = self.state.take().try_into_initialized()?;

        let config = TlsCommitConfig::builder()
            .protocol({
                let mut builder = MpcTlsConfig::builder()
                    .max_sent_data(self.config.max_sent_data)
                    .max_recv_data(self.config.max_recv_data);

                if let Some(value) = self.config.max_recv_data_online {
                    builder = builder.max_recv_data_online(value);
                }

                if let Some(value) = self.config.max_sent_records {
                    builder = builder.max_sent_records(value);
                }

                if let Some(value) = self.config.max_recv_records_online {
                    builder = builder.max_recv_records_online(value);
                }

                if let Some(value) = self.config.defer_decryption_from_start {
                    builder = builder.defer_decryption_from_start(value);
                }

                builder.network(self.config.network.into()).build()
            }?)
            .build()?;

        info!("connecting to verifier");

        let (_, verifier_conn) = WsMeta::connect(verifier_url, None).await?;

        info!("connected to verifier");

        let prover = prover.commit(config, verifier_conn.into_io()).await?;

        self.state = State::CommitAccepted(prover);

        Ok(())
    }

    /// Send the HTTP request to the server.
    pub async fn send_request(
        &mut self,
        ws_proxy_url: &str,
        request: HttpRequest,
    ) -> Result<HttpResponse> {
        let prover = self.state.take().try_into_commit_accepted()?;

        let mut builder = TlsClientConfig::builder()
            .server_name(ServerName::Dns(
                self.config
                    .server_name
                    .clone()
                    .try_into()
                    .map_err(|_| JsError::new("invalid server name"))?,
            ))
            .root_store(RootCertStore::mozilla());

        if let Some((certs, key)) = self.config.client_auth.clone() {
            let certs = certs
                .into_iter()
                .map(|cert| {
                    // Try to parse as PEM-encoded, otherwise assume DER.
                    if let Ok(cert) = CertificateDer::from_pem_slice(&cert) {
                        cert
                    } else {
                        CertificateDer(cert)
                    }
                })
                .collect();
            let key = PrivateKeyDer(key);
            builder = builder.client_auth((certs, key));
        }

        let config = builder.build()?;

        info!("connecting to server");

        let (_, server_conn) = WsMeta::connect(ws_proxy_url, None).await?;

        info!("connected to server");

        let (tls_conn, prover_fut) = prover.connect_with(config, server_conn.into_io()).await?;

        info!("sending request");

        let (response, prover) = futures::try_join!(
            send_request(tls_conn, request),
            prover_fut.map_err(Into::into)
        )?;

        info!("response received");

        self.state = State::Committed(prover);

        Ok(response)
    }

    /// Returns the transcript.
    pub fn transcript(&self) -> Result<Transcript> {
        let prover = self.state.try_as_committed()?;

        Ok(Transcript::from(prover.transcript()))
    }

    /// Reveals data to the verifier and finalizes the protocol.
    pub async fn reveal(&mut self, reveal: Reveal) -> Result<()> {
        let mut prover = self.state.take().try_into_committed()?;

        info!("revealing data");

        let mut builder = ProveConfig::builder(prover.transcript());

        for range in reveal.sent {
            builder.reveal_sent(&range)?;
        }

        for range in reveal.recv {
            builder.reveal_recv(&range)?;
        }

        if reveal.server_identity {
            builder.server_identity();
        }

        let config = builder.build()?;

        prover.prove(&config).await?;
        prover.close().await?;

        info!("Finalized");

        self.state = State::Complete;

        Ok(())
    }
}

async fn send_request(conn: TlsConnection, request: HttpRequest) -> Result<HttpResponse> {
    let conn = FuturesIo::new(conn);
    let request = hyper::Request::<Full<Bytes>>::try_from(request)?;

    let (mut request_sender, conn) = hyper::client::conn::http1::handshake(conn).await?;

    spawn_local(async move { conn.await.expect("connection runs to completion") });

    let response = request_sender.send_request(request).await?;

    let (response, body) = response.into_parts();

    // TODO: return the body
    let _body = body.collect().await?;

    let headers = response
        .headers
        .into_iter()
        .map(|(k, v)| {
            (
                k.map(|k| k.to_string()).unwrap_or_default(),
                v.as_bytes().to_vec(),
            )
        })
        .collect();

    Ok(HttpResponse {
        status: response.status.as_u16(),
        headers,
    })
}
