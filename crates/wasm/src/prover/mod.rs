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
    Session, SessionHandle,
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

#[derive(EnumTryAsInner)]
#[derive_err(Debug)]
enum State {
    Initialized,
    CommitAccepted {
        prover: Prover<state::CommitAccepted>,
        handle: SessionHandle,
    },
    Committed {
        prover: Prover<state::Committed>,
        handle: SessionHandle,
    },
    Complete,
    Error,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            State::Initialized => write!(f, "Initialized"),
            State::CommitAccepted { .. } => write!(f, "CommitAccepted"),
            State::Committed { .. } => write!(f, "Committed"),
            State::Complete => write!(f, "Complete"),
            State::Error => write!(f, "Error"),
        }
    }
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
            state: State::Initialized,
        })
    }

    /// Set up the prover.
    ///
    /// This performs all MPC setup prior to establishing the connection to the
    /// application server.
    pub async fn setup(&mut self, verifier_url: &str) -> Result<()> {
        let State::Initialized = self.state.take() else {
            return Err(JsError::new("prover is not in initialized state"));
        };

        let tls_commit_config = TlsCommitConfig::builder()
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

        let session = Session::new(verifier_conn.into_io());
        let (driver, mut handle) = session.split();
        spawn_local(async move {
            if let Err(e) = driver.await {
                tracing::error!("session driver error: {e}");
            }
        });

        let prover_config = tlsn::config::prover::ProverConfig::builder().build()?;
        let prover = handle.new_prover(prover_config)?;

        let prover = prover
            .commit(tls_commit_config)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        self.state = State::CommitAccepted { prover, handle };

        Ok(())
    }

    /// Send the HTTP request to the server.
    pub async fn send_request(
        &mut self,
        ws_proxy_url: &str,
        request: HttpRequest,
    ) -> Result<HttpResponse> {
        let State::CommitAccepted { prover, handle } = self.state.take() else {
            return Err(JsError::new("prover is not in commit accepted state"));
        };

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

        let tls_config = builder.build()?;

        info!("connecting to server");

        let (_, server_conn) = WsMeta::connect(ws_proxy_url, None).await?;

        info!("connected to server");

        let (tls_conn, prover_fut) = prover
            .connect(tls_config, server_conn.into_io())
            .map_err(|e| JsError::new(&e.to_string()))?;

        info!("sending request");

        let (response, prover) = futures::try_join!(
            send_request(tls_conn, request),
            prover_fut.map_err(|e| JsError::new(&e.to_string()))
        )?;

        info!("response received");

        self.state = State::Committed { prover, handle };

        Ok(response)
    }

    /// Returns the transcript.
    pub fn transcript(&self) -> Result<Transcript> {
        let State::Committed { prover, .. } = &self.state else {
            return Err(JsError::new("prover is not in committed state"));
        };

        Ok(Transcript::from(prover.transcript()))
    }

    /// Reveals data to the verifier and finalizes the protocol.
    pub async fn reveal(&mut self, reveal: Reveal) -> Result<()> {
        let State::Committed { mut prover, handle } = self.state.take() else {
            return Err(JsError::new("prover is not in committed state"));
        };

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

        prover
            .prove(&config)
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;
        prover
            .close()
            .await
            .map_err(|e| JsError::new(&e.to_string()))?;

        handle.close();

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
