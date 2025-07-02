mod config;

pub use config::ProverConfig;

use enum_try_as_inner::EnumTryAsInner;
use futures::TryFutureExt;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use tls_client_async::TlsConnection;
use tlsn::prover::{state, ProveConfig, Prover};
use tlsn_core::{request::RequestConfig, transcript::TranscriptCommitConfigBuilder};
use tracing::info;
use wasm_bindgen::{prelude::*, JsError};
use wasm_bindgen_futures::spawn_local;
use ws_stream_wasm::WsMeta;

use crate::{io::FuturesIo, types::*};

type Result<T> = std::result::Result<T, JsError>;

#[wasm_bindgen(js_name = Prover)]
pub struct JsProver {
    state: State,
}

#[derive(Debug, EnumTryAsInner)]
#[derive_err(Debug)]
enum State {
    Initialized(Prover<state::Initialized>),
    Setup(Prover<state::Setup>),
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
    pub fn new(config: ProverConfig) -> JsProver {
        JsProver {
            state: State::Initialized(Prover::new(config.into())),
        }
    }

    /// Set up the prover.
    ///
    /// This performs all MPC setup prior to establishing the connection to the
    /// application server.
    pub async fn setup(&mut self, verifier_url: &str) -> Result<()> {
        let prover = self.state.take().try_into_initialized()?;

        info!("connecting to verifier");

        let (_, verifier_conn) = WsMeta::connect(verifier_url, None).await?;

        info!("connected to verifier");

        let prover = prover.setup(verifier_conn.into_io()).await?;

        self.state = State::Setup(prover);

        Ok(())
    }

    /// Send the HTTP request to the server.
    pub async fn send_request(
        &mut self,
        ws_proxy_url: &str,
        request: HttpRequest,
    ) -> Result<HttpResponse> {
        let prover = self.state.take().try_into_setup()?;

        info!("connecting to server");

        let (_, server_conn) = WsMeta::connect(ws_proxy_url, None).await?;

        info!("connected to server");

        let (tls_conn, prover_fut) = prover.connect(server_conn.into_io()).await?;

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

    /// Runs the notarization protocol.
    pub async fn notarize(&mut self, commit: Commit) -> Result<NotarizationOutput> {
        let mut prover = self.state.take().try_into_committed()?;

        info!("starting notarization");

        let mut builder = TranscriptCommitConfigBuilder::new(prover.transcript());

        for range in commit.sent {
            builder.commit_sent(&range)?;
        }

        for range in commit.recv {
            builder.commit_recv(&range)?;
        }

        let transcript_commit = builder.build()?;

        let mut builder = RequestConfig::builder();

        builder.transcript_commit(transcript_commit);

        let request_config = builder.build()?;

        #[allow(deprecated)]
        let (attestation, secrets) = prover.notarize(&request_config).await?;
        prover.close().await?;

        info!("notarization complete");

        self.state = State::Complete;

        Ok(NotarizationOutput {
            attestation: attestation.into(),
            secrets: secrets.into(),
        })
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

impl From<Prover<state::Initialized>> for JsProver {
    fn from(value: Prover<state::Initialized>) -> Self {
        JsProver {
            state: State::Initialized(value),
        }
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
