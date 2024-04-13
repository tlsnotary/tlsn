mod config;

pub use config::{Body, HttpRequest, HttpResponse, Method, ProverConfig, Redact};

use enum_try_as_inner::EnumTryAsInner;
use futures::TryFutureExt;
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Request};
use serde_wasm_bindgen::{from_value, to_value};
use tls_client_async::TlsConnection;
use tlsn_core::Direction;
use tlsn_prover::{
    http::NotarizedHttpSession,
    tls::{state, Prover},
};
use tracing::{debug, info};
use utils::range::{RangeDifference, RangeSet};
use wasm_bindgen::{prelude::*, JsError, JsValue};
use wasm_bindgen_futures::spawn_local;
use ws_stream_wasm::WsMeta;

use crate::io::FuturesIo;

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
    Closed(Prover<state::Closed>),
    Complete,
    Error,
}

impl State {
    pub fn take(&mut self) -> Self {
        std::mem::replace(self, State::Error)
    }
}

#[wasm_bindgen(js_class = Prover)]
impl JsProver {
    #[wasm_bindgen(constructor)]
    pub fn new(config: JsValue) -> Result<JsProver> {
        let config: ProverConfig = from_value(config)?;

        Ok(JsProver {
            state: State::Initialized(Prover::new(config.into())),
        })
    }

    /// Set up the prover.
    ///
    /// This performs all MPC setup prior to establishing the connection to the
    /// application server.
    #[wasm_bindgen]
    pub async fn setup(&mut self, verifier_url: &str) -> Result<()> {
        let prover = self.state.take().try_into_initialized()?;

        info!("Connecting to verifier");

        let (_, verifier_conn) = WsMeta::connect(verifier_url, None).await?;

        info!("Connected to verifier");

        let prover = prover.setup(verifier_conn.into_io()).await?;

        self.state = State::Setup(prover);

        Ok(())
    }

    /// Send the HTTP request to the server.
    #[wasm_bindgen]
    pub async fn send_request(&mut self, ws_proxy_url: &str, request: JsValue) -> Result<JsValue> {
        let prover = self.state.take().try_into_setup()?;

        let request: config::HttpRequest = from_value(request)?;

        let (_, server_conn) = WsMeta::connect(ws_proxy_url, None).await?;

        let (tls_conn, prover_fut) = prover.connect(server_conn.into_io()).await?;
        let prover_ctrl = prover_fut.control();

        info!("Sending request");

        let (response, prover) = futures::try_join!(
            async move {
                prover_ctrl.defer_decryption().await?;
                send_request(tls_conn, request).await
            },
            prover_fut.map_err(Into::into),
        )?;

        info!("Response received");

        self.state = State::Closed(prover);

        Ok(to_value(&response)?)
    }

    /// Reveals data to the verifier, redacting the specified substrings.
    #[wasm_bindgen]
    pub async fn reveal(&mut self, redact: JsValue) -> Result<()> {
        let mut prover = self.state.take().try_into_closed()?.start_prove();

        info!("Revealing data");

        let redact: Redact = from_value(redact)?;

        let reveal_sent = compute_ranges(
            prover.sent_transcript().data().as_ref(),
            redact.sent.as_slice(),
        );
        let reveal_received = compute_ranges(
            prover.recv_transcript().data().as_ref(),
            redact.received.as_slice(),
        );

        prover.reveal(reveal_sent, Direction::Sent)?;
        prover.reveal(reveal_received, Direction::Received)?;
        prover.prove().await?;

        prover.finalize().await?;

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
    let body = body.collect().await?;

    let headers = response
        .headers
        .into_iter()
        .map(|(k, v)| {
            (
                k.map(|k| k.to_string()).unwrap_or_default(),
                Bytes::copy_from_slice(v.as_bytes()),
            )
        })
        .collect();

    Ok(HttpResponse {
        status: response.status.as_u16(),
        headers,
        body: None,
    })
}

fn compute_ranges(data: &[u8], redact: &[Vec<u8>]) -> RangeSet<usize> {
    let mut ranges = RangeSet::from(0..data.len());
    for substring in redact {
        for pos in data
            .windows(substring.len())
            .enumerate()
            .filter_map(
                |(i, window)| {
                    if window == substring {
                        Some(i)
                    } else {
                        None
                    }
                },
            )
        {
            ranges = ranges.difference(&(pos..pos + substring.len()));
        }
    }
    ranges
}
