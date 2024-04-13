mod config;

use enum_try_as_inner::EnumTryAsInner;
use serde_wasm_bindgen::from_value;
use tlsn_prover::tls::{state, Prover, ProverConfig};
use wasm_bindgen::{JsError, JsValue};
use ws_stream_wasm::WsMeta;

use self::config::{HttpRequest, HttpResponse};

type Result<T> = std::result::Result<T, JsError>;

#[wasm_bindgen]
pub struct WasmProver {
    state: State,
}

#[derive(EnumTryAsInner)]
enum State {
    Initialized(Prover<state::Initialized>),
    Setup(Prover<state::Setup>),
    Error,
}

impl State {
    pub fn take(&mut self) -> Self {
        std::mem::replace(&mut self.0, State::Error)
    }
}

#[wasm_bindgen]
impl WasmProver {
    #[wasm_bindgen(constructor)]
    pub fn new(config: JsValue) -> Result<WasmProver> {
        let config: ProverConfig = from_value(config)?;

        Ok(WasmProver(State::Initialized(Prover::new(config))))
    }

    /// Set up the prover.
    ///
    /// This performs all MPC setup prior to establishing the connection to the
    /// application server.
    #[wasm_bindgen]
    pub async fn setup(&mut self, verifier_url: &str) -> Result<()> {
        let prover = self.state.take().try_into_initialized()?;

        let (_, verifier_conn) = WsMeta::connect(verifier_url, None).await?;

        let prover = prover.setup(verifier_conn).await?;

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

        let (response, prover) = futures::try_join! {
            request(tls_conn, request),
            prover_fut,
        }?;

        let response = prover.send_request(request).await?;

        Ok(JsValue::from_serde(&response).unwrap())
    }
}

async fn request(conn: TlsConnection, req: HttpRequest) -> Result<HttpResponse> {
    todo!()
}
