mod config;

pub use config::VerifierConfig;

use enum_try_as_inner::EnumTryAsInner;
use serde_wasm_bindgen::{from_value, to_value};
use tlsn_verifier::tls::{state, Verifier};
use tracing::{debug, info};
use wasm_bindgen::{prelude::*, JsValue};
use ws_stream_wasm::{WsMeta, WsStream};

use crate::verifier::{self, config::VerifierData};

type Result<T> = std::result::Result<T, JsError>;

#[wasm_bindgen(js_name = Verifier)]
pub struct JsVerifier {
    state: State,
}

#[derive(EnumTryAsInner)]
#[derive_err(Debug)]
enum State {
    Initialized(Verifier<state::Initialized>),
    Connected((Verifier<state::Initialized>, WsStream)),
    Complete,
    Error,
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "State")
    }
}

impl State {
    pub fn take(&mut self) -> Self {
        std::mem::replace(self, State::Error)
    }
}

#[wasm_bindgen(js_class = Verifier)]
impl JsVerifier {
    #[wasm_bindgen(constructor)]
    pub fn new(config: JsValue) -> Result<JsVerifier> {
        let config: VerifierConfig = from_value(config)?;

        Ok(JsVerifier {
            state: State::Initialized(Verifier::new(config.into())),
        })
    }

    pub async fn connect(&mut self, prover_url: &str) -> Result<()> {
        let verifier = self.state.take().try_into_initialized()?;

        info!("Connecting to prover");

        let (_, prover_conn) = WsMeta::connect(prover_url, None).await?;

        info!("Connected to prover");
        web_sys::console::log_1(&"Connected to prover".into());

        self.state = State::Connected((verifier, prover_conn));

        Ok(())
    }

    #[wasm_bindgen]
    pub async fn verify(&mut self) -> Result<JsValue> {
        let (verifier, prover_conn) = self.state.take().try_into_connected()?;

        let (sent, recv, info) = verifier.verify(prover_conn.into_io()).await?;

        Ok(to_value(&VerifierData {
            server_dns: info.server_name.as_str().to_string(),
            sent: sent.data().to_vec(),
            sent_auth_ranges: sent
                .authed()
                .iter_ranges()
                .map(|r| [r.start as u64, r.end as u64])
                .collect(),
            received: recv.data().to_vec(),
            received_auth_ranges: recv
                .authed()
                .iter_ranges()
                .map(|r| [r.start as u64, r.end as u64])
                .collect(),
        })?)
    }
}
