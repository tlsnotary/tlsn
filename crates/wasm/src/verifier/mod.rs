mod config;

pub use config::VerifierConfig;

use enum_try_as_inner::EnumTryAsInner;
use tlsn_verifier::{
    state::{self, Initialized},
    Verifier,
};
use tracing::info;
use wasm_bindgen::prelude::*;
use ws_stream_wasm::{WsMeta, WsStream};

use crate::types::VerifierOutput;

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
    fn take(&mut self) -> Self {
        std::mem::replace(self, State::Error)
    }
}

#[wasm_bindgen(js_class = Verifier)]
impl JsVerifier {
    #[wasm_bindgen(constructor)]
    pub fn new(config: VerifierConfig) -> JsVerifier {
        JsVerifier {
            state: State::Initialized(Verifier::new(config.into())),
        }
    }

    /// Connect to the prover.
    pub async fn connect(&mut self, prover_url: &str) -> Result<()> {
        let verifier = self.state.take().try_into_initialized()?;

        info!("Connecting to prover");

        let (_, prover_conn) = WsMeta::connect(prover_url, None).await?;

        info!("Connected to prover");

        self.state = State::Connected((verifier, prover_conn));

        Ok(())
    }

    /// Verifies the connection and finalizes the protocol.
    pub async fn verify(&mut self) -> Result<VerifierOutput> {
        let (verifier, prover_conn) = self.state.take().try_into_connected()?;

        let (transcript, info) = verifier.verify(prover_conn.into_io()).await?;

        self.state = State::Complete;

        Ok(VerifierOutput {
            server_name: info.server_name.as_str().to_string(),
            connection_info: info.connection_info.into(),
            transcript: transcript.into(),
        })
    }
}

impl From<tlsn_verifier::Verifier<Initialized>> for JsVerifier {
    fn from(value: tlsn_verifier::Verifier<Initialized>) -> Self {
        Self {
            state: State::Initialized(value),
        }
    }
}
