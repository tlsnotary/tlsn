pub use tlsn_wasm::*;

use gloo_utils::format::JsValueSerdeExt;
use wasm_bindgen::prelude::*;

use crate::{
    bench::{bench_prover, BrowserBenchConfig},
    provider::{ProverProvider, VerifierAddr, VerifierProvider},
    test::{get_test, BrowserTestConfig},
};

extern "C" {
    fn __wasm_call_ctors();
}

#[wasm_bindgen(start)]
pub fn main() {
    unsafe { __wasm_call_ctors() };
}

#[wasm_bindgen(js_name = "runTestProver")]
pub async fn run_test_prover(config: JsValue) -> Result<(), JsError> {
    let config: BrowserTestConfig = config.into_serde()?;

    let test = get_test(&config.test.name).unwrap();

    let mut provider = ProverProvider::new(
        config.proxy_addr.clone(),
        config.server_addr.clone(),
        VerifierAddr::Ws {
            id: config.test.name,
        },
    );

    (test.prover)(&mut provider).await;

    Ok(())
}

#[wasm_bindgen(js_name = "runTestVerifier")]
pub async fn run_test_verifier(config: JsValue) -> Result<(), JsError> {
    let config: BrowserTestConfig = config.into_serde()?;

    let test = get_test(&config.test.name).unwrap();

    let mut provider = VerifierProvider::new(config.proxy_addr.clone(), &config.test.name);

    (test.verifier)(&mut provider).await;

    Ok(())
}

#[wasm_bindgen(js_name = "runBench")]
pub async fn run_bench(config: JsValue) -> Result<JsValue, JsError> {
    let config: BrowserBenchConfig = config.into_serde()?;

    let mut provider = ProverProvider::new(
        config.proxy_addr.clone(),
        config.server_addr.clone(),
        VerifierAddr::Tcp {
            addr: config.verifier_addr,
        },
    );

    let metrics = bench_prover(&mut provider, &config.bench)
        .await
        .map_err(|e| JsError::new(&e.to_string()))?;

    Ok(JsValue::from_serde(&metrics)?)
}
