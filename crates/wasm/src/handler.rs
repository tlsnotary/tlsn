//! WASM bindings for handler-based range extraction.
//!
//! Exposes [`compute_reveal`] to JavaScript, which parses HTTP transcripts
//! and maps plugin handlers to byte ranges for selective disclosure.

use wasm_bindgen::prelude::*;

/// Parses HTTP request/response transcripts and maps handlers to byte ranges.
///
/// This is the WASM wrapper around `tlsn_sdk_core::compute_reveal`.
///
/// # Arguments
///
/// * `sent` - Raw bytes of the HTTP request (sent data).
/// * `recv` - Raw bytes of the HTTP response (received data).
/// * `handlers` - Array of handler objects (deserialized from JS).
///
/// # Returns
///
/// A `ComputeRevealOutput` object containing:
/// - `sentRanges` / `recvRanges`: byte ranges for `Prover.reveal()`
/// - `sentRangesWithHandlers` / `recvRangesWithHandlers`: ranges annotated with handlers
#[wasm_bindgen(js_name = compute_reveal)]
pub fn compute_reveal(sent: &[u8], recv: &[u8], handlers: JsValue) -> Result<JsValue, JsError> {
    let handlers: Vec<tlsn_sdk_core::Handler> = serde_wasm_bindgen::from_value(handlers)
        .map_err(|e| JsError::new(&format!("failed to deserialize handlers: {e}")))?;

    let output = tlsn_sdk_core::compute_reveal(sent, recv, &handlers)
        .map_err(|e| JsError::new(&e.to_string()))?;

    serde_wasm_bindgen::to_value(&output).map_err(|e| JsError::new(&e.to_string()))
}
