//! WASM session bindings.

use serde::Deserialize;
use tsify::Tsify;

/// Options for the mux session shared by the prover and verifier.
#[derive(Debug, Default, Tsify, Deserialize)]
pub struct SessionOptions {
    /// Maximum number of concurrent mux streams per session.
    ///
    /// Defaults to 512 when unset. The session receive window (1 GiB) caps this
    /// at 4096.
    pub max_num_streams: Option<usize>,
}
