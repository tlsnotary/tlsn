//! Messages exchanged by the native and the wasm components of the browser prover.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq)]
/// The config sent to the wasm component.
pub struct Config {
    pub upload_size: usize,
    pub download_size: usize,
    pub defer_decryption: bool,
}

#[derive(Serialize, Deserialize, PartialEq)]
/// Sent by the wasm component when proving process is finished. Contains total runtime
/// in seconds.
pub struct Runtime(pub u64);
