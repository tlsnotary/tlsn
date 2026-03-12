use crate::types::VerifierMode;
use serde::Deserialize;
use tsify_next::Tsify;

#[derive(Debug, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct VerifierConfig {
    pub mode: Option<VerifierMode>,
    pub max_sent_data: usize,
    pub max_recv_data: usize,
    pub max_sent_records: Option<usize>,
    pub max_recv_records_online: Option<usize>,
}
