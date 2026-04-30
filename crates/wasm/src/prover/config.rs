use crate::types::NetworkSetting;
use serde::Deserialize;
use tsify_next::Tsify;

/// Protocol mode for the prover.
#[derive(Debug, Clone, Copy, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
pub enum ProverMode {
    /// MPC (Multi-Party Computation) mode.
    Mpc,
    /// Proxy mode.
    Proxy,
}

#[derive(Debug, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct ProverConfig {
    pub server_name: String,
    pub mode: ProverMode,
    pub max_sent_data: usize,
    pub max_sent_records: Option<usize>,
    pub max_recv_data_online: Option<usize>,
    pub max_recv_data: usize,
    pub max_recv_records_online: Option<usize>,
    pub defer_decryption_from_start: Option<bool>,
    pub network: NetworkSetting,
    pub client_auth: Option<(Vec<Vec<u8>>, Vec<u8>)>,
}
