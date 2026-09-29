use crate::session::SessionOptions;
use crate::types::NetworkSetting;
use serde::Deserialize;
use tsify::Tsify;

/// Protocol mode for the prover.
#[derive(Debug, Clone, Copy, Tsify, Deserialize)]
pub enum ProverMode {
    /// MPC (Multi-Party Computation) mode.
    Mpc,
    /// Proxy mode.
    Proxy,
}

#[derive(Debug, Tsify, Deserialize)]
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
    /// Custom root certificates (DER-encoded) for TLS server verification.
    ///
    /// If not provided, Mozilla root certificates are used.
    pub root_certs: Option<Vec<Vec<u8>>>,
    /// Options for the mux session with the verifier.
    #[serde(default, deserialize_with = "crate::strict::deserialize_strict")]
    pub session: SessionOptions,
}
