use serde::Deserialize;
use tlsn_common::config::ProtocolConfig;
use tsify_next::Tsify;

#[derive(Debug, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct ProverConfig {
    pub server_name: String,
    pub max_sent_data: usize,
    pub max_recv_data_online: Option<usize>,
    pub max_recv_data: usize,
    pub defer_decryption_from_start: Option<bool>,
}

impl From<ProverConfig> for tlsn_prover::ProverConfig {
    fn from(value: ProverConfig) -> Self {
        let mut builder = ProtocolConfig::builder();

        builder.max_sent_data(value.max_sent_data);
        builder.max_recv_data(value.max_recv_data);

        if let Some(value) = value.max_recv_data_online {
            builder.max_recv_data_online(value);
        }

        let protocol_config = builder.build().unwrap();

        let mut builder = tlsn_prover::ProverConfig::builder();
        builder
            .server_name(value.server_name.as_ref())
            .protocol_config(protocol_config);

        if let Some(value) = value.defer_decryption_from_start {
            builder.defer_decryption_from_start(value);
        }

        builder.build().unwrap()
    }
}
