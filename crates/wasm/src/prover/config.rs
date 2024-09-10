use serde::Deserialize;
use tlsn_common::config::ProtocolConfig;
use tsify_next::Tsify;

#[derive(Debug, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct ProverConfig {
    pub id: String,
    pub server_dns: String,
    pub max_sent_data: usize,
    pub max_recv_data_online: Option<usize>,
    pub max_recv_data: usize,
    pub defer_decryption_from_start: Option<bool>,
}

impl From<ProverConfig> for tlsn_prover::tls::ProverConfig {
    fn from(value: ProverConfig) -> Self {
        let mut builder = ProtocolConfig::builder();

        builder.max_sent_data(value.max_sent_data);

        if let Some(value) = value.max_recv_data_online {
            builder.max_recv_data_online(value);
        }

        builder.max_recv_data(value.max_recv_data);

        let protocol_config = builder.build().unwrap();

        let mut builder = tlsn_prover::tls::ProverConfig::builder();
        builder
            .id(value.id)
            .server_dns(value.server_dns)
            .protocol_config(protocol_config);

        if let Some(value) = value.defer_decryption_from_start {
            builder.defer_decryption_from_start(value);
        }

        builder.build().unwrap()
    }
}
