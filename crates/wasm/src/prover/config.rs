use serde::Deserialize;
use tsify_next::Tsify;

#[derive(Debug, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct ProverConfig {
    pub id: String,
    pub server_dns: String,
    pub max_sent_data: Option<usize>,
    pub max_recv_data: Option<usize>,
}

impl From<ProverConfig> for tlsn_prover::tls::ProverConfig {
    fn from(value: ProverConfig) -> Self {
        let mut builder = tlsn_prover::tls::ProverConfig::builder();
        builder.id(value.id);
        builder.server_dns(value.server_dns);

        if let Some(value) = value.max_sent_data {
            builder.max_sent_data(value);
        }

        if let Some(value) = value.max_recv_data {
            builder.max_recv_data(value);
        }

        builder.build().unwrap()
    }
}
