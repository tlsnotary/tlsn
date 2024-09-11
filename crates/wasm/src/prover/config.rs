use serde::Deserialize;
use tsify_next::Tsify;

#[derive(Debug, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct ProverConfig {
    pub id: String,
    pub server_name: String,
    pub max_sent_data: Option<usize>,
    pub max_recv_data: Option<usize>,
}

impl From<ProverConfig> for tlsn_prover::ProverConfig {
    fn from(value: ProverConfig) -> Self {
        let mut builder = tlsn_prover::ProverConfig::builder();
        builder.id(value.id);
        builder.server_name(value.server_name.as_ref());

        if let Some(value) = value.max_sent_data {
            builder.max_sent_data(value);
        }

        if let Some(value) = value.max_recv_data {
            builder.max_recv_data(value);
        }

        builder.build().unwrap()
    }
}
