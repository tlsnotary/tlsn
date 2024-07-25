use serde::Deserialize;
use tsify_next::Tsify;

#[derive(Debug, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct VerifierConfig {
    pub id: String,
    pub max_sent_data: Option<usize>,
    pub max_received_data: Option<usize>,
}

impl From<VerifierConfig> for tlsn_verifier::tls::VerifierConfig {
    fn from(value: VerifierConfig) -> Self {
        let mut builder = tlsn_verifier::tls::VerifierConfig::builder();

        if let Some(value) = value.max_sent_data {
            builder = builder.max_sent_data(value);
        }

        if let Some(value) = value.max_received_data {
            builder = builder.max_recv_data(value);
        }

        builder.id(value.id).build().unwrap()
    }
}
