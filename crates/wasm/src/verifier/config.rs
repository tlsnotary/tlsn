use serde::Deserialize;
use tlsn_common::config::ProtocolConfigValidator;
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
        let mut builder = ProtocolConfigValidator::builder();

        if let Some(value) = value.max_sent_data {
            builder.max_sent_data(value);
        }

        if let Some(value) = value.max_received_data {
            builder.max_recv_data(value);
        }

        let config_validator = builder.build().unwrap();

        tlsn_verifier::tls::VerifierConfig::builder()
            .id(value.id)
            .protocol_config_validator(config_validator)
            .build()
            .unwrap()
    }
}
