use serde::Deserialize;
use tlsn_common::config::ProtocolConfigValidator;
use tsify_next::Tsify;

#[derive(Debug, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct VerifierConfig {
    pub id: String,
    pub max_sent_data: usize,
    pub max_received_data: usize,
}

impl From<VerifierConfig> for tlsn_verifier::tls::VerifierConfig {
    fn from(value: VerifierConfig) -> Self {
        let mut builder = ProtocolConfigValidator::builder();

        builder.max_sent_data(value.max_sent_data);
        builder.max_recv_data(value.max_received_data);

        let config_validator = builder.build().unwrap();

        tlsn_verifier::tls::VerifierConfig::builder()
            .id(value.id)
            .protocol_config_validator(config_validator)
            .build()
            .unwrap()
    }
}
