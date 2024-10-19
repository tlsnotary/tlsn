use serde::Deserialize;
use tlsn_common::config::ProtocolConfigValidator;
use tsify_next::Tsify;

#[derive(Debug, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct VerifierConfig {
    pub max_sent_data: usize,
    pub max_recv_data: usize,
}

impl From<VerifierConfig> for tlsn_verifier::VerifierConfig {
    fn from(value: VerifierConfig) -> Self {
        let mut builder = ProtocolConfigValidator::builder();

        builder.max_sent_data(value.max_sent_data);
        builder.max_recv_data(value.max_recv_data);

        let validator = builder.build().unwrap();

        tlsn_verifier::VerifierConfig::builder()
            .protocol_config_validator(validator)
            .build()
            .unwrap()
    }
}
