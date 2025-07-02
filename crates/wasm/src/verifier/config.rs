use serde::Deserialize;
use tlsn::config::ProtocolConfigValidator;
use tsify_next::Tsify;

#[derive(Debug, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct VerifierConfig {
    pub max_sent_data: usize,
    pub max_recv_data: usize,
    pub max_sent_records: Option<usize>,
    pub max_recv_records_online: Option<usize>,
}

impl From<VerifierConfig> for tlsn::verifier::VerifierConfig {
    fn from(value: VerifierConfig) -> Self {
        let mut builder = ProtocolConfigValidator::builder();

        builder.max_sent_data(value.max_sent_data);
        builder.max_recv_data(value.max_recv_data);

        if let Some(value) = value.max_sent_records {
            builder.max_sent_records(value);
        }

        if let Some(value) = value.max_recv_records_online {
            builder.max_recv_records_online(value);
        }

        let validator = builder.build().unwrap();

        tlsn::verifier::VerifierConfig::builder()
            .protocol_config_validator(validator)
            .build()
            .unwrap()
    }
}
