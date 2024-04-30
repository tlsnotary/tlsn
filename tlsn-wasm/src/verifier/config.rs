use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct VerifierConfig {
    id: String,
    max_sent_data: Option<usize>,
    max_received_data: Option<usize>,
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

#[derive(Serialize, Deserialize)]
pub struct VerifierData {
    pub server_dns: String,
    pub sent: Vec<u8>,
    pub sent_auth_ranges: Vec<[u64; 2]>,
    pub received: Vec<u8>,
    pub received_auth_ranges: Vec<[u64; 2]>,
}
