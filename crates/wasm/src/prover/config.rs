use crate::types::NetworkSetting;
use serde::Deserialize;
use tlsn::config::ProtocolConfig;
use tsify_next::Tsify;

#[derive(Debug, Tsify, Deserialize)]
#[tsify(from_wasm_abi)]
pub struct ProverConfig {
    pub server_name: String,
    pub max_sent_data: usize,
    pub max_sent_records: Option<usize>,
    pub max_recv_data_online: Option<usize>,
    pub max_recv_data: usize,
    pub max_recv_records_online: Option<usize>,
    pub defer_decryption_from_start: Option<bool>,
    pub network: NetworkSetting,
    pub client_auth: Option<(Vec<Vec<u8>>, Vec<u8>)>,
}

impl From<ProverConfig> for tlsn::prover::ProverConfig {
    fn from(value: ProverConfig) -> Self {
        let mut builder = ProtocolConfig::builder();

        builder.max_sent_data(value.max_sent_data);
        builder.max_recv_data(value.max_recv_data);

        if let Some(value) = value.max_recv_data_online {
            builder.max_recv_data_online(value);
        }

        if let Some(value) = value.max_sent_records {
            builder.max_sent_records(value);
        }

        if let Some(value) = value.max_recv_records_online {
            builder.max_recv_records_online(value);
        }

        if let Some(value) = value.defer_decryption_from_start {
            builder.defer_decryption_from_start(value);
        }

        builder.network(value.network.into());
        let protocol_config = builder.build().unwrap();

        let mut builder = tlsn::prover::TlsConfig::builder();
        if let Some(cert_key) = value.client_auth {
            // Try to parse as PEM-encoded.
            if builder.client_auth_pem(cert_key.clone()).is_err() {
                // Otherwise assume DER encoding.
                builder.client_auth(cert_key);
            }
        }
        let tls_config = builder.build().unwrap();

        let mut builder = tlsn::prover::ProverConfig::builder();
        builder
            .server_name(value.server_name.as_ref())
            .protocol_config(protocol_config)
            .tls_config(tls_config);

        builder.build().unwrap()
    }
}
