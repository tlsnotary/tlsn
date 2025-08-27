use crate::types::NetworkSetting;
use serde::Deserialize;
use tlsn::{
    config::{CertificateDer, PrivateKeyDer, ProtocolConfig},
    connection::ServerName,
};
use tsify_next::Tsify;
use wasm_bindgen::JsError;

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

impl TryFrom<ProverConfig> for tlsn::prover::ProverConfig {
    type Error = JsError;

    fn try_from(value: ProverConfig) -> Result<Self, Self::Error> {
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
        if let Some((certs, key)) = value.client_auth {
            let certs = certs
                .into_iter()
                .map(|cert| {
                    // Try to parse as PEM-encoded, otherwise assume DER.
                    if let Ok(cert) = CertificateDer::from_pem_slice(&cert) {
                        cert
                    } else {
                        CertificateDer(cert)
                    }
                })
                .collect();
            let key = PrivateKeyDer(key);
            builder.client_auth((certs, key));
        }
        let tls_config = builder.build().unwrap();

        let server_name = ServerName::Dns(
            value
                .server_name
                .try_into()
                .map_err(|_| JsError::new("invalid server name"))?,
        );

        let mut builder = tlsn::prover::ProverConfig::builder();
        builder
            .server_name(server_name)
            .protocol_config(protocol_config)
            .tls_config(tls_config);

        Ok(builder.build().unwrap())
    }
}
