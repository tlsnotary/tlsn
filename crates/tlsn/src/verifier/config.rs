use std::fmt::{Debug, Formatter, Result};

use mpc_tls::Config;
use serde::{Deserialize, Serialize};
use tlsn_core::webpki::RootCertStore;

use crate::config::{NetworkSetting, ProtocolConfig, ProtocolConfigValidator};

/// Configuration for the [`Verifier`](crate::tls::Verifier).
#[allow(missing_docs)]
#[derive(derive_builder::Builder, Serialize, Deserialize)]
#[builder(pattern = "owned")]
pub struct VerifierConfig {
    protocol_config_validator: ProtocolConfigValidator,
    #[builder(default, setter(strip_option))]
    root_store: Option<RootCertStore>,
}

impl Debug for VerifierConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("VerifierConfig")
            .field("protocol_config_validator", &self.protocol_config_validator)
            .finish_non_exhaustive()
    }
}

impl VerifierConfig {
    /// Creates a new configuration builder.
    pub fn builder() -> VerifierConfigBuilder {
        VerifierConfigBuilder::default()
    }

    /// Returns the protocol configuration validator.
    pub fn protocol_config_validator(&self) -> &ProtocolConfigValidator {
        &self.protocol_config_validator
    }

    /// Returns the root certificate store.
    pub fn root_store(&self) -> Option<&RootCertStore> {
        self.root_store.as_ref()
    }

    pub(crate) fn build_mpc_tls_config(&self, protocol_config: &ProtocolConfig) -> Config {
        let mut builder = Config::builder();

        builder
            .max_sent(protocol_config.max_sent_data())
            .max_recv_online(protocol_config.max_recv_data_online())
            .max_recv(protocol_config.max_recv_data());

        if let Some(max_sent_records) = protocol_config.max_sent_records() {
            builder.max_sent_records(max_sent_records);
        }

        if let Some(max_recv_records_online) = protocol_config.max_recv_records_online() {
            builder.max_recv_records_online(max_recv_records_online);
        }

        if let NetworkSetting::Latency = protocol_config.network() {
            builder.low_bandwidth();
        }

        builder.build().unwrap()
    }
}
