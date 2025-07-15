use std::fmt::{Debug, Formatter, Result};

use crate::config::{NetworkSetting, ProtocolConfig, ProtocolConfigValidator};
use mpc_tls::Config;
use tls_core::anchors::{OwnedTrustAnchor, RootCertStore};

/// Configuration for the [`Verifier`](crate::tls::Verifier).
#[allow(missing_docs)]
#[derive(derive_builder::Builder)]
#[builder(pattern = "owned")]
pub struct VerifierConfig {
    protocol_config_validator: ProtocolConfigValidator,
    #[builder(default = "default_root_store()")]
    root_store: RootCertStore,
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
    pub fn root_store(&self) -> &RootCertStore {
        &self.root_store
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

fn default_root_store() -> RootCertStore {
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject.as_ref(),
            ta.subject_public_key_info.as_ref(),
            ta.name_constraints.as_ref().map(|nc| nc.as_ref()),
        )
    }));

    root_store
}
