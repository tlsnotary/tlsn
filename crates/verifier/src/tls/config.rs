use std::fmt::{Debug, Formatter, Result};
use tls_tee::{TeeTlsCommonConfig, TeeTlsFollowerConfig};
use tlsn_common::config::{DEFAULT_MAX_RECV_LIMIT, DEFAULT_MAX_SENT_LIMIT};

/// Configuration for the [`Verifier`](crate::tls::Verifier).
#[allow(missing_docs)]
#[derive(derive_builder::Builder)]
#[builder(pattern = "owned")]
pub struct VerifierConfig {
    #[builder(setter(into))]
    id: String,
    /// Maximum number of bytes that can be sent.
    #[builder(default = "DEFAULT_MAX_SENT_LIMIT")]
    max_sent_data: usize,
    /// Maximum number of bytes that can be received.
    #[builder(default = "DEFAULT_MAX_RECV_LIMIT")]
    max_recv_data: usize,
}

impl Debug for VerifierConfig {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        f.debug_struct("VerifierConfig")
            .field("id", &self.id)
            .field("max_sent_data", &self.max_sent_data)
            .field("max_recv_data", &self.max_recv_data)
            .field("cert_verifier", &"_")
            .finish()
    }
}

impl VerifierConfig {
    /// Creates a new configuration builder.
    pub fn builder() -> VerifierConfigBuilder {
        VerifierConfigBuilder::default()
    }

    /// Returns the ID of the notarization session.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the maximum number of bytes that can be sent.
    pub fn max_sent_data(&self) -> usize {
        self.max_sent_data
    }

    /// Returns the maximum number of bytes that can be received.
    pub fn max_recv_data(&self) -> usize {
        self.max_recv_data
    }

    pub(crate) fn build_tee_tls_config(&self) -> TeeTlsFollowerConfig {
        TeeTlsFollowerConfig::builder()
            .common(
                TeeTlsCommonConfig::builder()
                    .id(format!("{}/tee_tls", &self.id))
                    .handshake_commit(true)
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap()
    }
}
