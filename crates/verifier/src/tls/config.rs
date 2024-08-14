use std::fmt::{Debug, Formatter, Result};
use tls_core::verify::{ServerCertVerifier, WebPkiVerifier};
use tls_tee::{TeeTlsCommonConfig, TeeTlsFollowerConfig};
use tlsn_common::config::{DEFAULT_MAX_RECV_LIMIT, DEFAULT_MAX_SENT_LIMIT};
use tlsn_core::proof::default_cert_verifier;

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
    #[builder(
        pattern = "owned",
        setter(strip_option),
        default = "Some(default_cert_verifier())"
    )]
    cert_verifier: Option<WebPkiVerifier>,
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

    /// Returns the certificate verifier.
    pub fn cert_verifier(&self) -> &impl ServerCertVerifier {
        self.cert_verifier
            .as_ref()
            .expect("Certificate verifier should be set")
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
