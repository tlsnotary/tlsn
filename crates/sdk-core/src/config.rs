//! Configuration types for the SDK.

use serde::{Deserialize, Serialize};
use tlsn::webpki::{CertificateDer, RootCertStore};

use crate::error::Result;
#[cfg(not(feature = "mozilla-certs"))]
use crate::error::SdkError;

/// Configuration for the Prover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProverConfig {
    /// The server name (domain) to connect to.
    pub server_name: String,
    /// Maximum bytes that can be sent.
    pub max_sent_data: usize,
    /// Maximum number of sent records.
    pub max_sent_records: Option<usize>,
    /// Maximum bytes that can be received during online phase.
    pub max_recv_data_online: Option<usize>,
    /// Maximum bytes that can be received in total.
    pub max_recv_data: usize,
    /// Maximum number of received records during online phase.
    pub max_recv_records_online: Option<usize>,
    /// Whether to defer decryption from the start.
    pub defer_decryption_from_start: Option<bool>,
    /// Network setting for protocol optimization.
    pub network: NetworkSetting,
    /// Optional client authentication credentials (certificates, private key).
    pub client_auth: Option<ClientAuth>,
    /// Custom root certificates (DER-encoded) for TLS server verification.
    ///
    /// If `None`, the Mozilla root certificates are used.
    pub root_certs: Option<Vec<Vec<u8>>>,
}

impl ProverConfig {
    /// Creates a new ProverConfig builder.
    pub fn builder(server_name: impl Into<String>) -> ProverConfigBuilder {
        ProverConfigBuilder::new(server_name)
    }
}

/// Builder for ProverConfig.
#[derive(Debug, Clone)]
pub struct ProverConfigBuilder {
    server_name: String,
    max_sent_data: usize,
    max_sent_records: Option<usize>,
    max_recv_data_online: Option<usize>,
    max_recv_data: usize,
    max_recv_records_online: Option<usize>,
    defer_decryption_from_start: Option<bool>,
    network: NetworkSetting,
    client_auth: Option<ClientAuth>,
    root_certs: Option<Vec<Vec<u8>>>,
}

impl ProverConfigBuilder {
    /// Creates a new builder with the given server name.
    pub fn new(server_name: impl Into<String>) -> Self {
        Self {
            server_name: server_name.into(),
            max_sent_data: 4096,
            max_sent_records: None,
            max_recv_data_online: None,
            max_recv_data: 16384,
            max_recv_records_online: None,
            defer_decryption_from_start: None,
            network: NetworkSetting::Latency,
            client_auth: None,
            root_certs: None,
        }
    }

    /// Sets the maximum bytes that can be sent.
    pub fn max_sent_data(mut self, value: usize) -> Self {
        self.max_sent_data = value;
        self
    }

    /// Sets the maximum number of sent records.
    pub fn max_sent_records(mut self, value: usize) -> Self {
        self.max_sent_records = Some(value);
        self
    }

    /// Sets the maximum bytes that can be received during online phase.
    pub fn max_recv_data_online(mut self, value: usize) -> Self {
        self.max_recv_data_online = Some(value);
        self
    }

    /// Sets the maximum bytes that can be received in total.
    pub fn max_recv_data(mut self, value: usize) -> Self {
        self.max_recv_data = value;
        self
    }

    /// Sets the maximum number of received records during online phase.
    pub fn max_recv_records_online(mut self, value: usize) -> Self {
        self.max_recv_records_online = Some(value);
        self
    }

    /// Sets whether to defer decryption from the start.
    pub fn defer_decryption_from_start(mut self, value: bool) -> Self {
        self.defer_decryption_from_start = Some(value);
        self
    }

    /// Sets the network setting.
    pub fn network(mut self, value: NetworkSetting) -> Self {
        self.network = value;
        self
    }

    /// Sets the client authentication credentials.
    pub fn client_auth(mut self, certs: Vec<Vec<u8>>, key: Vec<u8>) -> Self {
        self.client_auth = Some(ClientAuth { certs, key });
        self
    }

    /// Sets custom root certificates (DER-encoded) for TLS server verification.
    ///
    /// If not set, the Mozilla root certificates are used.
    pub fn root_certs(mut self, certs: Vec<Vec<u8>>) -> Self {
        self.root_certs = Some(certs);
        self
    }

    /// Builds the ProverConfig.
    pub fn build(self) -> ProverConfig {
        ProverConfig {
            server_name: self.server_name,
            max_sent_data: self.max_sent_data,
            max_sent_records: self.max_sent_records,
            max_recv_data_online: self.max_recv_data_online,
            max_recv_data: self.max_recv_data,
            max_recv_records_online: self.max_recv_records_online,
            defer_decryption_from_start: self.defer_decryption_from_start,
            network: self.network,
            client_auth: self.client_auth,
            root_certs: self.root_certs,
        }
    }
}

/// Configuration for the Verifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierConfig {
    /// Maximum bytes that can be sent.
    pub max_sent_data: usize,
    /// Maximum bytes that can be received.
    pub max_recv_data: usize,
    /// Maximum number of sent records.
    pub max_sent_records: Option<usize>,
    /// Maximum number of received records during online phase.
    pub max_recv_records_online: Option<usize>,
    /// Custom root certificates (DER-encoded) for TLS server verification.
    ///
    /// If `None`, the Mozilla root certificates are used.
    pub root_certs: Option<Vec<Vec<u8>>>,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            max_sent_data: 4096,
            max_recv_data: 16384,
            max_sent_records: None,
            max_recv_records_online: None,
            root_certs: None,
        }
    }
}

impl VerifierConfig {
    /// Creates a new VerifierConfig builder.
    pub fn builder() -> VerifierConfigBuilder {
        VerifierConfigBuilder::default()
    }
}

/// Builder for VerifierConfig.
#[derive(Debug, Clone)]
pub struct VerifierConfigBuilder {
    max_sent_data: usize,
    max_recv_data: usize,
    max_sent_records: Option<usize>,
    max_recv_records_online: Option<usize>,
    root_certs: Option<Vec<Vec<u8>>>,
}

impl Default for VerifierConfigBuilder {
    fn default() -> Self {
        Self {
            max_sent_data: 4096,
            max_recv_data: 16384,
            max_sent_records: None,
            max_recv_records_online: None,
            root_certs: None,
        }
    }
}

impl VerifierConfigBuilder {
    /// Sets the maximum bytes that can be sent.
    pub fn max_sent_data(mut self, value: usize) -> Self {
        self.max_sent_data = value;
        self
    }

    /// Sets the maximum bytes that can be received.
    pub fn max_recv_data(mut self, value: usize) -> Self {
        self.max_recv_data = value;
        self
    }

    /// Sets the maximum number of sent records.
    pub fn max_sent_records(mut self, value: usize) -> Self {
        self.max_sent_records = Some(value);
        self
    }

    /// Sets the maximum number of received records during online phase.
    pub fn max_recv_records_online(mut self, value: usize) -> Self {
        self.max_recv_records_online = Some(value);
        self
    }

    /// Sets custom root certificates (DER-encoded) for TLS server verification.
    ///
    /// If not set, the Mozilla root certificates are used.
    pub fn root_certs(mut self, certs: Vec<Vec<u8>>) -> Self {
        self.root_certs = Some(certs);
        self
    }

    /// Builds the VerifierConfig.
    pub fn build(self) -> VerifierConfig {
        VerifierConfig {
            max_sent_data: self.max_sent_data,
            max_recv_data: self.max_recv_data,
            max_sent_records: self.max_sent_records,
            max_recv_records_online: self.max_recv_records_online,
            root_certs: self.root_certs,
        }
    }
}

/// Network optimization setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum NetworkSetting {
    /// Optimized for high bandwidth connections.
    Bandwidth,
    /// Optimized for low latency connections.
    #[default]
    Latency,
}

impl From<NetworkSetting> for tlsn::config::tls_commit::mpc::NetworkSetting {
    fn from(value: NetworkSetting) -> Self {
        match value {
            NetworkSetting::Bandwidth => Self::Bandwidth,
            NetworkSetting::Latency => Self::Latency,
        }
    }
}

/// Client authentication credentials.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientAuth {
    /// Client certificates (DER or PEM encoded).
    pub certs: Vec<Vec<u8>>,
    /// Client private key (DER encoded).
    pub key: Vec<u8>,
}

/// Builds a [`RootCertStore`] from optional DER-encoded root certificates.
///
/// If `root_certs` is `Some`, builds a store from the provided certificates.
/// If `None`, falls back to Mozilla root certificates (requires `mozilla-certs`
/// feature).
pub(crate) fn build_root_store(root_certs: &Option<Vec<Vec<u8>>>) -> Result<RootCertStore> {
    match root_certs {
        Some(certs) => Ok(RootCertStore {
            roots: certs
                .iter()
                .map(|cert| CertificateDer(cert.clone()))
                .collect(),
        }),
        None => {
            #[cfg(feature = "mozilla-certs")]
            {
                Ok(RootCertStore::mozilla())
            }
            #[cfg(not(feature = "mozilla-certs"))]
            {
                Err(SdkError::config(
                    "no root certificates provided and mozilla-certs feature is not enabled",
                ))
            }
        }
    }
}
