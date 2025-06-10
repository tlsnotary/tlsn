use std::sync::Arc;

use derive_builder::UninitializedFieldError;
use mpc_tls::Config;
use rustls_pki_types::{pem::PemObject, CertificateDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer};
use tls_core::key;
use tlsn_common::config::{NetworkSetting, ProtocolConfig};
use tlsn_core::{connection::ServerName, CryptoProvider};

/// Configuration for the prover.
#[derive(Debug, Clone, derive_builder::Builder)]
pub struct ProverConfig {
    /// The server DNS name.
    #[builder(setter(into))]
    server_name: ServerName,
    /// Protocol configuration to be checked with the verifier.
    protocol_config: ProtocolConfig,
    /// Cryptography provider.
    #[builder(default, setter(into))]
    crypto_provider: Arc<CryptoProvider>,
    /// TLS configuration.
    #[builder(default)]
    tls_config: TlsConfig,
}

impl ProverConfig {
    /// Creates a new builder for `ProverConfig`.
    pub fn builder() -> ProverConfigBuilder {
        ProverConfigBuilder::default()
    }

    /// Returns the server DNS name.
    pub fn server_name(&self) -> &ServerName {
        &self.server_name
    }

    /// Returns the crypto provider.
    pub fn crypto_provider(&self) -> &CryptoProvider {
        &self.crypto_provider
    }

    /// Returns the protocol configuration.
    pub fn protocol_config(&self) -> &ProtocolConfig {
        &self.protocol_config
    }

    /// Returns the TLS configuration.
    pub fn tls_config(&self) -> &TlsConfig {
        &self.tls_config
    }

    pub(crate) fn build_mpc_tls_config(&self) -> Config {
        let mut builder = Config::builder();

        builder
            .defer_decryption(self.protocol_config.defer_decryption_from_start())
            .max_sent(self.protocol_config.max_sent_data())
            .max_recv_online(self.protocol_config.max_recv_data_online())
            .max_recv(self.protocol_config.max_recv_data());

        if let Some(max_sent_records) = self.protocol_config.max_sent_records() {
            builder.max_sent_records(max_sent_records);
        }

        if let Some(max_recv_records_online) = self.protocol_config.max_recv_records_online() {
            builder.max_recv_records_online(max_recv_records_online);
        }

        if let NetworkSetting::Bandwidth = self.protocol_config.network() {
            builder.high_bandwidth();
        }

        builder.build().unwrap()
    }
}

/// Configuration for the prover's TLS connection.
#[derive(Debug, Clone, Default, derive_builder::Builder)]
#[builder(build_fn(error = "TlsConfigError"))]
pub struct TlsConfig {
    /// Certificate chain and a matching private key for client
    /// authentication.
    #[builder(default, setter(custom, strip_option))]
    client_auth: Option<(Vec<key::Certificate>, key::PrivateKey)>,
}

impl TlsConfig {
    /// Creates a new builder for `TlsConfig`.
    pub fn builder() -> TlsConfigBuilder {
        TlsConfigBuilder::default()
    }

    /// Returns a certificate chain and a matching private key for client
    /// authentication.
    pub fn client_auth(&self) -> &Option<(Vec<key::Certificate>, key::PrivateKey)> {
        &self.client_auth
    }
}

impl TlsConfigBuilder {
    /// Sets a certificate chain and a matching private key for client
    /// authentication.
    ///
    /// Often the chain will consist of a single end-entity certificate.
    ///
    /// The chain must be in the PEM-encoded X.509 format.
    /// The key must be in the PEM-encoded ASN.1 format (either PKCS#8 or
    /// PKCS#1).
    pub fn client_auth(
        &mut self,
        cert_key: (Vec<u8>, Vec<u8>),
    ) -> Result<&mut Self, TlsConfigError> {
        let key = match PrivatePkcs8KeyDer::from_pem_slice(&cert_key.1) {
            Ok(key) => (*key.secret_pkcs8_der()).to_vec(),
            // If unable to parse as PKCS#8, try PKCS#1.
            Err(_) => match PrivatePkcs1KeyDer::from_pem_slice(&cert_key.1) {
                Ok(key) => (*key.secret_pkcs1_der()).to_vec(),
                Err(_) => return Err(TlsConfigError::InvalidKey),
            },
        };

        let certs = CertificateDer::pem_slice_iter(&cert_key.0)
            .map(|c| {
                let c = c.map_err(|_| TlsConfigError::InvalidCertificate)?;
                Ok::<key::Certificate, TlsConfigError>(key::Certificate(c.to_vec()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        self.client_auth = Some(Some((certs, key::PrivateKey(key))));
        Ok(self)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TlsConfigError {
    #[error("missing field: {0:?}")]
    MissingField(String),
    #[error("the certificate for client authentication is invalid")]
    InvalidCertificate,
    #[error("the private key for client authentication is invalid")]
    InvalidKey,
}

impl From<derive_builder::UninitializedFieldError> for TlsConfigError {
    fn from(e: UninitializedFieldError) -> Self {
        TlsConfigError::MissingField(e.field_name().to_string())
    }
}
