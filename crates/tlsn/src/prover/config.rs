use mpc_tls::Config;
use tlsn_core::{
    connection::ServerName,
    webpki::{CertificateDer, PrivateKeyDer, RootCertStore},
};

use crate::config::{NetworkSetting, ProtocolConfig};

/// Configuration for the prover.
#[derive(Debug, Clone, derive_builder::Builder)]
pub struct ProverConfig {
    /// The server DNS name.
    #[builder(setter(into))]
    server_name: ServerName,
    /// Protocol configuration to be checked with the verifier.
    protocol_config: ProtocolConfig,
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

        if let NetworkSetting::Latency = self.protocol_config.network() {
            builder.low_bandwidth();
        }

        builder.build().unwrap()
    }
}

/// Configuration for the prover's TLS connection.
#[derive(Default, Debug, Clone)]
pub struct TlsConfig {
    /// Root certificates.
    root_store: Option<RootCertStore>,
    /// Certificate chain and a matching private key for client
    /// authentication.
    client_auth: Option<(Vec<CertificateDer>, PrivateKeyDer)>,
}

impl TlsConfig {
    /// Creates a new builder for `TlsConfig`.
    pub fn builder() -> TlsConfigBuilder {
        TlsConfigBuilder::default()
    }

    pub(crate) fn root_store(&self) -> Option<&RootCertStore> {
        self.root_store.as_ref()
    }

    /// Returns a certificate chain and a matching private key for client
    /// authentication.
    pub fn client_auth(&self) -> &Option<(Vec<CertificateDer>, PrivateKeyDer)> {
        &self.client_auth
    }
}

/// Builder for [`TlsConfig`].
#[derive(Debug, Default)]
pub struct TlsConfigBuilder {
    root_store: Option<RootCertStore>,
    client_auth: Option<(Vec<CertificateDer>, PrivateKeyDer)>,
}

impl TlsConfigBuilder {
    /// Sets the root certificates to use for verifying the server's
    /// certificate.
    pub fn root_store(&mut self, store: RootCertStore) -> &mut Self {
        self.root_store = Some(store);
        self
    }

    /// Sets a DER-encoded certificate chain and a matching private key for
    /// client authentication.
    ///
    /// Often the chain will consist of a single end-entity certificate.
    ///
    /// # Arguments
    ///
    /// * `cert_key` - A tuple containing the certificate chain and the private
    ///   key.
    ///
    ///   - Each certificate in the chain must be in the X.509 format.
    ///   - The key must be in the ASN.1 format (either PKCS#8 or PKCS#1).
    pub fn client_auth(&mut self, cert_key: (Vec<CertificateDer>, PrivateKeyDer)) -> &mut Self {
        self.client_auth = Some(cert_key);
        self
    }

    /// Builds the TLS configuration.
    pub fn build(self) -> Result<TlsConfig, TlsConfigError> {
        Ok(TlsConfig {
            root_store: self.root_store,
            client_auth: self.client_auth,
        })
    }
}

/// TLS configuration error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct TlsConfigError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
#[error("tls config error")]
enum ErrorRepr {}
