use std::sync::Arc;

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
    /// # Arguments
    ///
    /// * `cert_key` - A tuple containing the certificate chain and the private
    ///   key.
    ///
    ///   - The chain must be X.509-formatted in one of the following encodings:
    ///     - a single DER-encoded certificate
    ///     - a single PEM-encoded certificate
    ///     - a PEM bundle of multiple certificates
    ///
    ///   - The key must be ASN.1-formatted (either PKCS#8 or PKCS#1) in either
    ///     PEM or DER encoding.
    pub fn client_auth(&mut self, cert_key: (Vec<u8>, Vec<u8>)) -> &mut Self {
        let key = match PrivatePkcs8KeyDer::from_pem_slice(&cert_key.1) {
            // Try to parse as PEM PKCS#8.
            Ok(key) => (*key.secret_pkcs8_der()).to_vec(),
            // Otherwise, try to parse as PEM PKCS#1.
            Err(_) => match PrivatePkcs1KeyDer::from_pem_slice(&cert_key.1) {
                Ok(key) => (*key.secret_pkcs1_der()).to_vec(),
                Err(_) => {
                    // Otherwise, treat the key as DER-encoded.
                    cert_key.1
                }
            },
        };

        let certs = CertificateDer::pem_slice_iter(&cert_key.0)
            .map(|c| match c {
                Ok(c) => Ok(key::Certificate(c.to_vec())),
                Err(e) => Err(e),
            })
            .collect::<Result<Vec<_>, _>>();

        let certs = match certs {
            Ok(certs) => certs,
            Err(_) => {
                // Treat the cert chain as a single DER-encoded cert.
                vec![key::Certificate(cert_key.0.to_vec())]
            }
        };

        self.client_auth = Some(Some((certs, key::PrivateKey(key))));
        self
    }
}
