use crate::config::{NetworkSetting, ProtocolConfig};
use mpc_tls::Config;
use rustls_pki_types::{CertificateDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, pem::PemObject};
use tls_core::{
    anchors::{OwnedTrustAnchor, RootCertStore},
    key,
};
use tlsn_core::connection::ServerName;

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
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Root certificates.
    root_store: RootCertStore,
    /// Certificate chain and a matching private key for client
    /// authentication.
    client_auth: Option<(Vec<key::Certificate>, key::PrivateKey)>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject.as_ref(),
                ta.subject_public_key_info.as_ref(),
                ta.name_constraints.as_ref().map(|nc| nc.as_ref()),
            )
        }));

        Self {
            root_store,
            client_auth: None,
        }
    }
}

impl TlsConfig {
    /// Creates a new builder for `TlsConfig`.
    pub fn builder() -> TlsConfigBuilder {
        TlsConfigBuilder::default()
    }

    pub(crate) fn root_store(&self) -> &RootCertStore {
        &self.root_store
    }

    /// Returns a certificate chain and a matching private key for client
    /// authentication.
    pub fn client_auth(&self) -> &Option<(Vec<key::Certificate>, key::PrivateKey)> {
        &self.client_auth
    }
}

/// Builder for [`TlsConfig`].
#[derive(Debug, Default)]
pub struct TlsConfigBuilder {
    root_store: Option<RootCertStore>,
    client_auth: Option<(Vec<key::Certificate>, key::PrivateKey)>,
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
    pub fn client_auth(&mut self, cert_key: (Vec<Vec<u8>>, Vec<u8>)) -> &mut Self {
        let certs = cert_key
            .0
            .into_iter()
            .map(key::Certificate)
            .collect::<Vec<_>>();

        self.client_auth = Some((certs, key::PrivateKey(cert_key.1)));
        self
    }

    /// Sets a PEM-encoded certificate chain and a matching private key for
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
    pub fn client_auth_pem(
        &mut self,
        cert_key: (Vec<Vec<u8>>, Vec<u8>),
    ) -> Result<&mut Self, TlsConfigError> {
        let key = match PrivatePkcs8KeyDer::from_pem_slice(&cert_key.1) {
            // Try to parse as PEM PKCS#8.
            Ok(key) => (*key.secret_pkcs8_der()).to_vec(),
            // Otherwise, try to parse as PEM PKCS#1.
            Err(_) => match PrivatePkcs1KeyDer::from_pem_slice(&cert_key.1) {
                Ok(key) => (*key.secret_pkcs1_der()).to_vec(),
                Err(_) => return Err(ErrorRepr::InvalidKey.into()),
            },
        };

        let certs = cert_key
            .0
            .iter()
            .map(|c| {
                let c =
                    CertificateDer::from_pem_slice(c).map_err(|_| ErrorRepr::InvalidCertificate)?;
                Ok::<key::Certificate, TlsConfigError>(key::Certificate(c.as_ref().to_vec()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        self.client_auth = Some((certs, key::PrivateKey(key)));
        Ok(self)
    }

    /// Builds the TLS configuration.
    pub fn build(&self) -> Result<TlsConfig, TlsConfigError> {
        Ok(TlsConfig {
            root_store: self.root_store.clone().unwrap_or_else(|| {
                let mut root_store = RootCertStore::empty();
                root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(
                    |ta| {
                        OwnedTrustAnchor::from_subject_spki_name_constraints(
                            ta.subject.as_ref(),
                            ta.subject_public_key_info.as_ref(),
                            ta.name_constraints.as_ref().map(|nc| nc.as_ref()),
                        )
                    },
                ));
                root_store
            }),
            client_auth: self.client_auth.clone(),
        })
    }
}

/// TLS configuration error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct TlsConfigError(#[from] ErrorRepr);

#[derive(Debug, thiserror::Error)]
#[error("tls config error: {0}")]
enum ErrorRepr {
    #[error("the certificate for client authentication is invalid")]
    InvalidCertificate,
    #[error("the private key for client authentication is invalid")]
    InvalidKey,
}
