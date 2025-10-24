//! TLS client configuration.

use serde::{Deserialize, Serialize};

use crate::{
    connection::ServerName,
    webpki::{CertificateDer, PrivateKeyDer, RootCertStore},
};

/// TLS client configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsClientConfig {
    server_name: ServerName,
    /// Root certificates.
    root_store: RootCertStore,
    /// Certificate chain and a matching private key for client
    /// authentication.
    client_auth: Option<(Vec<CertificateDer>, PrivateKeyDer)>,
}

impl TlsClientConfig {
    /// Creates a new builder.
    pub fn builder() -> TlsConfigBuilder {
        TlsConfigBuilder::default()
    }

    /// Returns the server name.
    pub fn server_name(&self) -> &ServerName {
        &self.server_name
    }

    /// Returns the root certificates.
    pub fn root_store(&self) -> &RootCertStore {
        &self.root_store
    }

    /// Returns a certificate chain and a matching private key for client
    /// authentication.
    pub fn client_auth(&self) -> Option<&(Vec<CertificateDer>, PrivateKeyDer)> {
        self.client_auth.as_ref()
    }
}

/// Builder for [`TlsClientConfig`].
#[derive(Debug, Default)]
pub struct TlsConfigBuilder {
    server_name: Option<ServerName>,
    root_store: Option<RootCertStore>,
    client_auth: Option<(Vec<CertificateDer>, PrivateKeyDer)>,
}

impl TlsConfigBuilder {
    /// Sets the server name.
    pub fn server_name(mut self, server_name: ServerName) -> Self {
        self.server_name = Some(server_name);
        self
    }

    /// Sets the root certificates to use for verifying the server's
    /// certificate.
    pub fn root_store(mut self, store: RootCertStore) -> Self {
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
    pub fn client_auth(mut self, cert_key: (Vec<CertificateDer>, PrivateKeyDer)) -> Self {
        self.client_auth = Some(cert_key);
        self
    }

    /// Builds the TLS configuration.
    pub fn build(self) -> Result<TlsClientConfig, TlsConfigError> {
        let server_name = self.server_name.ok_or(ErrorRepr::MissingField {
            field: "server_name",
        })?;

        let root_store = self.root_store.ok_or(ErrorRepr::MissingField {
            field: "root_store",
        })?;

        Ok(TlsClientConfig {
            server_name,
            root_store,
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
enum ErrorRepr {
    #[error("missing required field: {field}")]
    MissingField { field: &'static str },
}
