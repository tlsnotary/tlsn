//! Web PKI types.

use std::time::Duration;

use rustls_pki_types::{self as webpki_types, pem::PemObject};
use serde::{Deserialize, Serialize};

use crate::connection::ServerName;

/// X.509 certificate, DER encoded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateDer(pub Vec<u8>);

impl CertificateDer {
    /// Creates a DER-encoded certificate from a PEM-encoded certificate.
    pub fn from_pem_slice(pem: &[u8]) -> Result<Self, PemError> {
        let der = webpki_types::CertificateDer::from_pem_slice(pem).map_err(|_| PemError {})?;

        Ok(Self(der.to_vec()))
    }
}

/// Private key, DER encoded.
#[derive(Debug, Clone, zeroize::ZeroizeOnDrop, Serialize, Deserialize)]
pub struct PrivateKeyDer(pub Vec<u8>);

impl PrivateKeyDer {
    /// Creates a DER-encoded private key from a PEM-encoded private key.
    pub fn from_pem_slice(pem: &[u8]) -> Result<Self, PemError> {
        let der = webpki_types::PrivateKeyDer::from_pem_slice(pem).map_err(|_| PemError {})?;

        Ok(Self(der.secret_der().to_vec()))
    }
}

/// PEM parsing error.
#[derive(Debug, thiserror::Error)]
#[error("failed to parse PEM object")]
pub struct PemError {}

/// Root certificate store.
///
/// This stores root certificates which are used to verify end-entity
/// certificates presented by a TLS server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootCertStore {
    /// Unvalidated DER-encoded X.509 root certificates.
    pub roots: Vec<CertificateDer>,
}

impl RootCertStore {
    /// Creates an empty root certificate store.
    pub fn empty() -> Self {
        Self { roots: Vec::new() }
    }
}

/// Server certificate verifier.
#[derive(Debug)]
pub struct ServerCertVerifier {
    roots: Vec<webpki_types::TrustAnchor<'static>>,
}

impl ServerCertVerifier {
    /// Creates a new server certificate verifier.
    pub fn new(roots: &RootCertStore) -> Result<Self, ServerCertVerifierError> {
        let roots = roots
            .roots
            .iter()
            .map(|cert| {
                webpki::anchor_from_trusted_cert(&webpki_types::CertificateDer::from(
                    cert.0.as_slice(),
                ))
                .map(|anchor| anchor.to_owned())
                .map_err(|err| ServerCertVerifierError::InvalidRootCertificate {
                    cert: cert.clone(),
                    reason: err.to_string(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self { roots })
    }

    /// Creates a new server certificate verifier with Mozilla root
    /// certificates.
    pub fn mozilla() -> Self {
        Self {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        }
    }

    /// Verifies the server certificate was valid at the given time of
    /// presentation.
    ///
    /// # Arguments
    ///
    /// * `end_entity` - End-entity certificate to verify.
    /// * `intermediates` - Intermediate certificates to a trust anchor.
    /// * `server_name` - Server DNS name.
    /// * `time` - Unix time the certificate was presented.
    pub fn verify_server_cert(
        &self,
        end_entity: &CertificateDer,
        intermediates: &[CertificateDer],
        server_name: &ServerName,
        time: u64,
    ) -> Result<(), ServerCertVerifierError> {
        let cert = webpki_types::CertificateDer::from(end_entity.0.as_slice());
        let cert = webpki::EndEntityCert::try_from(&cert).map_err(|e| {
            ServerCertVerifierError::InvalidEndEntityCertificate {
                cert: end_entity.clone(),
                reason: e.to_string(),
            }
        })?;
        let intermediates = intermediates
            .iter()
            .map(|c| webpki_types::CertificateDer::from(c.0.as_slice()))
            .collect::<Vec<_>>();
        let server_name = server_name.to_webpki();
        let time = webpki_types::UnixTime::since_unix_epoch(Duration::from_secs(time));

        cert.verify_for_usage(
            webpki::ALL_VERIFICATION_ALGS,
            &self.roots,
            &intermediates,
            time,
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .map(|_| ())
        .map_err(|_| ServerCertVerifierError::InvalidPath)?;

        cert.verify_is_valid_for_subject_name(&server_name)
            .map_err(|_| ServerCertVerifierError::InvalidServerName)?;

        Ok(())
    }
}

/// Error for [`ServerCertVerifier`].
#[derive(Debug, thiserror::Error)]
#[error("server certificate verification failed: {0}")]
pub enum ServerCertVerifierError {
    /// Root certificate store contains invalid certificate.
    #[error("root certificate store contains invalid certificate: {reason}")]
    InvalidRootCertificate {
        /// Invalid certificate.
        cert: CertificateDer,
        /// Reason for invalidity.
        reason: String,
    },
    /// End-entity certificate is invalid.
    #[error("end-entity certificate is invalid: {reason}")]
    InvalidEndEntityCertificate {
        /// Invalid certificate.
        cert: CertificateDer,
        /// Reason for invalidity.
        reason: String,
    },
    /// Failed to verify certificate path to provided trust anchors.
    #[error("failed to verify certificate path to provided trust anchors")]
    InvalidPath,
    /// Failed to verify certificate is valid for provided server name.
    #[error("failed to verify certificate is valid for provided server name")]
    InvalidServerName,
}
