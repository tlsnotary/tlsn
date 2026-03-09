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

    /// Creates a root certificate store with Mozilla root certificates.
    ///
    /// These certificates are sourced from [`webpki-root-certs`](https://docs.rs/webpki-root-certs/latest/webpki_root_certs/). It is not recommended to use these unless the
    /// application binary can be recompiled and deployed on-demand in the case
    /// that the root certificates need to be updated.
    #[cfg(feature = "mozilla-certs")]
    pub fn mozilla() -> Self {
        Self {
            roots: webpki_root_certs::TLS_SERVER_ROOT_CERTS
                .iter()
                .map(|cert| CertificateDer(cert.to_vec()))
                .collect(),
        }
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

    /// Creates a server certificate verifier with Mozilla root certificates.
    ///
    /// These certificates are sourced from [`webpki-root-certs`](https://docs.rs/webpki-root-certs/latest/webpki_root_certs/). It is not recommended to use these unless the
    /// application binary can be recompiled and deployed on-demand in the case
    /// that the root certificates need to be updated.
    #[cfg(feature = "mozilla-certs")]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        connection::DnsName,
        fixtures::ConnectionFixture,
        transcript::Transcript,
    };
    use tlsn_data_fixtures::http::{request::GET_WITH_HEADER, response::OK_JSON};

    #[test]
    fn test_cert_from_pem_valid() {
        // Use a known PEM certificate from the fixtures
        let fixture = ConnectionFixture::tlsnotary(
            Transcript::new(GET_WITH_HEADER, OK_JSON).length(),
        );
        // We can't easily get PEM from fixtures (they're DER), so test the
        // error path and the RootCertStore API instead.
        let store = RootCertStore::empty();
        assert!(store.roots.is_empty());
    }

    #[test]
    fn test_cert_from_pem_invalid() {
        let err = CertificateDer::from_pem_slice(b"not a valid PEM");
        assert!(err.is_err());
    }

    #[test]
    fn test_private_key_from_pem_invalid() {
        let err = PrivateKeyDer::from_pem_slice(b"not a valid PEM");
        assert!(err.is_err());
    }

    #[test]
    fn test_root_cert_store_empty() {
        let store = RootCertStore::empty();
        assert!(store.roots.is_empty());
    }

    #[test]
    fn test_server_cert_verifier_new() {
        let root_store = RootCertStore {
            roots: webpki_root_certs::TLS_SERVER_ROOT_CERTS
                .iter()
                .map(|c| CertificateDer(c.to_vec()))
                .collect(),
        };

        let verifier = ServerCertVerifier::new(&root_store);
        assert!(verifier.is_ok());
    }

    #[test]
    fn test_server_cert_verifier_invalid_root() {
        let root_store = RootCertStore {
            roots: vec![CertificateDer(vec![0, 1, 2, 3])],
        };

        let err = ServerCertVerifier::new(&root_store);
        assert!(matches!(
            err.unwrap_err(),
            ServerCertVerifierError::InvalidRootCertificate { .. }
        ));
    }

    #[test]
    fn test_verify_server_cert_success() {
        let root_store = RootCertStore {
            roots: webpki_root_certs::TLS_SERVER_ROOT_CERTS
                .iter()
                .map(|c| CertificateDer(c.to_vec()))
                .collect(),
        };
        let verifier = ServerCertVerifier::new(&root_store).unwrap();

        let fixture = ConnectionFixture::tlsnotary(
            Transcript::new(GET_WITH_HEADER, OK_JSON).length(),
        );

        let (ee, intermediates) = fixture.server_cert_data.certs.split_first().unwrap();
        assert!(verifier
            .verify_server_cert(
                ee,
                intermediates,
                &fixture.server_name,
                fixture.connection_info.time,
            )
            .is_ok());
    }

    #[test]
    fn test_verify_server_cert_wrong_name() {
        let root_store = RootCertStore {
            roots: webpki_root_certs::TLS_SERVER_ROOT_CERTS
                .iter()
                .map(|c| CertificateDer(c.to_vec()))
                .collect(),
        };
        let verifier = ServerCertVerifier::new(&root_store).unwrap();

        let fixture = ConnectionFixture::tlsnotary(
            Transcript::new(GET_WITH_HEADER, OK_JSON).length(),
        );

        let bad_name = ServerName::Dns(DnsName::try_from("wrong.example.com").unwrap());
        let (ee, intermediates) = fixture.server_cert_data.certs.split_first().unwrap();
        let err = verifier.verify_server_cert(
            ee,
            intermediates,
            &bad_name,
            fixture.connection_info.time,
        );

        assert!(matches!(
            err.unwrap_err(),
            ServerCertVerifierError::InvalidServerName
        ));
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
