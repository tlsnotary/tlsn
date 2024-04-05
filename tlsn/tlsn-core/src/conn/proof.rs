use serde::{Deserialize, Serialize};
use tls_core::verify::WebPkiVerifier;

use crate::{
    conn::{
        default_cert_verifier, CertificateSecrets, ConnectionInfo, HandshakeData, ServerIdentity,
    },
    hash::Hash,
};

/// TLS server identity proof.
#[derive(Debug, Serialize, Deserialize)]
pub struct ServerIdentityProof {
    pub(crate) cert_secrets: CertificateSecrets,
    pub(crate) identity: ServerIdentity,
}

/// Server identity proof verification error.
#[derive(Debug, thiserror::Error)]
pub enum ServerIdentityProofError {
    /// Invalid commitment.
    #[error("invalid commitment")]
    InvalidCommitment,
    /// Invalid certificate data.
    #[error("invalid certificate data")]
    InvalidCertData(#[from] crate::conn::CertificateVerificationError),
}

impl ServerIdentityProof {
    /// Verifies the server identity proof with the default certificate root store
    /// provided by the `webpki-roots` crate.
    ///
    /// # Arguments
    ///
    /// * `info` - The connection information.
    /// * `handshake_data` - The handshake data.
    /// * `cert_commitment` - The commitment to the server's certificate and signature.
    /// * `chain_commitment` - The commitment to the certificate chain.
    pub fn verify_with_default_cert_verifier(
        self,
        info: &ConnectionInfo,
        handshake_data: &HandshakeData,
        cert_commitment: &Hash,
        chain_commitment: &Hash,
    ) -> Result<ServerIdentity, ServerIdentityProofError> {
        self.verify(
            info,
            handshake_data,
            cert_commitment,
            chain_commitment,
            &default_cert_verifier(),
        )
    }

    /// Verifies the server identity proof with the provided certificate root store.
    ///
    /// # Arguments
    ///
    /// * `info` - The connection information.
    /// * `handshake_data` - The handshake data.
    /// * `cert_commitment` - The commitment to the server's certificate and signature.
    /// * `chain_commitment` - The commitment to the certificate chain.
    /// * `cert_verifier` - The certificate verifier.
    pub fn verify(
        self,
        info: &ConnectionInfo,
        handshake_data: &HandshakeData,
        cert_commitment: &Hash,
        chain_commitment: &Hash,
        cert_verifier: &WebPkiVerifier,
    ) -> Result<ServerIdentity, ServerIdentityProofError> {
        // Verify certificate and identity.
        self.cert_secrets.data.verify_with_verifier(
            info,
            handshake_data,
            &self.identity,
            cert_verifier,
        )?;

        // Verify commitments
        let expected_cert_commitment = self
            .cert_secrets
            .cert_commitment(cert_commitment.algorithm())
            .expect("cert should be present");
        let expected_chain_commitment = self
            .cert_secrets
            .cert_chain_commitment(cert_commitment.algorithm())
            .expect("certs should be present");

        if cert_commitment != &expected_cert_commitment
            || chain_commitment != &expected_chain_commitment
        {
            return Err(ServerIdentityProofError::InvalidCommitment);
        }

        Ok(self.identity)
    }
}
