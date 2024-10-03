//! Types for proving details of a connection.

use serde::{Deserialize, Serialize};

use crate::{
    connection::{
        commit::{ServerCertCommitment, ServerCertOpening},
        CertificateVerificationError, ServerEphemKey, ServerName,
    },
    hash::{HashAlgorithmExt, HashProviderError},
    CryptoProvider,
};

/// TLS server identity proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerIdentityProof {
    name: ServerName,
    opening: ServerCertOpening,
}

impl ServerIdentityProof {
    pub(crate) fn new(name: ServerName, opening: ServerCertOpening) -> Self {
        Self { name, opening }
    }

    /// Verifies the server identity proof.
    ///
    /// # Arguments
    ///
    /// * `provider` - The crypto provider to use for verification.
    /// * `time` - The time of the connection.
    /// * `server_ephemeral_key` - The server's ephemeral key.
    /// * `commitment` - Commitment to the server certificate.
    pub fn verify_with_provider(
        self,
        provider: &CryptoProvider,
        time: u64,
        server_ephemeral_key: &ServerEphemKey,
        commitment: &ServerCertCommitment,
    ) -> Result<ServerName, ServerIdentityProofError> {
        let hasher = provider.hash.get(&commitment.0.alg)?;

        if commitment.0.value != hasher.hash_separated(&self.opening) {
            return Err(ServerIdentityProofError {
                kind: ErrorKind::Commitment,
                message: "certificate opening does not match commitment".to_string(),
            });
        }

        // Verify certificate and identity.
        self.opening.data().verify_with_provider(
            provider,
            time,
            server_ephemeral_key,
            &self.name,
        )?;

        Ok(self.name)
    }
}

/// Error for [`ServerIdentityProof`].
#[derive(Debug, thiserror::Error)]
#[error("server identity proof error: {kind}: {message}")]
pub struct ServerIdentityProofError {
    kind: ErrorKind,
    message: String,
}

impl From<HashProviderError> for ServerIdentityProofError {
    fn from(err: HashProviderError) -> Self {
        Self {
            kind: ErrorKind::Provider,
            message: err.to_string(),
        }
    }
}

impl From<CertificateVerificationError> for ServerIdentityProofError {
    fn from(err: CertificateVerificationError) -> Self {
        Self {
            kind: ErrorKind::Certificate,
            message: err.to_string(),
        }
    }
}

#[derive(Debug)]
enum ErrorKind {
    Provider,
    Commitment,
    Certificate,
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorKind::Provider => write!(f, "provider"),
            ErrorKind::Commitment => write!(f, "commitment"),
            ErrorKind::Certificate => write!(f, "certificate"),
        }
    }
}
