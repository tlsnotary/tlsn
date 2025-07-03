//! Types for committing details of a connection.

use serde::{Deserialize, Serialize};

use tlsn_core::{
    connection::{CertificateVerificationError, ServerCertData, ServerEphemKey, ServerName},
    hash::{Blinded, HashAlgorithm, HashProviderError, TypedHash},
};

use crate::{CryptoProvider, hash::HashAlgorithmExt, serialize::impl_domain_separator};

/// Opens a [`ServerCertCommitment`].
#[derive(Clone, Serialize, Deserialize)]
pub struct ServerCertOpening(Blinded<ServerCertData>);

impl_domain_separator!(ServerCertOpening);

opaque_debug::implement!(ServerCertOpening);

impl ServerCertOpening {
    pub(crate) fn new(data: ServerCertData) -> Self {
        Self(Blinded::new(data))
    }

    pub(crate) fn commit(&self, hasher: &dyn HashAlgorithm) -> ServerCertCommitment {
        ServerCertCommitment(TypedHash {
            alg: hasher.id(),
            value: hasher.hash_separated(self),
        })
    }

    /// Returns the server identity data.
    pub fn data(&self) -> &ServerCertData {
        self.0.data()
    }
}

/// Commitment to a server certificate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServerCertCommitment(pub(crate) TypedHash);

impl_domain_separator!(ServerCertCommitment);

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
    /// * `provider` - Crypto provider.
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
        self.opening
            .data()
            .verify(&provider.cert, time, server_ephemeral_key, &self.name)?;

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
