use std::time::{Duration, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use mpz_core::{commit::Decommitment, serialize::CanonicalSerialize};
use tls_core::{
    anchors::{OwnedTrustAnchor, RootCertStore},
    dns::ServerName as TlsServerName,
    handshake::HandshakeData,
    verify::{ServerCertVerifier, WebPkiVerifier},
};

use crate::{
    proof::SubstringsProof,
    session::SessionHeader,
    signature::{Signature, SignatureVerifyError},
    NotaryPublicKey, ServerName,
};

/// Proof that a transcript of communications took place between a Prover and Server.
#[derive(Debug, Serialize, Deserialize)]
pub struct TlsProof {
    /// Proof of the TLS handshake, server identity, and commitments to the the transcript.
    pub session: SessionProof,
    /// Proof regarding the contents of the transcript.
    pub substrings: SubstringsProof,
}

/// An error that can occur while verifying a [`SessionProof`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SessionProofError {
    /// Session proof is missing Notary signature
    #[error("session proof is missing notary signature")]
    MissingNotarySignature,
    /// Invalid signature
    #[error(transparent)]
    InvalidSignature(#[from] SignatureVerifyError),
    /// Invalid server name.
    #[error("invalid server name: {0}")]
    InvalidServerName(String),
    /// Invalid handshake
    #[error("handshake verification failed: {0}")]
    InvalidHandshake(String),
    /// Invalid server certificate
    #[error("server certificate verification failed: {0}")]
    InvalidServerCertificate(String),
}

/// Proof of the TLS handshake, server identity, and commitments to the the transcript.
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionProof {
    /// The session header
    pub header: SessionHeader,
    /// The server name.
    pub server_name: ServerName,
    /// Signature for the session header, if the notary signed it
    pub signature: Option<Signature>,
    /// Decommitment to the TLS handshake and server identity.
    pub handshake_data_decommitment: Decommitment<HandshakeData>,
}

impl SessionProof {
    /// Verify the session proof, returning the server's name.
    ///
    /// # Arguments
    ///
    /// * `notary_public_key` - The public key of the notary.
    /// * `cert_verifier` - The certificate verifier.
    pub fn verify(
        &self,
        notary_public_key: impl Into<NotaryPublicKey>,
        cert_verifier: &impl ServerCertVerifier,
    ) -> Result<(), SessionProofError> {
        // Verify notary signature
        let signature = self
            .signature
            .as_ref()
            .ok_or(SessionProofError::MissingNotarySignature)?;

        signature.verify(&self.header.to_bytes(), notary_public_key)?;

        // Verify server name
        let server_name = TlsServerName::try_from(self.server_name.as_ref())
            .map_err(|e| SessionProofError::InvalidServerName(e.to_string()))?;

        // Verify handshake
        self.handshake_data_decommitment
            .verify(self.header.handshake_summary().handshake_commitment())
            .map_err(|e| SessionProofError::InvalidHandshake(e.to_string()))?;

        // Verify server certificate
        self.handshake_data_decommitment
            .data()
            .verify(
                cert_verifier,
                UNIX_EPOCH + Duration::from_secs(self.header.handshake_summary().time()),
                &server_name,
            )
            .map_err(|e| SessionProofError::InvalidServerCertificate(e.to_string()))?;

        Ok(())
    }

    /// Verify the session proof using trust anchors from the `webpki-roots` crate.
    ///
    /// # Arguments
    ///
    /// * `notary_public_key` - The public key of the notary.
    pub fn verify_with_default_cert_verifier(
        &self,
        notary_public_key: impl Into<NotaryPublicKey>,
    ) -> Result<(), SessionProofError> {
        let mut root_store = RootCertStore::empty();
        root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
        let verifier = WebPkiVerifier::new(root_store, None);

        self.verify(notary_public_key, &verifier)
    }
}
