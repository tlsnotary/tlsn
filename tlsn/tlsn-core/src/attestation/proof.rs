use serde::{Deserialize, Serialize};
use tls_core::verify::WebPkiVerifier;

use crate::{
    attestation::{AttestationBody, AttestationHeader, FieldKind},
    conn::{ServerIdentity, ServerIdentityProof, ServerIdentityProofError},
    merkle::MerkleProof,
    substring::{SubstringProof, SubstringProofError},
    PartialTranscript,
};

/// An error for [`BodyProof`].
#[derive(Debug, thiserror::Error)]
#[error("attestation body is not consistent with the header")]
pub struct BodyProofError();

/// An attestation body proof.
#[derive(Debug, Serialize, Deserialize)]
pub struct BodyProof {
    body: AttestationBody,
    proof: MerkleProof,
}

impl BodyProof {
    /// Verifies the proof against the attestation header.
    pub fn verify(self, header: &AttestationHeader) -> Result<AttestationBody, BodyProofError> {
        let mut fields: Vec<_> = self
            .body
            .fields
            .iter()
            .map(|(id, field)| (id.0 as usize, field.clone()))
            .collect();
        fields.sort_by_key(|(id, _)| *id);
        let (leaf_indices, leafs): (Vec<_>, Vec<_>) = fields.into_iter().unzip();

        self.proof
            .verify(&header.root, &leaf_indices, &leafs)
            .map_err(|_| BodyProofError())?;

        Ok(self.body)
    }
}

/// An error for [`AttestationProof`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AttestationProofError {
    /// Attestation body is not consistent with the header.
    #[error("body proof error: {0}")]
    InvalidBody(#[from] BodyProofError),
    /// Attestation is missing a required field.
    #[error("missing field: {0:?}")]
    MissingField(FieldKind),
    /// Server identity proof error.
    #[error("server identity proof error: {0}")]
    IdentityProof(#[from] ServerIdentityProofError),
    /// Substring proof error.
    #[error("substring proof error: {0}")]
    SubstringProof(#[from] SubstringProofError),
}

/// An attestation proof.
#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationProof {
    body_proof: BodyProof,
    identity_proof: Option<ServerIdentityProof>,
    substring_proof: Option<SubstringProof>,
}

/// The output of an attestation proof.
#[derive(Debug)]
#[non_exhaustive]
pub struct AttestationProofOutput {
    /// The attestation body.
    pub body: AttestationBody,
    /// The server identity.
    pub server_identity: Option<ServerIdentity>,
    /// The partial transcript.
    pub transcript: Option<PartialTranscript>,
}

impl AttestationProof {
    /// Verifies the proof against the attestation header.
    ///
    /// # Arguments
    ///
    /// * `header` - The header attested to by a Notary.
    /// * `cert_verifier` - The certificate verifier.
    pub fn verify(
        self,
        header: &AttestationHeader,
        cert_verifier: &WebPkiVerifier,
    ) -> Result<AttestationProofOutput, AttestationProofError> {
        let body = self.body_proof.verify(header)?;
        let server_identity = if let Some(proof) = self.identity_proof {
            let info = body
                .get_info()
                .ok_or_else(|| AttestationProofError::MissingField(FieldKind::ConnectionInfo))?;
            let handshake_data = body
                .get_handshake_data()
                .ok_or_else(|| AttestationProofError::MissingField(FieldKind::HandshakeData))?;
            let cert_commitment = body.get_cert_commitment().ok_or_else(|| {
                AttestationProofError::MissingField(FieldKind::CertificateCommitment)
            })?;
            let cert_chain_commitment = body.get_cert_chain_commitment().ok_or_else(|| {
                AttestationProofError::MissingField(FieldKind::CertificateChainCommitment)
            })?;

            Some(proof.verify(
                info,
                handshake_data,
                cert_commitment,
                cert_chain_commitment,
                cert_verifier,
            )?)
        } else {
            None
        };
        let transcript = self
            .substring_proof
            .map(|proof| proof.verify(&body))
            .transpose()?;

        Ok(AttestationProofOutput {
            body,
            server_identity,
            transcript,
        })
    }
}
