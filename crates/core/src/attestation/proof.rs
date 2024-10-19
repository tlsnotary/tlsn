use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    attestation::{Attestation, Body, Header},
    hash::HashAlgorithm,
    merkle::{MerkleProof, MerkleTree},
    serialize::CanonicalSerialize,
    signing::{Signature, VerifyingKey},
    CryptoProvider,
};

/// Proof of an attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationProof {
    signature: Signature,
    header: Header,
    body: BodyProof,
}

impl AttestationProof {
    pub(crate) fn new(
        provider: &CryptoProvider,
        attestation: &Attestation,
    ) -> Result<Self, AttestationError> {
        let hasher = provider
            .hash
            .get(&attestation.header.root.alg)
            .map_err(|e| AttestationError::new(ErrorKind::Provider, e))?;

        let body = BodyProof::new(hasher, attestation.body.clone())?;

        Ok(Self {
            signature: attestation.signature.clone(),
            header: attestation.header.clone(),
            body,
        })
    }

    /// Returns the verifying key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        self.body.verifying_key()
    }

    /// Verifies the attestation proof.
    ///
    /// # Arguments
    ///
    /// * `provider` - Cryptography provider.
    /// * `verifying_key` - Verifying key for the Notary signature.
    pub fn verify(self, provider: &CryptoProvider) -> Result<Attestation, AttestationError> {
        let signature_verifier = provider
            .signature
            .get(&self.signature.alg)
            .map_err(|e| AttestationError::new(ErrorKind::Provider, e))?;

        // Verify body corresponding to the header.
        let body = self.body.verify_with_provider(provider, &self.header)?;

        // Verify signature of the header.
        signature_verifier
            .verify(
                &body.verifying_key.data,
                &CanonicalSerialize::serialize(&self.header),
                &self.signature.data,
            )
            .map_err(|e| AttestationError::new(ErrorKind::Signature, e))?;

        Ok(Attestation {
            signature: self.signature,
            header: self.header,
            body,
        })
    }
}

/// Proof of an attestation body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BodyProof {
    body: Body,
    proof: MerkleProof,
}

impl BodyProof {
    /// Returns a new body proof.
    // TODO: Support including a subset of fields instead of the entire body.
    pub(crate) fn new(
        hasher: &dyn HashAlgorithm,
        body: Body,
    ) -> Result<BodyProof, AttestationError> {
        let (indices, leaves): (Vec<_>, Vec<_>) = body
            .hash_fields(hasher)
            .into_iter()
            .map(|(id, hash)| (id.0 as usize, hash))
            .unzip();

        let mut tree = MerkleTree::new(hasher.id());
        tree.insert(hasher, leaves);

        let proof = tree.proof(&indices);

        Ok(BodyProof { body, proof })
    }

    pub(crate) fn verifying_key(&self) -> &VerifyingKey {
        &self.body.verifying_key.data
    }

    /// Verifies the proof against the attestation header.
    pub(crate) fn verify_with_provider(
        self,
        provider: &CryptoProvider,
        header: &Header,
    ) -> Result<Body, AttestationError> {
        let hasher = provider
            .hash
            .get(&header.root.alg)
            .map_err(|e| AttestationError::new(ErrorKind::Provider, e))?;

        let fields = self
            .body
            .hash_fields(hasher)
            .into_iter()
            .map(|(id, hash)| (id.0 as usize, hash));

        self.proof
            .verify(hasher, &header.root, fields)
            .map_err(|e| AttestationError::new(ErrorKind::Body, e))?;

        Ok(self.body)
    }
}

/// Error for [`AttestationProof`].
#[derive(Debug, thiserror::Error)]
pub struct AttestationError {
    kind: ErrorKind,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl AttestationError {
    fn new<E>(kind: ErrorKind, source: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            kind,
            source: Some(source.into()),
        }
    }
}

impl fmt::Display for AttestationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("attestation proof error: ")?;

        match self.kind {
            ErrorKind::Provider => f.write_str("provider error")?,
            ErrorKind::Signature => f.write_str("signature error")?,
            ErrorKind::Body => f.write_str("body proof error")?,
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {}", source)?;
        }

        Ok(())
    }
}

#[derive(Debug)]
enum ErrorKind {
    Provider,
    Signature,
    Body,
}
