use serde::{Deserialize, Serialize};

use crate::{
    attestation::FieldId,
    hash::{
        impl_domain_separator, Blinded, Blinder, HashAlgorithmExt, HashProvider, HashProviderError,
        TypedHash,
    },
    transcript::{Direction, Idx, InvalidSubsequence, Subsequence},
};

/// Hash of plaintext in the transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PlaintextHash {
    /// Direction of the plaintext.
    pub direction: Direction,
    /// Index of plaintext.
    pub idx: Idx,
    /// The hash of the data.
    pub hash: TypedHash,
}

impl_domain_separator!(PlaintextHash);

/// Secret data for a plaintext hash commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PlaintextHashSecret {
    pub(crate) direction: Direction,
    pub(crate) idx: Idx,
    pub(crate) commitment: FieldId,
    pub(crate) blinder: Blinder,
}

/// Proof of the plaintext of a hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PlaintextHashProof {
    data: Blinded<Vec<u8>>,
    commitment: FieldId,
}

impl PlaintextHashProof {
    pub(crate) fn new(data: Blinded<Vec<u8>>, commitment: FieldId) -> Self {
        Self { data, commitment }
    }
}

impl PlaintextHashProof {
    /// Returns the field id of the commitment this opening corresponds to.
    pub(crate) fn commitment_id(&self) -> &FieldId {
        &self.commitment
    }

    /// Verifies the proof, returning the subsequence of plaintext.
    ///
    /// # Arguments
    ///
    /// * `commitment` - The commitment attested to by a Notary.
    pub(crate) fn verify(
        self,
        provider: &HashProvider,
        commitment: &PlaintextHash,
    ) -> Result<(Direction, Subsequence), PlaintextHashProofError> {
        let alg = provider.get(&commitment.hash.alg)?;

        if commitment.hash.value != alg.hash_canonical(&self.data) {
            return Err(PlaintextHashProofError::new(
                "hash does not match commitment",
            ));
        }

        Ok((
            commitment.direction,
            Subsequence::new(commitment.idx.clone(), self.data.into_parts().0)?,
        ))
    }
}

/// Error for [`PlaintextHashProof`].
#[derive(Debug, thiserror::Error)]
#[error("invalid plaintext hash proof: {0}")]
pub(crate) struct PlaintextHashProofError(String);

impl PlaintextHashProofError {
    fn new<T: Into<String>>(msg: T) -> Self {
        Self(msg.into())
    }
}

impl From<HashProviderError> for PlaintextHashProofError {
    fn from(err: HashProviderError) -> Self {
        Self(err.to_string())
    }
}

impl From<InvalidSubsequence> for PlaintextHashProofError {
    fn from(err: InvalidSubsequence) -> Self {
        Self(err.to_string())
    }
}
