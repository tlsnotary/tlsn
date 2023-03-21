//! Commitment protocols

use rand::{thread_rng, Rng};

use crate::utils::blake3;

/// Error associated with commitments
#[derive(Debug, thiserror::Error)]
pub enum CommitmentError {
    #[error("Invalid commitment opening")]
    InvalidOpening,
    #[error("Message does not match commitment")]
    InvalidMessage,
}

/// A commitment of the form H(key || message) using Blake3
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HashCommitment(pub(crate) [u8; 32]);

impl HashCommitment {
    /// Verifies an opening against this commitment
    pub fn verify(&self, opening: &Opening) -> Result<(), CommitmentError> {
        if self.0 != opening.commit().0 {
            return Err(CommitmentError::InvalidOpening);
        }
        Ok(())
    }
}

/// A randomly generated 32 byte key
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CommitmentKey(pub(crate) [u8; 32]);

impl CommitmentKey {
    /// Creates a random 32 byte key
    pub fn random() -> Self {
        Self(thread_rng().gen())
    }
}

/// Opening information for a commitment
#[derive(Debug, Clone, PartialEq)]
pub struct Opening {
    pub(crate) key: CommitmentKey,
    pub(crate) message: Vec<u8>,
}

impl Opening {
    /// Creates a new opening for a keyed hash commitment
    pub fn new(message: &[u8]) -> Self {
        Self {
            key: CommitmentKey::random(),
            message: message.to_vec(),
        }
    }

    /// Returns message
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// Verifies this opening corresponds to a given message.
    pub fn verify_message(&self, message: &[u8]) -> Result<(), CommitmentError> {
        if self.message != message {
            return Err(CommitmentError::InvalidMessage);
        }
        Ok(())
    }

    /// Creates a new commitment to this opening
    pub fn commit(&self) -> HashCommitment {
        let mut message = self.key.0.to_vec();
        message.extend(&self.message);
        HashCommitment(blake3(&message))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_commitment_pass() {
        let message = [0, 1, 2, 3u8];
        let opening = Opening::new(&message);
        let commitment = opening.commit();

        commitment.verify(&opening).unwrap();
    }

    #[test]
    fn test_commitment_invalid_key() {
        let message = [0, 1, 2, 3u8];
        let mut opening = Opening::new(&message);
        let commitment = opening.commit();

        opening.key.0[0] = opening.key.0[0] - 1;

        let err = commitment.verify(&opening).unwrap_err();

        assert!(matches!(err, CommitmentError::InvalidOpening));
    }

    #[test]
    fn test_commitment_invalid_message() {
        let message = [0, 1, 2, 3u8];
        let mut opening = Opening::new(&message);
        let commitment = opening.commit();

        opening.message[0] = opening.message[0] + 1;

        let err = commitment.verify(&opening).unwrap_err();

        assert!(matches!(err, CommitmentError::InvalidOpening));
    }
}
