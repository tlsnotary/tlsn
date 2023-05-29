//! This module provides a hash commitment scheme for types which implement
//! [`CanonicalSerialize`](crate::serialize::CanonicalSerialize)

use crate::{
    hash::{Hash, SecureHash},
    serialize::CanonicalSerialize,
};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};

/// Error associated with commitments
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
pub enum CommitmentError {
    #[error("Invalid decommitment")]
    InvalidDecommitment,
}

/// A randomly generated 32 byte nonce
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Nonce([u8; 32]);

impl Nonce {
    /// Creates a random 32 byte nonce
    fn random() -> Self {
        Self(thread_rng().gen())
    }
}

/// Decommitment data for a commitment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decommitment<T>
where
    T: CanonicalSerialize,
{
    nonce: Nonce,
    data: T,
}

impl<T> Decommitment<T>
where
    T: CanonicalSerialize,
{
    /// Creates a new decommitment
    pub fn new(data: T) -> Self {
        Self {
            nonce: Nonce::random(),
            data,
        }
    }

    /// Creates a new decommitment with the provided nonce
    pub fn new_with_nonce(data: T, nonce: Nonce) -> Self {
        Self { nonce, data }
    }

    /// Creates a hash commitment
    pub fn commit(&self) -> Hash {
        self.hash()
    }

    /// Verifies that the provided commitment corresponds to this decommitment
    pub fn verify(&self, commitment: &Hash) -> Result<(), CommitmentError> {
        if commitment != &self.commit() {
            return Err(CommitmentError::InvalidDecommitment);
        }

        Ok(())
    }

    /// Returns the data
    pub fn data(&self) -> &T {
        &self.data
    }

    /// Returns the nonce
    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// Returns the data
    pub fn into_inner(self) -> T {
        self.data
    }
}

/// A trait for committing to arbitrary data which implements [`CanonicalSerialize`](crate::serialize::CanonicalSerialize)
pub trait HashCommit
where
    Self: CanonicalSerialize + Sized,
{
    /// Creates a hash commitment to self
    fn hash_commit(self) -> (Decommitment<Self>, Hash) {
        let decommitment = Decommitment::new(self);
        let commitment = decommitment.commit();

        (decommitment, commitment)
    }
}

impl<T> HashCommit for T where T: serde::Serialize {}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_commitment_pass() {
        let message = [0, 1, 2, 3u8];
        let (decommitment, commitment) = message.hash_commit();

        decommitment.verify(&commitment).unwrap();
    }

    #[test]
    fn test_commitment_invalid_nonce() {
        let message = [0, 1, 2, 3u8];
        let (mut decommitment, commitment) = message.hash_commit();

        decommitment.nonce.0[0] -= 1;

        let err = decommitment.verify(&commitment).unwrap_err();

        assert!(matches!(err, CommitmentError::InvalidDecommitment));
    }

    #[test]
    fn test_commitment_invalid_data() {
        let message = [0, 1, 2, 3u8];
        let (mut decommitment, commitment) = message.hash_commit();

        decommitment.data[0] += 1;

        let err = decommitment.verify(&commitment).unwrap_err();

        assert!(matches!(err, CommitmentError::InvalidDecommitment));
    }
}
