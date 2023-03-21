#[cfg(feature = "garble")]
pub mod garble;
#[cfg(feature = "ot")]
pub mod ot;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::commit;

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct HashCommitment(pub [u8; 32]);

impl From<commit::HashCommitment> for HashCommitment {
    fn from(c: commit::HashCommitment) -> Self {
        Self(c.0)
    }
}

impl From<HashCommitment> for commit::HashCommitment {
    fn from(c: HashCommitment) -> Self {
        Self(c.0)
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CommitmentKey(pub [u8; 32]);

impl From<commit::CommitmentKey> for CommitmentKey {
    fn from(key: commit::CommitmentKey) -> Self {
        Self(key.0)
    }
}

impl From<CommitmentKey> for commit::CommitmentKey {
    fn from(key: CommitmentKey) -> Self {
        Self(key.0)
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CommitmentOpening {
    pub key: CommitmentKey,
    pub message: Vec<u8>,
}

impl From<commit::Opening> for CommitmentOpening {
    fn from(c: commit::Opening) -> Self {
        Self {
            key: c.key.into(),
            message: c.message,
        }
    }
}

impl From<CommitmentOpening> for commit::Opening {
    fn from(c: CommitmentOpening) -> Self {
        Self {
            key: c.key.into(),
            message: c.message,
        }
    }
}
