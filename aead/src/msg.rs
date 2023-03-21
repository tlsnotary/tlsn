#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use mpc_core::msgs::{CommitmentOpening, HashCommitment};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum AeadMessage {
    TagShareCommitment(HashCommitment),
    TagShareOpening(CommitmentOpening),
    TagShare(TagShare),
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TagShare {
    pub share: Vec<u8>,
}

impl From<crate::aes_gcm::AesGcmTagShare> for TagShare {
    fn from(tag_share: crate::aes_gcm::AesGcmTagShare) -> Self {
        Self {
            share: tag_share.0.to_vec(),
        }
    }
}
