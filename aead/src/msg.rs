use serde::{Deserialize, Serialize};

use mpc_core::{commit::Decommitment, hash::Hash};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AeadMessage {
    TagShareCommitment(Hash),
    TagShareDecommitment(Decommitment<TagShare>),
    TagShare(TagShare),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
