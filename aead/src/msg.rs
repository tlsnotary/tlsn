//! Message types for AEAD protocols.

use serde::{Deserialize, Serialize};

use mpz_core::{commit::Decommitment, hash::Hash};

/// Aead messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum AeadMessage {
    TagShareCommitment(Hash),
    TagShareDecommitment(Decommitment<TagShare>),
    TagShare(TagShare),
}

/// A tag share.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagShare {
    /// The share of the tag.
    pub share: Vec<u8>,
}

impl From<crate::aes_gcm::AesGcmTagShare> for TagShare {
    fn from(tag_share: crate::aes_gcm::AesGcmTagShare) -> Self {
        Self {
            share: tag_share.0.to_vec(),
        }
    }
}
