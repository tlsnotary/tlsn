#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum AeadMessage {
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

impl From<TagShare> for crate::unchecked::UncheckedTagShare {
    fn from(tag_share: TagShare) -> Self {
        Self(tag_share.share)
    }
}
