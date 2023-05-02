use serde::{Deserialize, Serialize};
use std::ops::Add;

use crate::AeadError;

pub const AES_GCM_TAG_LEN: usize = 16;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AesGcmTagShare(pub(crate) [u8; 16]);

impl AesGcmTagShare {
    pub fn from_unchecked(share: &[u8]) -> Result<Self, AeadError> {
        if share.len() != 16 {
            return Err(AeadError::ValidationError(
                "Received tag share is not 16 bytes long".to_string(),
            ));
        }
        let mut result = [0u8; 16];
        result.copy_from_slice(share);
        Ok(Self(result))
    }
}

impl AsRef<[u8]> for AesGcmTagShare {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Add for AesGcmTagShare {
    type Output = Vec<u8>;

    fn add(self, rhs: Self) -> Self::Output {
        self.0
            .iter()
            .zip(rhs.0.iter())
            .map(|(a, b)| a ^ b)
            .collect()
    }
}

/// Builds padded data for GHASH
pub(crate) fn build_ghash_data(mut aad: Vec<u8>, mut ciphertext: Vec<u8>) -> Vec<u8> {
    let associated_data_bitlen = (aad.len() as u64) * 8;
    let text_bitlen = (ciphertext.len() as u64) * 8;

    let len_block = ((associated_data_bitlen as u128) << 64) + (text_bitlen as u128);

    // pad data to be a multiple of 16 bytes
    let aad_padded_block_count = (aad.len() / 16) + (aad.len() % 16 != 0) as usize;
    aad.resize(aad_padded_block_count * 16, 0);

    let ciphertext_padded_block_count =
        (ciphertext.len() / 16) + (ciphertext.len() % 16 != 0) as usize;
    ciphertext.resize(ciphertext_padded_block_count * 16, 0);

    let mut data: Vec<u8> = Vec::with_capacity(aad.len() + ciphertext.len() + 8);
    data.extend(aad);
    data.extend(ciphertext);
    data.extend_from_slice(&len_block.to_be_bytes());

    data
}
