//! GHASH methods.

// This module belongs in tls/core. It was moved out here temporarily.

use ghash::{
    universal_hash::{KeyInit, UniversalHash as UniversalHashReference},
    GHash,
};

/// Computes a GHASH tag.
pub fn ghash(aad: &Vec<u8>, ciphertext: &Vec<u8>, key: &[u8; 16]) -> [u8; 16] {
    let mut ghash = GHash::new(key.into());
    ghash.update_padded(&build_ghash_data(aad.to_vec(), ciphertext.clone()));
    let out = ghash.finalize();
    out.into()
}

/// Builds padded data for GHASH.
pub fn build_ghash_data(mut aad: Vec<u8>, mut ciphertext: Vec<u8>) -> Vec<u8> {
    let associated_data_bitlen = (aad.len() as u64) * 8;
    let text_bitlen = (ciphertext.len() as u64) * 8;

    let len_block = ((associated_data_bitlen as u128) << 64) + (text_bitlen as u128);

    // Pad data to be a multiple of 16 bytes.
    let aad_padded_block_count = (aad.len() / 16) + (aad.len() % 16 != 0) as usize;
    aad.resize(aad_padded_block_count * 16, 0);

    let ciphertext_padded_block_count =
        (ciphertext.len() / 16) + (ciphertext.len() % 16 != 0) as usize;
    ciphertext.resize(ciphertext_padded_block_count * 16, 0);

    let mut data: Vec<u8> = Vec::with_capacity(aad.len() + ciphertext.len() + 16);
    data.extend(aad);
    data.extend(ciphertext);
    data.extend_from_slice(&len_block.to_be_bytes());

    data
}
