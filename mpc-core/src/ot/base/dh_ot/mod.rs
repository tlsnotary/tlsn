//! This module implements the CO15 Oblivious Transfer protocol from
//! [ref1] https://eprint.iacr.org/2015/267.pdf (see Figure 1)

pub mod receiver;
pub mod sender;

pub use receiver::*;
pub use sender::*;

use crate::{ot::base::ReceiverCoreError, Block};
use blake3::Hasher;
use curve25519_dalek::ristretto::RistrettoPoint;

pub(crate) const DOMAIN_SEP: &[u8] = b"CO15 DH-OT";

/// Hashes a ristretto point to a symmetric key
pub(crate) fn hash_point(point: &RistrettoPoint, tweak: &[u8]) -> Block {
    // Compute H(tweak || point)
    let mut h = Hasher::new();
    h.update(&tweak);
    h.update(point.compress().as_bytes());
    let digest = h.finalize();
    let digest: &[u8; 32] = digest.as_bytes();

    // Copy the first 16 bytes into a Block
    let mut block = [0u8; 16];
    block.copy_from_slice(&digest[..16]);
    block.into()
}

// We just do block encryption the ordinary way
pub(crate) type DhOtCiphertext = Block;

// Encrypts an input: E_k(m) = k ⊕ m
fn encrypt_input(key: Block, input: Block) -> DhOtCiphertext {
    key ^ input
}

// Decrypts an input: D_k(c) = k ⊕ c
fn decrypt_input(key: Block, ct: DhOtCiphertext) -> Result<Block, ReceiverCoreError> {
    Ok(key ^ ct)
}

// Unclear if we need to do quasi-authenticated encryption as below. Relevant Github issue:
// https://github.com/emp-toolkit/emp-ot/issues/74#issuecomment-1151550188
/*
// The encryption scheme in CO15 produces a ciphertext and a tag, both 16 bytes
pub(crate) type DhOtCiphertext = [Block; 2];

// Encrypts an input according to CO15: E_k(m) = (k[:16] ⊕ m, k[16:])
fn encrypt_input(key: &[u8; 32], input: Block) -> DhOtCiphertext {
    // Break the key into two blocks, α and β
    let mut alpha_buf = [0u8; 16];
    let mut beta_buf = [0u8; 16];
    alpha_buf.copy_from_slice(&key[..16]);
    beta_buf.copy_from_slice(&key[16..]);
    let alpha = Block::from(alpha_buf);
    let beta = Block::from(beta_buf);

    [input ^ alpha, beta]
}

// Decrypts an input according to CO15: D_k(c) = k[:16] ⊕ c[:16] if k[16:] == c[:16], else ⊥
fn decrypt_input(key: &[u8; 32], ct: &DhOtCiphertext) -> Result<Block, ReceiverCoreError> {
    // Break the key into two blocks, α and β
    let mut alpha_buf = [0u8; 16];
    let mut beta_buf = [0u8; 16];
    alpha_buf.copy_from_slice(&key[..16]);
    beta_buf.copy_from_slice(&key[16..]);
    let alpha = Block::from(alpha_buf);
    let beta = Block::from(beta_buf);

    if !bool::from(beta.ct_eq(&ct[1])) {
        Err(ReceiverCoreError::MalformedCiphertext)
    } else {
        Ok(alpha ^ ct[0])
    }
}
*/
