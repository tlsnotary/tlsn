//! This module implements the CO15 Oblivious Transfer protocol from
//! [ref1] https://eprint.iacr.org/2015/267.pdf (see Figure 1)

pub mod receiver;
pub mod sender;

pub use receiver::*;
pub use sender::*;

use crate::{ot::base::ReceiverCoreError, Block};
use curve25519_dalek::ristretto::RistrettoPoint;
use sha2::{digest, Sha256};

pub(crate) const DOMAIN_SEP: &str = "CO15 DH-OT";

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SenderSetup {
    pub public_key: RistrettoPoint,
}

/// The final output of the sender to the receiver
#[derive(Clone, Debug, PartialEq)]
pub struct SenderPayload {
    /// The pair of ciphertexts output by the sender. At most one of these can be decrypted by the
    /// receiver.
    pub ciphertexts: Vec<DhOtCiphertext>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ReceiverChoices {
    pub blinded_choices: Vec<RistrettoPoint>,
}

impl ReceiverChoices {
    /// Returns the number of choices made by the receiver
    fn len(&self) -> usize {
        self.blinded_choices.len()
    }
}

/// Hashes a ristretto point
pub(crate) fn hash_point(point: &RistrettoPoint, tweak: &[u8]) -> digest::Output<Sha256> {
    // Compute H(tweak || point)
    let mut h = Sha256::new();
    h.update(&tweak);
    h.update(point.compress().as_bytes());
    h.finalize()
}

// The encryption scheme in CO15 produces a ciphertext and a tag, both 16 bytse
pub(crate) type DhOtCiphertext = [Block; 2];

// Encrypts an input according to CO15: E_k(m) = (k[:16] ⊕ m, k[16:])
fn encrypt_input(key: [u8; 32], input: Block) -> DhOtCiphertext {
    // Break the key into two blocks, α and β
    let alpha = Block::from(key[..16]);
    let beta = Block::from(key[16..]);

    [input ^ alpha, beta]
}

// Decrypts an input according to CO15: D_k(c) = k[:16] ⊕ c[:16] if k[16:] == c[:16], else ⊥
fn decrypt_input(key: [u8; 32], ct: DhOtCiphertext) -> Result<Block, ReceiverCoreError> {
    // Break the key into two blocks, α and β
    let alpha = Block::from(key[..16]);
    let beta = Block::from(key[16..]);

    if beta != ct[1] {
        Err(ReceiverCoreError::MalformedCiphertext)
    } else {
        Ok(alpha ^ ct[0])
    }
}
