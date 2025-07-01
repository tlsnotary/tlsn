//! Ciphertext commitments and proof.

use crate::{hash::TypedHash, transcript::Direction};
use serde::{Deserialize, Serialize};

/// Ciphertext commitment.
///
/// Also contains a commitment to the client or sever write key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ciphertext {
    direction: Direction,
    ciphertext: Vec<u8>,
    key: TypedHash,
}

/// Proof for a [`Ciphertext`] commitment.
#[derive(Clone, Serialize, Deserialize)]
pub struct PlaintextProof {
    direction: Direction,
    plaintext: Vec<u8>,
    key: SessionKey,
}

/// TLS session key.
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionKey {
    direction: Direction,
    key: Vec<u8>,
}

opaque_debug::implement!(SessionKey);
