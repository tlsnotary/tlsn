//! Ciphertext commitments and proof.

use crate::hash::TypedHash;
use serde::{Deserialize, Serialize};

/// Ciphertext commitments
///
/// Also contains commitments to client/sever write keys
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ciphertext {
    sent: Vec<u8>,
    recv: Vec<u8>,
    client_write_key: TypedHash,
    server_write_key: TypedHash,
}

/// Proof for [`Ciphertext`] commitments.
#[derive(Clone, Serialize, Deserialize)]
pub struct PlaintextProof {
    sent: Vec<u8>,
    recv: Vec<u8>,
    keys: SessionKeys,
}

/// TLS session keys.
#[derive(Clone, Serialize, Deserialize)]
pub struct SessionKeys {
    client_write_key: Vec<u8>,
    server_write_key: Vec<u8>,
}

opaque_debug::implement!(SessionKeys);
