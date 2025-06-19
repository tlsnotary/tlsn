//! Ciphertext commitments and proof.

use crate::hash::TypedHash;
use serde::{Deserialize, Serialize};

/// Ciphertext commitments
///
/// Also contains commitments to client/sever write keys
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ciphertext {
    sent: Vec<u8>,
    received: Vec<u8>,
    client_write_key: TypedHash,
    server_write_key: TypedHash,
}

/// Proof for [`Ciphertext`] commitments.
#[derive(Clone, Serialize, Deserialize)]
pub struct PlaintextProof {}
