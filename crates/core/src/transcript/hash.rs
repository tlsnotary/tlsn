//! Plaintext hash commitments.

use serde::{Deserialize, Serialize};

use crate::{
    hash::{Blinder, HashAlgId, HashAlgorithm, TypedHash},
    transcript::{Direction, Idx},
};

/// Hashes plaintext with a blinder.
///
/// By convention, plaintext is hashed as `H(msg | blinder)`.
pub fn hash_plaintext(hasher: &dyn HashAlgorithm, msg: &[u8], blinder: &Blinder) -> TypedHash {
    TypedHash {
        alg: hasher.id(),
        value: hasher.hash_prefixed(msg, blinder.as_bytes()),
    }
}

/// Hash of plaintext in the transcript.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PlaintextHash {
    /// Direction of the plaintext.
    pub direction: Direction,
    /// Index of plaintext.
    pub idx: Idx,
    /// The hash of the data.
    pub hash: TypedHash,
}

/// Secret component of [`PlaintextHash`].
#[derive(Clone, Serialize, Deserialize)]
pub struct PlaintextHashSecret {
    /// Direction of the plaintext.
    pub direction: Direction,
    /// Index of plaintext.
    pub idx: Idx,
    /// The algorithm of the hash.
    pub alg: HashAlgId,
    /// Blinder for the hash.
    pub blinder: Blinder,
}

opaque_debug::implement!(PlaintextHashSecret);
