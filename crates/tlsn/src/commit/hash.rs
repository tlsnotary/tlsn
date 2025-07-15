//! Plaintext hash commitments.

use std::collections::HashMap;

use mpz_core::bitvec::BitVec;
use mpz_hash::sha256::Sha256;
use mpz_memory_core::{
    DecodeFutureTyped, MemoryExt, Vector,
    binary::{Binary, U8},
};
use mpz_vm_core::{Vm, VmError, prelude::*};
use tlsn_core::{
    hash::{Blinder, Hash, HashAlgId, TypedHash},
    transcript::{
        Direction, Idx,
        hash::{PlaintextHash, PlaintextHashSecret},
    },
};

use crate::{Role, commit::transcript::TranscriptRefs};

/// Future which will resolve to the committed hash values.
#[derive(Debug)]

pub(crate) struct HashCommitFuture {
    #[allow(clippy::type_complexity)]
    futs: Vec<(
        Direction,
        Idx,
        HashAlgId,
        DecodeFutureTyped<BitVec, Vec<u8>>,
    )>,
}

impl HashCommitFuture {
    /// Tries to receive the value, returning an error if the value is not
    /// ready.
    pub(crate) fn try_recv(self) -> Result<Vec<PlaintextHash>, HashCommitError> {
        let mut output = Vec::new();
        for (direction, idx, alg, mut fut) in self.futs {
            let hash = fut
                .try_recv()
                .map_err(|_| HashCommitError::decode())?
                .ok_or_else(HashCommitError::decode)?;
            output.push(PlaintextHash {
                direction,
                idx,
                hash: TypedHash {
                    alg,
                    value: Hash::try_from(hash).map_err(HashCommitError::convert)?,
                },
            });
        }

        Ok(output)
    }
}

/// Prove plaintext hash commitments.
pub(crate) fn prove_hash(
    vm: &mut dyn Vm<Binary>,
    refs: &TranscriptRefs,
    idxs: impl IntoIterator<Item = (Direction, Idx, HashAlgId)>,
) -> Result<(HashCommitFuture, Vec<PlaintextHashSecret>), HashCommitError> {
    let mut futs = Vec::new();
    let mut secrets = Vec::new();
    for (direction, idx, alg, hash_ref, blinder_ref) in
        hash_commit_inner(vm, Role::Prover, refs, idxs)?
    {
        let blinder: Blinder = rand::random();

        vm.assign(blinder_ref, blinder.as_bytes().to_vec())?;
        vm.commit(blinder_ref)?;

        let hash_fut = vm.decode(Vector::<U8>::from(hash_ref))?;

        futs.push((direction, idx.clone(), alg, hash_fut));
        secrets.push(PlaintextHashSecret {
            direction,
            idx,
            blinder,
            alg,
        });
    }

    Ok((HashCommitFuture { futs }, secrets))
}

/// Verify plaintext hash commitments.
pub(crate) fn verify_hash(
    vm: &mut dyn Vm<Binary>,
    refs: &TranscriptRefs,
    idxs: impl IntoIterator<Item = (Direction, Idx, HashAlgId)>,
) -> Result<HashCommitFuture, HashCommitError> {
    let mut futs = Vec::new();
    for (direction, idx, alg, hash_ref, blinder_ref) in
        hash_commit_inner(vm, Role::Verifier, refs, idxs)?
    {
        vm.commit(blinder_ref)?;

        let hash_fut = vm.decode(Vector::<U8>::from(hash_ref))?;

        futs.push((direction, idx, alg, hash_fut));
    }

    Ok(HashCommitFuture { futs })
}

/// Commit plaintext hashes of the transcript.
#[allow(clippy::type_complexity)]
fn hash_commit_inner(
    vm: &mut dyn Vm<Binary>,
    role: Role,
    refs: &TranscriptRefs,
    idxs: impl IntoIterator<Item = (Direction, Idx, HashAlgId)>,
) -> Result<Vec<(Direction, Idx, HashAlgId, Array<U8, 32>, Vector<U8>)>, HashCommitError> {
    let mut output = Vec::new();
    let mut hashers = HashMap::new();
    for (direction, idx, alg) in idxs {
        let blinder = vm.alloc_vec::<U8>(16)?;
        match role {
            Role::Prover => vm.mark_private(blinder)?,
            Role::Verifier => vm.mark_blind(blinder)?,
        }

        let hash = match alg {
            HashAlgId::SHA256 => {
                let mut hasher = if let Some(hasher) = hashers.get(&alg).cloned() {
                    hasher
                } else {
                    let hasher = Sha256::new_with_init(vm).map_err(HashCommitError::hasher)?;
                    hashers.insert(alg, hasher.clone());
                    hasher
                };

                for plaintext in refs.get(direction, &idx).expect("plaintext refs are valid") {
                    hasher.update(&plaintext);
                }
                hasher.update(&blinder);
                hasher.finalize(vm).map_err(HashCommitError::hasher)?
            }
            alg => {
                return Err(HashCommitError::unsupported_alg(alg));
            }
        };

        output.push((direction, idx, alg, hash, blinder));
    }

    Ok(output)
}

/// Error type for hash commitments.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct HashCommitError(#[from] ErrorRepr);

impl HashCommitError {
    fn decode() -> Self {
        Self(ErrorRepr::Decode)
    }

    fn convert(e: &'static str) -> Self {
        Self(ErrorRepr::Convert(e))
    }

    fn hasher<E>(e: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self(ErrorRepr::Hasher(e.into()))
    }

    fn unsupported_alg(alg: HashAlgId) -> Self {
        Self(ErrorRepr::UnsupportedAlg { alg })
    }
}

#[derive(Debug, thiserror::Error)]
#[error("hash commit error: {0}")]
enum ErrorRepr {
    #[error("VM error: {0}")]
    Vm(VmError),
    #[error("failed to decode hash")]
    Decode,
    #[error("failed to convert hash: {0}")]
    Convert(&'static str),
    #[error("unsupported hash algorithm: {alg}")]
    UnsupportedAlg { alg: HashAlgId },
    #[error("hasher error: {0}")]
    Hasher(Box<dyn std::error::Error + Send + Sync>),
}

impl From<VmError> for HashCommitError {
    fn from(value: VmError) -> Self {
        Self(ErrorRepr::Vm(value))
    }
}
