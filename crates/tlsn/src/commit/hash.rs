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
        Direction, Idx, TlsTranscript,
        ciphertext::{CiphertextCommitment, SessionKey, SessionSecret},
        hash::{PlaintextHash, PlaintextHashSecret},
    },
};

use crate::{Role, commit::transcript::TranscriptRefs};

/// Future which will resolve to the committed hash values.
#[derive(Debug)]
pub(crate) struct HashCommitFuture<T> {
    futs: T,
}

pub(crate) struct Plaintext {
    #[allow(clippy::type_complexity)]
    inner: Vec<(
        Direction,
        Idx,
        HashAlgId,
        DecodeFutureTyped<BitVec, Vec<u8>>,
    )>,
}

impl HashCommitFuture<Plaintext> {
    /// Tries to receive the value, returning an error if the value is not
    /// ready.
    pub(crate) fn try_recv(self) -> Result<Vec<PlaintextHash>, HashCommitError> {
        let mut output = Vec::new();
        for (direction, idx, alg, mut fut) in self.futs.inner {
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

    /// Prove plaintext hash commitments.
    pub(crate) fn prove(
        vm: &mut dyn Vm<Binary>,
        refs: &TranscriptRefs,
        idxs: impl IntoIterator<Item = (Direction, Idx, HashAlgId)>,
    ) -> Result<(Self, Vec<PlaintextHashSecret>), HashCommitError> {
        let mut inner = Vec::new();
        let mut secrets = Vec::new();
        for (direction, idx, alg, hash_ref, blinder_ref) in
            Self::commit(vm, Role::Prover, refs, idxs)?
        {
            let blinder: Blinder = rand::random();

            vm.assign(blinder_ref, blinder.as_bytes().to_vec())?;
            vm.commit(blinder_ref)?;

            let hash_fut = vm.decode(Vector::<U8>::from(hash_ref))?;

            inner.push((direction, idx.clone(), alg, hash_fut));
            secrets.push(PlaintextHashSecret {
                direction,
                idx,
                blinder,
                alg,
            });
        }

        let futs = Plaintext { inner };
        Ok((Self { futs }, secrets))
    }

    /// Verify plaintext hash commitments.
    pub(crate) fn verify(
        vm: &mut dyn Vm<Binary>,
        refs: &TranscriptRefs,
        idxs: impl IntoIterator<Item = (Direction, Idx, HashAlgId)>,
    ) -> Result<Self, HashCommitError> {
        let mut inner = Vec::new();
        for (direction, idx, alg, hash_ref, blinder_ref) in
            Self::commit(vm, Role::Verifier, refs, idxs)?
        {
            vm.commit(blinder_ref)?;

            let hash_fut = vm.decode(Vector::<U8>::from(hash_ref))?;

            inner.push((direction, idx, alg, hash_fut));
        }

        let futs = Plaintext { inner };
        Ok(Self { futs })
    }

    /// Commit plaintext hashes of the transcript.
    #[allow(clippy::type_complexity)]
    fn commit(
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
}

pub(crate) struct KeyAndIv {
    alg: HashAlgId,
    hash: DecodeFutureTyped<BitVec, Vec<u8>>,
}

impl HashCommitFuture<KeyAndIv> {
    /// Tries to receive the value, returning an error if the value is not
    /// ready.
    pub(crate) fn into_commitment(
        mut self,
        tls_transcript: &TlsTranscript,
    ) -> Result<CiphertextCommitment, HashCommitError> {
        let hash = self
            .futs
            .hash
            .try_recv()
            .map_err(|_| HashCommitError::decode())?
            .ok_or_else(HashCommitError::decode)?;

        let hash = TypedHash {
            alg: self.futs.alg,
            value: Hash::try_from(hash).map_err(HashCommitError::convert)?,
        };

        let transcript = tls_transcript.to_ciphertext_transcript(Direction::Received);
        let idx = Idx::new(0..transcript.record_count());

        let commitment = CiphertextCommitment::new(idx, hash, transcript);
        Ok(commitment)
    }

    /// Prove session secret hash commitments.
    pub(crate) fn prove(
        vm: &mut dyn Vm<Binary>,
        alg: HashAlgId,
        key: Vector<U8>,
        key_plain: [u8; 16],
        iv: Vector<U8>,
        iv_plain: [u8; 4],
    ) -> Result<(Self, SessionSecret), HashCommitError> {
        let (alg, hash, blinder_ref) = Self::commit(vm, Role::Prover, alg, key, iv)?;
        let blinder: Blinder = rand::random();

        vm.assign(blinder_ref, blinder.as_bytes().to_vec())?;
        vm.commit(blinder_ref)?;

        let hash = vm.decode(hash)?;

        let futs = KeyAndIv { alg, hash };

        let session_key = SessionKey {
            key: key_plain,
            iv: iv_plain,
        };

        let secrets = SessionSecret {
            alg,
            key: session_key,
            blinder,
        };
        Ok((Self { futs }, secrets))
    }

    /// Verify session secret hash commitments.
    pub(crate) fn verify(
        vm: &mut dyn Vm<Binary>,
        alg: HashAlgId,
        key: Vector<U8>,
        iv: Vector<U8>,
    ) -> Result<Self, HashCommitError> {
        let (alg, hash, blinder) = Self::commit(vm, Role::Verifier, alg, key, iv)?;
        vm.commit(blinder)?;

        let hash = vm.decode(hash)?;

        let futs = KeyAndIv { alg, hash };
        Ok(Self { futs })
    }

    /// Commit hash of the session secret.
    fn commit(
        vm: &mut dyn Vm<Binary>,
        role: Role,
        alg: HashAlgId,
        key: Vector<U8>,
        iv: Vector<U8>,
    ) -> Result<(HashAlgId, Vector<U8>, Vector<U8>), HashCommitError> {
        let blinder = vm.alloc_vec::<U8>(16)?;
        match role {
            Role::Prover => vm.mark_private(blinder)?,
            Role::Verifier => vm.mark_blind(blinder)?,
        }

        let mut hasher = match alg {
            HashAlgId::SHA256 => Sha256::new_with_init(vm).map_err(HashCommitError::hasher)?,
            alg => {
                return Err(HashCommitError::unsupported_alg(alg));
            }
        };
        hasher.update(&key);
        hasher.update(&iv);
        hasher.update(&blinder);
        let hash = hasher.finalize(vm).map_err(HashCommitError::hasher)?;

        Ok((alg, hash.into(), blinder))
    }
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
