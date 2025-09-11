//! Plaintext hash commitments.

use crate::{Role, commit::transcript::TranscriptRefs};
use mpz_core::bitvec::BitVec;
use mpz_hash::sha256::Sha256;
use mpz_memory_core::{
    DecodeFutureTyped, MemoryExt, Vector,
    binary::{Binary, U8},
};
use mpz_vm_core::{Vm, VmError, prelude::*};
use rangeset::RangeSet;
use std::collections::HashMap;
use tlsn_core::{
    hash::{Blinder, Hash, HashAlgId, TypedHash},
    transcript::{
        Direction,
        hash::{PlaintextHash, PlaintextHashSecret},
    },
};

/// Creates plaintext hashes.
#[derive(Debug)]
pub(crate) struct PlaintextHasher {
    ranges: Vec<HashRange>,
}

impl PlaintextHasher {
    /// Creates a new instance.
    ///
    /// # Arguments
    ///
    /// * `indices` - The hash indices.
    pub(crate) fn new<'a>(
        indices: impl Iterator<Item = &'a (Direction, RangeSet<usize>, HashAlgId)>,
    ) -> Self {
        let mut ranges = Vec::new();

        for (direction, index, id) in indices {
            let hash_range = HashRange::new(*direction, index.clone(), *id);
            ranges.push(hash_range);
        }

        Self { ranges }
    }

    /// Prove plaintext hash commitments.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine.
    /// * `transcript_refs` - The transcript references.
    pub(crate) fn prove(
        &self,
        vm: &mut dyn Vm<Binary>,
        transcript_refs: &TranscriptRefs,
    ) -> Result<(HashFuture, Vec<PlaintextHashSecret>), HashCommitError> {
        let (hash_refs, blinders) = commit(vm, &self.ranges, Role::Prover, transcript_refs)?;

        let mut futures = Vec::new();
        let mut secrets = Vec::new();

        for ((range, hash_ref), blinder_ref) in self.ranges.iter().zip(hash_refs).zip(blinders) {
            let blinder: Blinder = rand::random();

            vm.assign(blinder_ref, blinder.as_bytes().to_vec())?;
            vm.commit(blinder_ref)?;

            let hash_fut = vm.decode(Vector::<U8>::from(hash_ref))?;

            futures.push((range.clone(), hash_fut));
            secrets.push(PlaintextHashSecret {
                direction: range.direction,
                idx: range.range.clone(),
                blinder,
                alg: range.id,
            });
        }

        let hashes = HashFuture { futures };
        Ok((hashes, secrets))
    }

    /// Verify plaintext hash commitments.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine.
    /// * `transcript_refs` - The transcript references.
    pub(crate) fn verify(
        &self,
        vm: &mut dyn Vm<Binary>,
        transcript_refs: &TranscriptRefs,
    ) -> Result<HashFuture, HashCommitError> {
        let (hash_refs, blinders) = commit(vm, &self.ranges, Role::Verifier, transcript_refs)?;

        let mut futures = Vec::new();

        for ((range, hash_ref), blinder) in self.ranges.iter().zip(hash_refs).zip(blinders) {
            vm.commit(blinder)?;

            let hash_fut = vm.decode(Vector::<U8>::from(hash_ref))?;
            futures.push((range.clone(), hash_fut))
        }

        let hashes = HashFuture { futures };
        Ok(hashes)
    }
}

/// Commit plaintext hashes of the transcript.
#[allow(clippy::type_complexity)]
fn commit(
    vm: &mut dyn Vm<Binary>,
    ranges: &[HashRange],
    role: Role,
    refs: &TranscriptRefs,
) -> Result<(Vec<Array<U8, 32>>, Vec<Vector<U8>>), HashCommitError> {
    let mut hashers = HashMap::new();
    let mut hash_refs = Vec::new();
    let mut blinders = Vec::new();

    for HashRange {
        direction,
        range,
        id,
    } in ranges.iter()
    {
        let blinder = vm.alloc_vec::<U8>(16)?;
        match role {
            Role::Prover => vm.mark_private(blinder)?,
            Role::Verifier => vm.mark_blind(blinder)?,
        }

        let hash = match *id {
            HashAlgId::SHA256 => {
                let mut hasher = if let Some(hasher) = hashers.get(id).cloned() {
                    hasher
                } else {
                    let hasher = Sha256::new_with_init(vm).map_err(HashCommitError::hasher)?;
                    hashers.insert(id, hasher.clone());
                    hasher
                };

                for plaintext in refs.get(*direction, range) {
                    hasher.update(&plaintext);
                }

                hasher.update(&blinder);
                hasher.finalize(vm).map_err(HashCommitError::hasher)?
            }
            id => {
                return Err(HashCommitError::unsupported_alg(id));
            }
        };

        hash_refs.push(hash);
        blinders.push(blinder);
    }

    Ok((hash_refs, blinders))
}

/// Future which will resolve to the committed hash values.
#[derive(Debug)]
pub(crate) struct HashFuture {
    futures: Vec<(HashRange, DecodeFutureTyped<BitVec, Vec<u8>>)>,
}

impl HashFuture {
    /// Tries to receive the value, returning an error if the value is not
    /// ready.
    pub(crate) fn try_recv(self) -> Result<Vec<PlaintextHash>, HashCommitError> {
        let mut output = Vec::new();

        for (hash_range, mut fut) in self.futures {
            let hash = fut
                .try_recv()
                .map_err(|_| HashCommitError::decode())?
                .ok_or_else(HashCommitError::decode)?;

            output.push(PlaintextHash {
                direction: hash_range.direction,
                idx: hash_range.range,
                hash: TypedHash {
                    alg: hash_range.id,
                    value: Hash::try_from(hash).map_err(HashCommitError::convert)?,
                },
            });
        }

        Ok(output)
    }
}

#[derive(Debug, Clone)]
struct HashRange {
    direction: Direction,
    range: RangeSet<usize>,
    id: HashAlgId,
}

impl HashRange {
    fn new(direction: Direction, range: RangeSet<usize>, id: HashAlgId) -> Self {
        Self {
            direction,
            range,
            id,
        }
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

#[cfg(test)]
mod test {
    use crate::{
        Role,
        commit::{hash::PlaintextHasher, transcript::TranscriptRefs},
    };
    use mpz_common::context::test_st_context;
    use mpz_garble_core::Delta;
    use mpz_memory_core::{
        MemoryExt, Vector, ViewExt,
        binary::{Binary, U8},
    };
    use mpz_ot::ideal::rcot::{IdealRCOTReceiver, IdealRCOTSender, ideal_rcot};
    use mpz_vm_core::{Execute, Vm};
    use mpz_zk::{Prover, ProverConfig, Verifier, VerifierConfig};
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use rangeset::{RangeSet, UnionMut};
    use rstest::{fixture, rstest};
    use sha2::Digest;
    use tlsn_core::{
        hash::HashAlgId,
        transcript::{Direction, Idx},
    };

    #[rstest]
    #[tokio::test]
    async fn test_hasher() {
        let mut sent1 = RangeSet::default();
        sent1.union_mut(&(1..6));
        sent1.union_mut(&(11..16));

        let mut sent2 = RangeSet::default();
        sent2.union_mut(&(22..25));

        let mut recv = RangeSet::default();
        recv.union_mut(&(20..25));

        let hash_ranges = [
            (Direction::Sent, Idx::new(sent1), HashAlgId::SHA256),
            (Direction::Sent, Idx::new(sent2), HashAlgId::SHA256),
            (Direction::Received, Idx::new(recv), HashAlgId::SHA256),
        ];

        let mut refs_prover = TranscriptRefs::new(1000, 1000);
        let mut refs_verifier = TranscriptRefs::new(1000, 1000);
        let values = [
            b"abcde".to_vec(),
            b"vwxyz".to_vec(),
            b"xxx".to_vec(),
            b"12345".to_vec(),
        ];

        let (mut ctx_p, mut ctx_v) = test_st_context(8);
        let (mut prover, mut verifier) = vms();

        let mut values_iter = values.iter();

        for (direction, idx, _) in hash_ranges.iter() {
            for range in idx.iter_ranges() {
                let value = values_iter.next().unwrap();

                let ref_prover = assign(Role::Prover, &mut prover, value.clone());
                refs_prover.add(*direction, &range, ref_prover);

                let ref_verifier = assign(Role::Verifier, &mut verifier, value.clone());
                refs_verifier.add(*direction, &range, ref_verifier);
            }
        }

        let hasher_prover = PlaintextHasher::new(hash_ranges.iter());
        let hasher_verifier = PlaintextHasher::new(hash_ranges.iter());

        tokio::try_join!(
            prover.execute_all(&mut ctx_p),
            verifier.execute_all(&mut ctx_v)
        )
        .unwrap();

        let (prover_hashes, prover_secrets) =
            hasher_prover.prove(&mut prover, &refs_prover).unwrap();
        let verifier_hashes = hasher_verifier
            .verify(&mut verifier, &refs_verifier)
            .unwrap();

        tokio::try_join!(
            prover.execute_all(&mut ctx_p),
            verifier.execute_all(&mut ctx_v)
        )
        .unwrap();

        let prover_hashes = prover_hashes.try_recv().unwrap();
        let verifier_hashes = verifier_hashes.try_recv().unwrap();

        assert_eq!(prover_hashes, verifier_hashes);

        let values_per_commitment = [b"abcdevwxyz".to_vec(), b"xxx".to_vec(), b"12345".to_vec()];

        for ((value, hash), secret) in values_per_commitment
            .iter()
            .zip(prover_hashes)
            .zip(prover_secrets)
        {
            let blinder = secret.blinder.as_bytes();
            let mut blinded_value = value.clone();
            blinded_value.extend_from_slice(blinder);
            let expected_hash = sha256(&blinded_value);

            let hash: Vec<u8> = hash.hash.value.into();

            assert_eq!(expected_hash, hash);
        }
    }

    fn assign(role: Role, vm: &mut dyn Vm<Binary>, value: Vec<u8>) -> Vector<U8> {
        let reference: Vector<U8> = vm.alloc_vec(value.len()).unwrap();

        if let Role::Prover = role {
            vm.mark_private(reference).unwrap();
            vm.assign(reference, value).unwrap();
        } else {
            vm.mark_blind(reference).unwrap();
        }

        vm.commit(reference).unwrap();

        reference
    }

    fn sha256(data: &[u8]) -> Vec<u8> {
        let mut hasher = sha2::Sha256::default();
        hasher.update(data);
        hasher.finalize().as_slice().to_vec()
    }

    #[fixture]
    fn vms() -> (Prover<IdealRCOTReceiver>, Verifier<IdealRCOTSender>) {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let (ot_send, ot_recv) = ideal_rcot(rng.random(), delta.into_inner());

        let prover = Prover::new(ProverConfig::default(), ot_recv);
        let verifier = Verifier::new(VerifierConfig::default(), delta, ot_send);

        (prover, verifier)
    }
}
