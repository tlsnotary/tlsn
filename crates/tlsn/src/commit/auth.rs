use mpz_core::bitvec::BitVec;
use mpz_memory_core::{DecodeFutureTyped, MemoryExt, ViewExt, binary::Binary};
use mpz_vm_core::Vm;
use rangeset::{Difference, RangeSet, Subset};

use crate::{
    commit::transcript::ReferenceMap,
    zk_aes_ctr::{ZkAesCtr, ZkAesCtrError},
};

pub(crate) fn prove_plaintext(
    vm: &mut dyn Vm<Binary>,
    zk_aes: &mut ZkAesCtr,
    plaintext: &[u8],
    ranges: &RangeSet<usize>,
    public: &RangeSet<usize>,
) -> Result<ReferenceMap, PlaintextAuthError> {
    assert!(public.is_subset(ranges), "public is not a subset of ranges");

    if ranges.is_empty() {
        return Ok(ReferenceMap::default());
    }

    let (plaintext_map, ciphertext_map) = zk_aes
        .alloc_plaintext(vm, ranges)
        .map_err(ErrorRepr::ZkAesCtr)?;

    for (range, chunk) in plaintext_map
        .index(&ranges.difference(public))
        .expect("map contains all ranges")
        .iter()
    {
        vm.mark_private(*chunk).map_err(PlaintextAuthError::vm)?;
        vm.assign(*chunk, plaintext[range].to_vec())
            .map_err(PlaintextAuthError::vm)?;
        vm.commit(*chunk).map_err(PlaintextAuthError::vm)?;
    }

    for (range, chunk) in plaintext_map
        .index(public)
        .expect("map contains all ranges")
        .iter()
    {
        vm.mark_public(*chunk).map_err(PlaintextAuthError::vm)?;
        vm.assign(*chunk, plaintext[range].to_vec())
            .map_err(PlaintextAuthError::vm)?;
        vm.commit(*chunk).map_err(PlaintextAuthError::vm)?;
    }

    for (_, chunk) in ciphertext_map.iter() {
        drop(vm.decode(*chunk).map_err(PlaintextAuthError::vm)?);
    }

    Ok(plaintext_map)
}

pub(crate) fn verify_plaintext(
    vm: &mut dyn Vm<Binary>,
    zk_aes: &mut ZkAesCtr,
    plaintext: &[u8],
    ciphertext: &[u8],
    ranges: &RangeSet<usize>,
    public: &RangeSet<usize>,
) -> Result<(ReferenceMap, PlaintextProof), PlaintextAuthError> {
    assert!(public.is_subset(ranges), "public is not a subset of ranges");

    if ranges.is_empty() {
        return Ok((
            ReferenceMap::default(),
            PlaintextProof {
                ciphertexts: vec![],
            },
        ));
    }

    let (plaintext_map, ciphertext_map) = zk_aes
        .alloc_plaintext(vm, ranges)
        .map_err(ErrorRepr::ZkAesCtr)?;

    for (_, chunk) in plaintext_map
        .index(&ranges.difference(public))
        .expect("map contains all ranges")
        .iter()
    {
        vm.mark_blind(*chunk).map_err(PlaintextAuthError::vm)?;
        vm.commit(*chunk).map_err(PlaintextAuthError::vm)?;
    }

    for (range, chunk) in plaintext_map
        .index(public)
        .expect("map contains all ranges")
        .iter()
    {
        vm.mark_public(*chunk).map_err(PlaintextAuthError::vm)?;
        vm.assign(*chunk, plaintext[range].to_vec())
            .map_err(PlaintextAuthError::vm)?;
        vm.commit(*chunk).map_err(PlaintextAuthError::vm)?;
    }

    let mut ciphertexts = Vec::new();
    for (range, chunk) in ciphertext_map
        .index(ranges)
        .expect("map contains all ranges")
        .iter()
    {
        ciphertexts.push((
            ciphertext[range].to_vec(),
            vm.decode(*chunk).map_err(PlaintextAuthError::vm)?,
        ));
    }

    Ok((plaintext_map, PlaintextProof { ciphertexts }))
}

#[derive(Debug, thiserror::Error)]
#[error("plaintext authentication error: {0}")]
pub(crate) struct PlaintextAuthError(#[from] ErrorRepr);

impl PlaintextAuthError {
    fn vm<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Vm(err.into()))
    }
}

#[derive(Debug, thiserror::Error)]
enum ErrorRepr {
    #[error("vm error: {0}")]
    Vm(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("zk aes ctr error: {0}")]
    ZkAesCtr(ZkAesCtrError),
    #[error("missing decoding")]
    MissingDecoding,
    #[error("invalid ciphertext")]
    InvalidCiphertext,
}

#[must_use]
pub(crate) struct PlaintextProof {
    // (expected, actual)
    ciphertexts: Vec<(Vec<u8>, DecodeFutureTyped<BitVec, Vec<u8>>)>,
}

impl PlaintextProof {
    pub(crate) fn verify(self) -> Result<(), PlaintextAuthError> {
        let Self {
            ciphertexts: ciphertext,
        } = self;

        for (expected, mut actual) in ciphertext {
            let actual = actual
                .try_recv()
                .map_err(PlaintextAuthError::vm)?
                .ok_or(PlaintextAuthError(ErrorRepr::MissingDecoding))?;

            if actual != expected {
                return Err(PlaintextAuthError(ErrorRepr::InvalidCiphertext));
            }
        }

        Ok(())
    }
}
