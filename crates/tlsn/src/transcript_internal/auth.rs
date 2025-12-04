use std::sync::Arc;

use aes::Aes128;
use ctr::{
    Ctr32BE,
    cipher::{KeyIvInit, StreamCipher, StreamCipherSeek},
};
use mpz_circuits::{AES128, circuits::xor};
use mpz_core::bitvec::BitVec;
use mpz_memory_core::{
    Array, DecodeFutureTyped, MemoryExt, Vector, ViewExt,
    binary::{Binary, U8},
};
use mpz_vm_core::{Call, CallableExt, Vm};
use rangeset::{
    iter::RangeIterator,
    ops::{Difference, Union},
    set::RangeSet,
};
use tlsn_core::transcript::Record;

use crate::transcript_internal::ReferenceMap;

pub(crate) fn prove_plaintext<'a>(
    vm: &mut dyn Vm<Binary>,
    key: Array<U8, 16>,
    iv: Array<U8, 4>,
    plaintext: &[u8],
    records: impl IntoIterator<Item = &'a Record>,
    reveal: &RangeSet<usize>,
    commit: &RangeSet<usize>,
) -> Result<ReferenceMap, PlaintextAuthError> {
    let is_reveal_all = reveal == (0..plaintext.len());

    let alloc_ranges = if is_reveal_all {
        commit.clone()
    } else {
        // The plaintext is only partially revealed, so we need to authenticate in ZK.
        commit.union(reveal).into_set()
    };

    let plaintext_refs = alloc_plaintext(vm, &alloc_ranges)?;
    let records = RecordParams::from_iter(records).collect::<Vec<_>>();

    if is_reveal_all {
        drop(vm.decode(key).map_err(PlaintextAuthError::vm)?);
        drop(vm.decode(iv).map_err(PlaintextAuthError::vm)?);

        for (range, slice) in plaintext_refs.iter() {
            vm.mark_public(*slice).map_err(PlaintextAuthError::vm)?;
            vm.assign(*slice, plaintext[range].to_vec())
                .map_err(PlaintextAuthError::vm)?;
            vm.commit(*slice).map_err(PlaintextAuthError::vm)?;
        }
    } else {
        let private = commit.difference(reveal).into_set();
        for (_, slice) in plaintext_refs
            .index(&private)
            .expect("all ranges are allocated")
            .iter()
        {
            vm.mark_private(*slice).map_err(PlaintextAuthError::vm)?;
        }

        for (_, slice) in plaintext_refs
            .index(reveal)
            .expect("all ranges are allocated")
            .iter()
        {
            vm.mark_public(*slice).map_err(PlaintextAuthError::vm)?;
        }

        for (range, slice) in plaintext_refs.iter() {
            vm.assign(*slice, plaintext[range].to_vec())
                .map_err(PlaintextAuthError::vm)?;
            vm.commit(*slice).map_err(PlaintextAuthError::vm)?;
        }

        let ciphertext = alloc_ciphertext(vm, key, iv, plaintext_refs.clone(), &records)?;
        for (_, slice) in ciphertext.iter() {
            drop(vm.decode(*slice).map_err(PlaintextAuthError::vm)?);
        }
    }

    Ok(plaintext_refs)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_plaintext<'a>(
    vm: &mut dyn Vm<Binary>,
    key: Array<U8, 16>,
    iv: Array<U8, 4>,
    plaintext: &'a [u8],
    ciphertext: &'a [u8],
    records: impl IntoIterator<Item = &'a Record>,
    reveal: &RangeSet<usize>,
    commit: &RangeSet<usize>,
) -> Result<(ReferenceMap, PlaintextProof<'a>), PlaintextAuthError> {
    let is_reveal_all = reveal == (0..plaintext.len());

    let alloc_ranges = if is_reveal_all {
        commit.clone()
    } else {
        // The plaintext is only partially revealed, so we need to authenticate in ZK.
        commit.union(reveal).into_set()
    };

    let plaintext_refs = alloc_plaintext(vm, &alloc_ranges)?;
    let records = RecordParams::from_iter(records).collect::<Vec<_>>();

    let plaintext_proof = if is_reveal_all {
        let key = vm.decode(key).map_err(PlaintextAuthError::vm)?;
        let iv = vm.decode(iv).map_err(PlaintextAuthError::vm)?;

        for (range, slice) in plaintext_refs.iter() {
            vm.mark_public(*slice).map_err(PlaintextAuthError::vm)?;
            vm.assign(*slice, plaintext[range].to_vec())
                .map_err(PlaintextAuthError::vm)?;
            vm.commit(*slice).map_err(PlaintextAuthError::vm)?;
        }

        PlaintextProof(ProofInner::WithKey {
            key,
            iv,
            records,
            plaintext,
            ciphertext,
        })
    } else {
        let private = commit.difference(reveal).into_set();
        for (_, slice) in plaintext_refs
            .index(&private)
            .expect("all ranges are allocated")
            .iter()
        {
            vm.mark_blind(*slice).map_err(PlaintextAuthError::vm)?;
        }

        for (range, slice) in plaintext_refs
            .index(reveal)
            .expect("all ranges are allocated")
            .iter()
        {
            vm.mark_public(*slice).map_err(PlaintextAuthError::vm)?;
            vm.assign(*slice, plaintext[range].to_vec())
                .map_err(PlaintextAuthError::vm)?;
        }

        for (_, slice) in plaintext_refs.iter() {
            vm.commit(*slice).map_err(PlaintextAuthError::vm)?;
        }

        let ciphertext_map = alloc_ciphertext(vm, key, iv, plaintext_refs.clone(), &records)?;

        let mut ciphertexts = Vec::new();
        for (range, chunk) in ciphertext_map.iter() {
            ciphertexts.push((
                &ciphertext[range],
                vm.decode(*chunk).map_err(PlaintextAuthError::vm)?,
            ));
        }

        PlaintextProof(ProofInner::WithZk { ciphertexts })
    };

    Ok((plaintext_refs, plaintext_proof))
}

fn alloc_plaintext(
    vm: &mut dyn Vm<Binary>,
    ranges: &RangeSet<usize>,
) -> Result<ReferenceMap, PlaintextAuthError> {
    let len = ranges.len();

    if len == 0 {
        return Ok(ReferenceMap::default());
    }

    let plaintext = vm.alloc_vec::<U8>(len).map_err(PlaintextAuthError::vm)?;

    let mut pos = 0;
    Ok(ReferenceMap::from_iter(ranges.iter_ranges().map(
        move |range| {
            let chunk = plaintext
                .get(pos..pos + range.len())
                .expect("length was checked");
            pos += range.len();
            (range.start, chunk)
        },
    )))
}

fn alloc_ciphertext<'a>(
    vm: &mut dyn Vm<Binary>,
    key: Array<U8, 16>,
    iv: Array<U8, 4>,
    plaintext: ReferenceMap,
    records: impl IntoIterator<Item = &'a RecordParams>,
) -> Result<ReferenceMap, PlaintextAuthError> {
    if plaintext.is_empty() {
        return Ok(ReferenceMap::default());
    }

    let ranges = RangeSet::from(plaintext.keys().collect::<Vec<_>>());

    let keystream = alloc_keystream(vm, key, iv, &ranges, records)?;
    let mut builder = Call::builder(Arc::new(xor(ranges.len() * 8)));
    for (_, slice) in plaintext.iter() {
        builder = builder.arg(*slice);
    }
    for slice in keystream {
        builder = builder.arg(slice);
    }
    let call = builder.build().expect("call should be valid");

    let ciphertext: Vector<U8> = vm.call(call).map_err(PlaintextAuthError::vm)?;

    let mut pos = 0;
    Ok(ReferenceMap::from_iter(ranges.iter_ranges().map(
        move |range| {
            let chunk = ciphertext
                .get(pos..pos + range.len())
                .expect("length was checked");
            pos += range.len();
            (range.start, chunk)
        },
    )))
}

fn alloc_keystream<'a>(
    vm: &mut dyn Vm<Binary>,
    key: Array<U8, 16>,
    iv: Array<U8, 4>,
    ranges: &RangeSet<usize>,
    records: impl IntoIterator<Item = &'a RecordParams>,
) -> Result<Vec<Vector<U8>>, PlaintextAuthError> {
    let mut keystream = Vec::new();

    let mut pos = 0;
    let mut range_iter = ranges.iter_ranges();
    let mut current_range = range_iter.next();
    for record in records {
        let mut explicit_nonce = None;
        let mut current_block = None;
        loop {
            let Some(range) = current_range.take().or_else(|| range_iter.next()) else {
                return Ok(keystream);
            };

            let record_range = pos..pos + record.len;
            if range.start >= record_range.end {
                current_range = Some(range);
                break;
            }

            // Range with record offset applied.
            let offset_range = range.start - pos..range.end - pos;

            let explicit_nonce = if let Some(explicit_nonce) = explicit_nonce {
                explicit_nonce
            } else {
                let nonce = alloc_explicit_nonce(vm, record.explicit_nonce.clone())?;
                explicit_nonce = Some(nonce);
                nonce
            };

            const BLOCK_SIZE: usize = 16;
            let block_num = offset_range.start / BLOCK_SIZE;
            let block = if let Some((current_block_num, block)) = current_block.take()
                && current_block_num == block_num
            {
                block
            } else {
                let block = alloc_block(vm, key, iv, explicit_nonce, block_num)?;
                current_block = Some((block_num, block));
                block
            };

            // Range within the block.
            let block_range_start = offset_range.start % BLOCK_SIZE;
            let len =
                (range.end.min(record_range.end) - range.start).min(BLOCK_SIZE - block_range_start);
            let block_range = block_range_start..block_range_start + len;

            keystream.push(block.get(block_range).expect("range is checked"));

            // If the range extends past the block, process the tail.
            if range.start + len < range.end {
                current_range = Some(range.start + len..range.end);
            }
        }

        pos += record.len;
    }

    Err(ErrorRepr::OutOfBounds.into())
}

fn alloc_explicit_nonce(
    vm: &mut dyn Vm<Binary>,
    explicit_nonce: Vec<u8>,
) -> Result<Vector<U8>, PlaintextAuthError> {
    const EXPLICIT_NONCE_LEN: usize = 8;
    let nonce = vm
        .alloc_vec::<U8>(EXPLICIT_NONCE_LEN)
        .map_err(PlaintextAuthError::vm)?;
    vm.mark_public(nonce).map_err(PlaintextAuthError::vm)?;
    vm.assign(nonce, explicit_nonce)
        .map_err(PlaintextAuthError::vm)?;
    vm.commit(nonce).map_err(PlaintextAuthError::vm)?;

    Ok(nonce)
}

fn alloc_block(
    vm: &mut dyn Vm<Binary>,
    key: Array<U8, 16>,
    iv: Array<U8, 4>,
    explicit_nonce: Vector<U8>,
    block: usize,
) -> Result<Vector<U8>, PlaintextAuthError> {
    let ctr: Array<U8, 4> = vm.alloc().map_err(PlaintextAuthError::vm)?;
    vm.mark_public(ctr).map_err(PlaintextAuthError::vm)?;
    const START_CTR: u32 = 2;
    vm.assign(ctr, (START_CTR + block as u32).to_be_bytes())
        .map_err(PlaintextAuthError::vm)?;
    vm.commit(ctr).map_err(PlaintextAuthError::vm)?;

    let block: Array<U8, 16> = vm
        .call(
            Call::builder(AES128.clone())
                .arg(key)
                .arg(iv)
                .arg(explicit_nonce)
                .arg(ctr)
                .build()
                .expect("call should be valid"),
        )
        .map_err(PlaintextAuthError::vm)?;

    Ok(Vector::from(block))
}

struct RecordParams {
    explicit_nonce: Vec<u8>,
    len: usize,
}

impl RecordParams {
    fn from_iter<'a>(records: impl IntoIterator<Item = &'a Record>) -> impl Iterator<Item = Self> {
        records.into_iter().map(|record| Self {
            explicit_nonce: record.explicit_nonce.clone(),
            len: record.ciphertext.len(),
        })
    }
}

#[must_use]
pub(crate) struct PlaintextProof<'a>(ProofInner<'a>);

impl<'a> PlaintextProof<'a> {
    pub(crate) fn verify(self) -> Result<(), PlaintextAuthError> {
        match self.0 {
            ProofInner::WithKey {
                mut key,
                mut iv,
                records,
                plaintext,
                ciphertext,
            } => {
                let key = key
                    .try_recv()
                    .map_err(PlaintextAuthError::vm)?
                    .ok_or(ErrorRepr::MissingDecoding)?;
                let iv = iv
                    .try_recv()
                    .map_err(PlaintextAuthError::vm)?
                    .ok_or(ErrorRepr::MissingDecoding)?;

                verify_plaintext_with_key(key, iv, &records, plaintext, ciphertext)?;
            }
            ProofInner::WithZk { ciphertexts } => {
                for (expected, mut actual) in ciphertexts {
                    let actual = actual
                        .try_recv()
                        .map_err(PlaintextAuthError::vm)?
                        .ok_or(PlaintextAuthError(ErrorRepr::MissingDecoding))?;

                    if actual != expected {
                        return Err(PlaintextAuthError(ErrorRepr::InvalidPlaintext));
                    }
                }
            }
        }

        Ok(())
    }
}

enum ProofInner<'a> {
    WithKey {
        key: DecodeFutureTyped<BitVec, [u8; 16]>,
        iv: DecodeFutureTyped<BitVec, [u8; 4]>,
        records: Vec<RecordParams>,
        plaintext: &'a [u8],
        ciphertext: &'a [u8],
    },
    WithZk {
        // (expected, actual)
        #[allow(clippy::type_complexity)]
        ciphertexts: Vec<(&'a [u8], DecodeFutureTyped<BitVec, Vec<u8>>)>,
    },
}

fn aes_ctr_apply_keystream(key: &[u8; 16], iv: &[u8; 4], explicit_nonce: &[u8], input: &mut [u8]) {
    let mut full_iv = [0u8; 16];
    full_iv[0..4].copy_from_slice(iv);
    full_iv[4..12].copy_from_slice(&explicit_nonce[..8]);

    const START_CTR: u32 = 2;
    let mut cipher = Ctr32BE::<Aes128>::new(key.into(), &full_iv.into());
    cipher
        .try_seek(START_CTR * 16)
        .expect("start counter is less than keystream length");
    cipher.apply_keystream(input);
}

fn verify_plaintext_with_key<'a>(
    key: [u8; 16],
    iv: [u8; 4],
    records: impl IntoIterator<Item = &'a RecordParams>,
    plaintext: &[u8],
    ciphertext: &[u8],
) -> Result<(), PlaintextAuthError> {
    let mut pos = 0;
    let mut text = Vec::new();
    for record in records {
        text.clear();
        text.extend_from_slice(&plaintext[pos..pos + record.len]);

        aes_ctr_apply_keystream(&key, &iv, &record.explicit_nonce, &mut text);

        if text != ciphertext[pos..pos + record.len] {
            return Err(PlaintextAuthError(ErrorRepr::InvalidPlaintext));
        }

        pos += record.len;
    }

    Ok(())
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
    #[error("plaintext out of bounds of records. This should never happen and is an internal bug.")]
    OutOfBounds,
    #[error("missing decoding")]
    MissingDecoding,
    #[error("plaintext does not match ciphertext")]
    InvalidPlaintext,
}

#[cfg(test)]
#[allow(clippy::all)]
mod tests {
    use super::*;
    use mpz_common::context::test_st_context;
    use mpz_ideal_vm::IdealVm;
    use mpz_vm_core::prelude::*;
    use rand::{Rng, SeedableRng, rngs::StdRng};
    use rstest::*;
    use std::ops::Range;

    fn build_vm(key: [u8; 16], iv: [u8; 4]) -> (IdealVm, Array<U8, 16>, Array<U8, 4>) {
        let mut vm = IdealVm::new();
        let key_ref = vm.alloc::<Array<U8, 16>>().unwrap();
        let iv_ref = vm.alloc::<Array<U8, 4>>().unwrap();

        vm.mark_public(key_ref).unwrap();
        vm.mark_public(iv_ref).unwrap();
        vm.assign(key_ref, key).unwrap();
        vm.assign(iv_ref, iv).unwrap();
        vm.commit(key_ref).unwrap();
        vm.commit(iv_ref).unwrap();

        (vm, key_ref, iv_ref)
    }

    fn expected_aes_ctr<'a>(
        key: [u8; 16],
        iv: [u8; 4],
        records: impl IntoIterator<Item = &'a RecordParams>,
        ranges: &RangeSet<usize>,
    ) -> Vec<u8> {
        let mut keystream = Vec::new();
        let mut pos = 0;
        for record in records {
            let mut record_keystream = vec![0u8; record.len];
            aes_ctr_apply_keystream(&key, &iv, &record.explicit_nonce, &mut record_keystream);
            for mut range in ranges.iter_ranges() {
                range.start = range.start.max(pos);
                range.end = range.end.min(pos + record.len);
                if range.start < range.end {
                    keystream
                        .extend_from_slice(&record_keystream[range.start - pos..range.end - pos]);
                }
            }
            pos += record.len;
        }

        keystream
    }

    #[rstest]
    #[case::single_record_empty([0], [])]
    #[case::multiple_empty_records_empty([0, 0], [])]
    #[case::multiple_records_empty([128, 64], [])]
    #[case::single_block_full([16], [0..16])]
    #[case::single_block_partial([16], [2..14])]
    #[case::partial_block_full([15], [0..15])]
    #[case::out_of_bounds([16], [0..17])]
    #[case::multiple_records_full([128, 63, 33, 15, 4], [0..243])]
    #[case::multiple_records_partial([128, 63, 33, 15, 4], [1..15, 16..17, 18..19, 126..130, 224..225, 242..243])]
    #[tokio::test]
    async fn test_alloc_keystream(
        #[case] record_lens: impl IntoIterator<Item = usize>,
        #[case] ranges: impl IntoIterator<Item = Range<usize>>,
    ) {
        let mut rng = StdRng::seed_from_u64(0);
        let mut key = [0u8; 16];
        let mut iv = [0u8; 4];
        rng.fill(&mut key);
        rng.fill(&mut iv);

        let mut total_len = 0;
        let records = record_lens
            .into_iter()
            .map(|len| {
                let mut explicit_nonce = [0u8; 8];
                rng.fill(&mut explicit_nonce);
                total_len += len;
                RecordParams {
                    explicit_nonce: explicit_nonce.to_vec(),
                    len,
                }
            })
            .collect::<Vec<_>>();

        let ranges = RangeSet::from(ranges.into_iter().collect::<Vec<_>>());
        let is_out_of_bounds = ranges.end().unwrap_or(0) > total_len;

        let (mut ctx, _) = test_st_context(1024);
        let (mut vm, key_ref, iv_ref) = build_vm(key, iv);

        let keystream = match alloc_keystream(&mut vm, key_ref, iv_ref, &ranges, &records) {
            Ok(_) if is_out_of_bounds => panic!("should be out of bounds"),
            Ok(keystream) => keystream,
            Err(PlaintextAuthError(ErrorRepr::OutOfBounds)) if is_out_of_bounds => {
                return;
            }
            Err(e) => panic!("unexpected error: {:?}", e),
        };

        vm.execute(&mut ctx).await.unwrap();

        let keystream: Vec<u8> = keystream
            .iter()
            .flat_map(|slice| vm.get(*slice).unwrap().unwrap())
            .collect();

        assert_eq!(keystream.len(), ranges.len());

        let expected = expected_aes_ctr(key, iv, &records, &ranges);

        assert_eq!(keystream, expected);
    }

    #[rstest]
    #[case::single_record_empty([0])]
    #[case::single_record([32])]
    #[case::multiple_records([128, 63, 33, 15, 4])]
    #[case::multiple_records_with_empty([128, 63, 33, 0, 15, 4])]
    fn test_verify_plaintext_with_key(
        #[case] record_lens: impl IntoIterator<Item = usize>,
        #[values(false, true)] tamper: bool,
    ) {
        let mut rng = StdRng::seed_from_u64(0);
        let mut key = [0u8; 16];
        let mut iv = [0u8; 4];
        rng.fill(&mut key);
        rng.fill(&mut iv);

        let mut total_len = 0;
        let records = record_lens
            .into_iter()
            .map(|len| {
                let mut explicit_nonce = [0u8; 8];
                rng.fill(&mut explicit_nonce);
                total_len += len;
                RecordParams {
                    explicit_nonce: explicit_nonce.to_vec(),
                    len,
                }
            })
            .collect::<Vec<_>>();

        let mut plaintext = vec![0u8; total_len];
        rng.fill(plaintext.as_mut_slice());

        let mut ciphertext = plaintext.clone();
        expected_aes_ctr(key, iv, &records, &(0..total_len).into())
            .iter()
            .zip(ciphertext.iter_mut())
            .for_each(|(key, pt)| {
                *pt ^= *key;
            });

        if tamper {
            plaintext.first_mut().map(|pt| *pt ^= 1);
        }

        match verify_plaintext_with_key(key, iv, &records, &plaintext, &ciphertext) {
            Ok(_) if tamper && !plaintext.is_empty() => panic!("should be invalid"),
            Err(e) if !tamper => panic!("unexpected error: {:?}", e),
            _ => {}
        }
    }
}
