use std::{ops::Range, sync::Arc};

use mpz_circuits::circuits::{AES128, xor};
use mpz_memory_core::{
    Array, MemoryExt, Vector, ViewExt,
    binary::{Binary, U8},
};
use mpz_vm_core::{Call, CallableExt, Vm};
use rangeset::RangeSet;
use tlsn_core::transcript::Record;

use crate::commit::transcript::ReferenceMap;

/// ZK AES-CTR encryption.
#[derive(Debug)]
pub(crate) struct ZkAesCtr {
    key: Array<U8, 16>,
    iv: Array<U8, 4>,
    records: Vec<(usize, RecordState)>,
    total_len: usize,
}

impl ZkAesCtr {
    /// Creates a new instance.
    pub(crate) fn new<'record>(
        key: Array<U8, 16>,
        iv: Array<U8, 4>,
        records: impl IntoIterator<Item = &'record Record>,
    ) -> Self {
        let mut pos = 0;
        let mut record_state = Vec::new();
        for record in records {
            record_state.push((
                pos,
                RecordState {
                    explicit_nonce: Some(record.explicit_nonce.clone()),
                    explicit_nonce_ref: None,
                    range: pos..pos + record.ciphertext.len(),
                },
            ));
            pos += record.ciphertext.len();
        }

        Self {
            key,
            iv,
            records: record_state,
            total_len: pos,
        }
    }

    /// Allocates the plaintext for the provided ranges.
    ///
    /// Returns a reference to the plaintext and the ciphertext.
    pub(crate) fn alloc_plaintext(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        ranges: &RangeSet<usize>,
    ) -> Result<(ReferenceMap, ReferenceMap), ZkAesCtrError> {
        let len = ranges.len();

        if len > self.total_len {
            return Err(ZkAesCtrError(ErrorRepr::TranscriptBounds {
                len,
                max: self.total_len,
            }));
        }

        let plaintext = vm.alloc_vec::<U8>(len).map_err(ZkAesCtrError::vm)?;
        let keystream = self.alloc_keystream(vm, ranges)?;

        let mut builder = Call::builder(Arc::new(xor(len * 8))).arg(plaintext);
        for slice in keystream {
            builder = builder.arg(slice);
        }
        let call = builder.build().expect("call should be valid");

        let ciphertext: Vector<U8> = vm.call(call).map_err(ZkAesCtrError::vm)?;

        let mut pos = 0;
        let plaintext = ReferenceMap::from_iter(ranges.iter_ranges().map(move |range| {
            let chunk = plaintext
                .get(pos..pos + range.len())
                .expect("length was checked");
            pos += range.len();
            (range.start, chunk)
        }));

        let mut pos = 0;
        let ciphertext = ReferenceMap::from_iter(ranges.iter_ranges().map(move |range| {
            let chunk = ciphertext
                .get(pos..pos + range.len())
                .expect("length was checked");
            pos += range.len();
            (range.start, chunk)
        }));

        Ok((plaintext, ciphertext))
    }

    fn alloc_keystream(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        ranges: &RangeSet<usize>,
    ) -> Result<Vec<Vector<U8>>, ZkAesCtrError> {
        let mut keystream = Vec::new();

        let mut range_iter = ranges.iter_ranges();
        let mut current_range = range_iter.next();
        for (pos, record) in self.records.iter_mut() {
            let pos = *pos;
            let mut current_block = None;
            loop {
                let Some(range) = current_range.take().or_else(|| range_iter.next()) else {
                    return Ok(keystream);
                };

                if range.start >= record.range.end {
                    current_range = Some(range);
                    break;
                }

                const BLOCK_SIZE: usize = 16;
                let block_num = (range.start - pos) / BLOCK_SIZE;
                let block = if let Some((current_block_num, block)) = current_block.take()
                    && current_block_num == block_num
                {
                    block
                } else {
                    let block = record.alloc_block(vm, self.key, self.iv, block_num)?;

                    current_block = Some((block_num, block));

                    block
                };

                let start = (range.start - pos) % BLOCK_SIZE;
                let end = (range.len() - start).min(BLOCK_SIZE);
                let len = end - start;

                keystream.push(block.get(start..end).expect("range is checked"));

                // If the range is larger than a block, process the tail.
                if range.len() > BLOCK_SIZE {
                    current_range = Some(range.start + len..range.end);
                }
            }
        }

        unreachable!("plaintext length was checked");
    }
}

#[derive(Debug)]
struct RecordState {
    explicit_nonce: Option<Vec<u8>>,
    range: Range<usize>,
    explicit_nonce_ref: Option<Vector<U8>>,
}

impl RecordState {
    fn alloc_explicit_nonce(
        &mut self,
        vm: &mut dyn Vm<Binary>,
    ) -> Result<Vector<U8>, ZkAesCtrError> {
        if let Some(explicit_nonce) = self.explicit_nonce_ref.clone() {
            Ok(explicit_nonce)
        } else {
            const EXPLICIT_NONCE_LEN: usize = 8;
            let explicit_nonce_ref = vm
                .alloc_vec::<U8>(EXPLICIT_NONCE_LEN)
                .map_err(ZkAesCtrError::vm)?;
            vm.mark_public(explicit_nonce_ref)
                .map_err(ZkAesCtrError::vm)?;
            vm.assign(
                explicit_nonce_ref,
                self.explicit_nonce
                    .take()
                    .expect("explicit nonce only set once"),
            )
            .map_err(ZkAesCtrError::vm)?;
            vm.commit(explicit_nonce_ref).map_err(ZkAesCtrError::vm)?;

            self.explicit_nonce_ref = Some(explicit_nonce_ref);
            Ok(explicit_nonce_ref)
        }
    }

    fn alloc_block(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        key: Array<U8, 16>,
        iv: Array<U8, 4>,
        block: usize,
    ) -> Result<Vector<U8>, ZkAesCtrError> {
        let explicit_nonce = self.alloc_explicit_nonce(vm)?;
        let ctr: Array<U8, 4> = vm.alloc().map_err(ZkAesCtrError::vm)?;
        vm.mark_public(ctr).map_err(ZkAesCtrError::vm)?;
        const START_CTR: u32 = 2;
        vm.assign(ctr, (START_CTR + block as u32).to_be_bytes())
            .map_err(ZkAesCtrError::vm)?;
        vm.commit(ctr).map_err(ZkAesCtrError::vm)?;

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
            .map_err(ZkAesCtrError::vm)?;

        Ok(Vector::from(block))
    }
}

/// Error for [`ZkAesCtr`].
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct ZkAesCtrError(#[from] ErrorRepr);

impl ZkAesCtrError {
    fn vm<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
    {
        Self(ErrorRepr::Vm(err.into()))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("zk aes error")]
enum ErrorRepr {
    #[error("vm error: {0}")]
    Vm(Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("transcript bounds exceeded: {len} > {max}")]
    TranscriptBounds { len: usize, max: usize },
}
