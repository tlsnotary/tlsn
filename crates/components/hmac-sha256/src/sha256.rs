use crate::PrfError;
use mpz_circuits::circuits::SHA256_COMPRESS;
use mpz_vm_core::{
    memory::{
        binary::{Binary, U32, U8},
        Array, MemoryExt, Vector, ViewExt,
    },
    Call, CallableExt, Vm,
};

#[derive(Debug, Default)]
pub(crate) struct Sha256 {
    state: Option<Array<U32, 8>>,
    chunks: Vec<Vector<U8>>,
    processed: u32,
}

impl Sha256 {
    const IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn set_state(&mut self, state: Array<U32, 8>) -> &mut Self {
        self.state = Some(state);
        self
    }

    pub(crate) fn set_processed(&mut self, processed: u32) -> &mut Self {
        self.processed = processed;
        self
    }

    pub(crate) fn update(&mut self, data: Vector<U8>) -> &mut Self {
        self.chunks.push(data);
        self
    }

    pub(crate) fn alloc(mut self, vm: &mut dyn Vm<Binary>) -> Result<Array<U32, 8>, PrfError> {
        assert!(
            !self.chunks.is_empty(),
            "Cannnot compute Sha256 on empty data"
        );

        let mut state = if let Some(state) = self.state {
            state
        } else {
            Self::assign_iv(vm)?
        };

        let mut remainder = None;
        let mut block: Vec<Vector<U8>> = vec![];
        let mut chunk_iter = self.chunks.iter().copied();

        loop {
            if let Some(remainder) = remainder.take() {
                block.push(remainder);
            }
            let Some(mut chunk) = chunk_iter.next() else {
                break;
            };

            let len_before: usize = block.iter().map(|b| b.len()).sum();
            let len_after = len_before + chunk.len();

            if len_after <= 64 {
                block.push(chunk);
            } else {
                let excess_len = len_after - 64;
                remainder = Some(chunk.split_off(chunk.len() - excess_len));

                block.push(chunk);
                state = Self::compute_state(vm, state, &block)?;
                block.clear();
            }
        }

        let padding = self.compute_padding(&block);
        let padding_ref: Vector<U8> = vm.alloc_vec(padding.len()).map_err(PrfError::vm)?;

        vm.mark_public(padding_ref).map_err(PrfError::vm)?;
        vm.assign(padding_ref, padding).map_err(PrfError::vm)?;
        vm.commit(padding_ref).map_err(PrfError::vm)?;

        block.push(padding_ref);
        Self::compute_state(vm, state, &block)
    }

    fn assign_iv(vm: &mut dyn Vm<Binary>) -> Result<Array<U32, 8>, PrfError> {
        let iv: Array<U32, 8> = vm.alloc().map_err(PrfError::vm)?;

        vm.mark_public(iv).map_err(PrfError::vm)?;
        vm.assign(iv, Self::IV).map_err(PrfError::vm)?;
        vm.commit(iv).map_err(PrfError::vm)?;

        Ok(iv)
    }

    fn compute_state(
        vm: &mut dyn Vm<Binary>,
        state: Array<U32, 8>,
        data: &[Vector<U8>],
    ) -> Result<Array<U32, 8>, PrfError> {
        let mut compress = Call::builder(SHA256_COMPRESS.clone()).arg(state);
        for &block in data {
            compress = compress.arg(block);
        }
        let compress = compress.build().map_err(PrfError::vm)?;

        vm.call(compress).map_err(PrfError::vm)
    }

    fn compute_padding(&mut self, block: &[Vector<U8>]) -> Vec<u8> {
        let msg_len: usize = block.iter().map(|b| b.len()).sum();
        let pos: usize = self.processed as usize;

        let bit_len = msg_len * 8;
        let processed_bit_len = (bit_len + (pos * 8)) as u64;

        // minimum length of padded message in bytes
        let min_padded_len = msg_len + 9;
        // number of 64-byte blocks rounded up
        let block_count = (min_padded_len / 64) + (min_padded_len % 64 != 0) as usize;
        // message is padded to a multiple of 64 bytes
        let padded_len = block_count * 64;
        // number of bytes to pad
        let pad_len = padded_len - msg_len;

        // append a single '1' bit
        // append K '0' bits, where K is the minimum number >= 0 such that (L + 1 + K +
        // 64) is a multiple of 512 append L as a 64-bit big-endian integer, making
        // the total post-processed length a multiple of 512 bits such that the bits
        // in the message are: <original message of length L> 1 <K zeros> <L as 64 bit
        // integer> , (the number of bits will be a multiple of 512)
        let mut padding = Vec::new();
        padding.push(128_u8);
        padding.extend((0..pad_len - 9).map(|_| 0_u8));
        padding.extend(processed_bit_len.to_be_bytes());

        padding
    }
}

/// Reference SHA256 implementation.
///
/// # Arguments
///
/// * `state` - The SHA256 state.
/// * `pos` - The number of bytes processed in the current state.
/// * `msg` - The message to hash.
pub(crate) fn sha256(mut state: [u32; 8], pos: usize, msg: &[u8]) -> [u32; 8] {
    use sha2::{
        compress256,
        digest::{
            block_buffer::{BlockBuffer, Eager},
            generic_array::typenum::U64,
        },
    };

    let mut buffer = BlockBuffer::<U64, Eager>::default();
    buffer.digest_blocks(msg, |b| compress256(&mut state, b));
    buffer.digest_pad(0x80, &(((msg.len() + pos) * 8) as u64).to_be_bytes(), |b| {
        compress256(&mut state, &[*b])
    });
    state
}
