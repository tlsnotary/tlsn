//! Computation of SHA256.

use crate::PrfError;
use mpz_circuits::circuits::SHA256_COMPRESS;
use mpz_vm_core::{
    memory::{
        binary::{Binary, U32, U8},
        Array, MemoryExt, Vector, ViewExt,
    },
    Call, CallableExt, Vm,
};

/// Computes SHA256.
#[derive(Debug, Default)]
pub(crate) struct Sha256 {
    state: Option<Array<U32, 8>>,
    chunks: Vec<Vector<U8>>,
    processed: usize,
}

impl Sha256 {
    /// The default initialization vector.
    const IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    /// Sets the state.
    ///
    /// # Arguments
    ///
    /// * `state` - The starting state for the SHA256 compression function.
    /// * `processed` - The number of already processed bytes corresponding to
    ///   `state`.
    pub(crate) fn set_state(&mut self, state: Array<U32, 8>, processed: usize) -> &mut Self {
        self.state = Some(state);
        self.processed = processed;
        self
    }

    /// Feeds data into the hash function.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to hash.
    pub(crate) fn update(&mut self, data: Vector<U8>) -> &mut Self {
        self.chunks.push(data);
        self
    }

    /// Computes the padding for SHA256.
    ///
    /// Padding is computed depending on [`Self::state`] and
    /// [`Self::processed`].
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine.
    pub(crate) fn add_padding(&mut self, vm: &mut dyn Vm<Binary>) -> Result<&mut Self, PrfError> {
        let msg_len: usize = self.chunks.iter().map(|b| b.len()).sum();
        let pos = self.processed;

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

        let padding_ref: Vector<U8> = vm.alloc_vec(padding.len()).map_err(PrfError::vm)?;

        vm.mark_public(padding_ref).map_err(PrfError::vm)?;
        vm.assign(padding_ref, padding).map_err(PrfError::vm)?;
        vm.commit(padding_ref).map_err(PrfError::vm)?;

        self.chunks.push(padding_ref);
        Ok(self)
    }

    /// Adds the [`Call`] to the [`Vm`], and returns the output.
    ///
    /// # Arguments
    ///
    /// * `vm` - The virtual machine.
    pub(crate) fn alloc(self, vm: &mut dyn Vm<Binary>) -> Result<Array<U32, 8>, PrfError> {
        let mut state = if let Some(state) = self.state {
            state
        } else {
            Self::assign_iv(vm)?
        };

        // SHA256 compression function takes 64 byte blocks as inputs but our blocks in
        // `self.chunks` can have arbitrary size to simplify the api. So we need to
        // repartition them to 64 byte blocks and feed those into the
        // compression function.
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
        let mut compress = Call::builder(SHA256_COMPRESS.clone());

        for &block in data {
            compress = compress.arg(block);
        }

        let compress = compress.arg(state).build().map_err(PrfError::vm)?;
        vm.call(compress).map_err(PrfError::vm)
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

#[cfg(test)]
mod tests {
    use crate::{
        convert_to_bytes,
        sha256::{sha256, Sha256},
        test_utils::{compress_256, mock_vm},
    };
    use mpz_common::context::test_st_context;
    use mpz_vm_core::{
        memory::{
            binary::{U32, U8},
            Array, MemoryExt, Vector, ViewExt,
        },
        Execute,
    };

    #[tokio::test]
    async fn test_sha256_circuit() {
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut leader, mut follower) = mock_vm();

        let (inputs, references) = test_fixtures();
        for (input, &reference) in inputs.iter().zip(references.iter()) {
            let input_leader: Vector<U8> = leader.alloc_vec(input.len()).unwrap();
            leader.mark_public(input_leader).unwrap();
            leader.assign(input_leader, input.clone()).unwrap();
            leader.commit(input_leader).unwrap();

            let mut sha_leader = Sha256::default();
            sha_leader
                .update(input_leader)
                .add_padding(&mut leader)
                .unwrap();
            let sha_out_leader = sha_leader.alloc(&mut leader).unwrap();
            let sha_out_leader = leader.decode(sha_out_leader).unwrap();

            let input_follower: Vector<U8> = follower.alloc_vec(input.len()).unwrap();
            follower.mark_public(input_follower).unwrap();
            follower.assign(input_follower, input.clone()).unwrap();
            follower.commit(input_follower).unwrap();

            let mut sha_follower = Sha256::default();
            sha_follower
                .update(input_follower)
                .add_padding(&mut follower)
                .unwrap();
            let sha_out_follower = sha_follower.alloc(&mut follower).unwrap();
            let sha_out_follower = follower.decode(sha_out_follower).unwrap();

            let (sha_out_leader, sha_out_follower) = tokio::try_join!(
                async {
                    leader.execute_all(&mut ctx_a).await.unwrap();
                    sha_out_leader.await
                },
                async {
                    follower.execute_all(&mut ctx_b).await.unwrap();
                    sha_out_follower.await
                }
            )
            .unwrap();

            assert_eq!(sha_out_leader, sha_out_follower);
            assert_eq!(convert_to_bytes(sha_out_leader), reference);
        }
    }

    #[tokio::test]
    async fn test_sha256_circuit_set_state() {
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut leader, mut follower) = mock_vm();

        let (inputs, references) = test_fixtures();

        // only take 3rd example because we need minimum 64 bits.
        let input = &inputs[2];
        let reference = references[2];

        // This has to be 64 bytes, because the sha256 compression function operates on
        // 64 byte blocks.
        let skip = 64;

        let state = compress_256(Sha256::IV, &input[..skip]);
        let test = input[skip..].to_vec();

        let input_leader: Vector<U8> = leader.alloc_vec(test.len()).unwrap();
        leader.mark_public(input_leader).unwrap();
        leader.assign(input_leader, test.clone()).unwrap();
        leader.commit(input_leader).unwrap();

        let state_leader: Array<U32, 8> = leader.alloc().unwrap();
        leader.mark_public(state_leader).unwrap();
        leader.assign(state_leader, state).unwrap();
        leader.commit(state_leader).unwrap();

        let mut sha_leader = Sha256::default();
        sha_leader
            .set_state(state_leader, skip)
            .update(input_leader)
            .add_padding(&mut leader)
            .unwrap();
        let sha_out_leader = sha_leader.alloc(&mut leader).unwrap();
        let sha_out_leader = leader.decode(sha_out_leader).unwrap();

        let input_follower: Vector<U8> = follower.alloc_vec(test.len()).unwrap();
        follower.mark_public(input_follower).unwrap();
        follower.assign(input_follower, test).unwrap();
        follower.commit(input_follower).unwrap();

        let state_follower: Array<U32, 8> = follower.alloc().unwrap();
        follower.mark_public(state_follower).unwrap();
        follower.assign(state_follower, state).unwrap();
        follower.commit(state_follower).unwrap();

        let mut sha_follower = Sha256::default();
        sha_follower
            .set_state(state_follower, skip)
            .update(input_follower)
            .add_padding(&mut follower)
            .unwrap();
        let sha_out_follower = sha_follower.alloc(&mut follower).unwrap();
        let sha_out_follower = follower.decode(sha_out_follower).unwrap();

        let (sha_out_leader, sha_out_follower) = tokio::try_join!(
            async {
                leader.execute_all(&mut ctx_a).await.unwrap();
                sha_out_leader.await
            },
            async {
                follower.execute_all(&mut ctx_b).await.unwrap();
                sha_out_follower.await
            }
        )
        .unwrap();

        assert_eq!(sha_out_leader, sha_out_follower);
        assert_eq!(convert_to_bytes(sha_out_leader), reference);
    }

    #[test]
    fn test_sha256_reference() {
        let (inputs, references) = test_fixtures();
        for (input, &reference) in inputs.iter().zip(references.iter()) {
            let sha = sha256(Sha256::IV, 0, input);
            assert_eq!(convert_to_bytes(sha), reference);
        }
    }

    #[test]
    fn test_sha256_reference_set_state() {
        let (inputs, references) = test_fixtures();

        // only take 3rd example because we need minimum 64 bits.
        let input = &inputs[2];
        let reference = references[2];

        // This has to be 64 bytes, because the sha256 compression function operates on
        // 64 byte blocks.
        let skip = 64;

        let state = compress_256(Sha256::IV, &input[..skip]);
        let test = input[skip..].to_vec();

        let sha = sha256(state, skip, &test);
        assert_eq!(convert_to_bytes(sha), reference);
    }

    fn test_fixtures() -> (Vec<Vec<u8>>, Vec<[u8; 32]>) {
        let test_vectors: Vec<Vec<u8>> = vec![
            b"abc".to_vec(),
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".to_vec(),
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".to_vec()
        ];
        let expected: Vec<[u8; 32]> = vec![
            hex::decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
                .unwrap()
                .try_into()
                .unwrap(),
            hex::decode("cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1")
                .unwrap()
                .try_into()
                .unwrap(),
        ];

        (test_vectors, expected)
    }
}
