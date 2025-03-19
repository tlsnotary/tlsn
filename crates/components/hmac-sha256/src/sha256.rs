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
    processed: usize,
}

impl Sha256 {
    const IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn set_state(&mut self, state: Array<U32, 8>, processed: usize) -> &mut Self {
        self.state = Some(state);
        self.processed = processed;
        self
    }

    pub(crate) fn update(&mut self, data: Vector<U8>) -> &mut Self {
        self.chunks.push(data);
        self
    }

    pub(crate) fn alloc(mut self, vm: &mut dyn Vm<Binary>) -> Result<Array<U32, 8>, PrfError> {
        let mut state = if let Some(state) = self.state {
            state
        } else {
            Self::assign_iv(vm)?
        };

        self.compute_padding(vm)?;

        // Sha256 compression function takes 64 byte blocks as inputs but our blocks in
        // `self.chunks` can have arbitrary size to simplify the api. So we need to repartition
        // them to 64 byte blocks and feed those into the compression function.
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

    fn compute_padding(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), PrfError> {
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
        Ok(())
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

pub(crate) fn convert_to_bytes(input: [u32; 8]) -> [u8; 32] {
    let mut output = [0_u8; 32];
    for (k, byte_chunk) in input.iter().enumerate() {
        let byte_chunk = byte_chunk.to_be_bytes();
        output[4 * k..4 * (k + 1)].copy_from_slice(&byte_chunk);
    }
    output
}

#[cfg(test)]
mod tests {
    use crate::sha256::{convert_to_bytes, sha256, Sha256};
    use mpz_common::context::test_st_context;
    use mpz_garble::protocol::semihonest::{Evaluator, Garbler};
    use mpz_ot::ideal::cot::{ideal_cot, IdealCOTReceiver, IdealCOTSender};
    use mpz_vm_core::{
        memory::{
            binary::{U32, U8},
            correlated::Delta,
            Array, MemoryExt, Vector, ViewExt,
        },
        Execute,
    };
    use rand::{rngs::StdRng, SeedableRng};

    #[tokio::test]
    async fn test_sha256_circuit() {
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut generator, mut evaluator) = mock_vm();

        let (test_iter, expected_iter) = test_fixtures();
        for (test, expected) in test_iter.zip(expected_iter) {
            let input_ref_gen: Vector<U8> = generator.alloc_vec(test.len()).unwrap();
            generator.mark_public(input_ref_gen).unwrap();
            generator.assign(input_ref_gen, test.clone()).unwrap();
            generator.commit(input_ref_gen).unwrap();

            let mut sha_gen = Sha256::new();
            sha_gen.update(input_ref_gen);
            let sha_out_gen = sha_gen.alloc(&mut generator).unwrap();
            let sha_out_gen = generator.decode(sha_out_gen).unwrap();

            let input_ref_ev: Vector<U8> = evaluator.alloc_vec(test.len()).unwrap();
            evaluator.mark_public(input_ref_ev).unwrap();
            evaluator.assign(input_ref_ev, test).unwrap();
            evaluator.commit(input_ref_ev).unwrap();

            let mut sha_ev = Sha256::new();
            sha_ev.update(input_ref_ev);
            let sha_out_ev = sha_ev.alloc(&mut evaluator).unwrap();
            let sha_out_ev = evaluator.decode(sha_out_ev).unwrap();

            let (sha_gen, sha_ev) = tokio::try_join!(
                async {
                    generator.execute_all(&mut ctx_a).await.unwrap();
                    sha_out_gen.await
                },
                async {
                    evaluator.execute_all(&mut ctx_b).await.unwrap();
                    sha_out_ev.await
                }
            )
            .unwrap();

            assert_eq!(sha_gen, sha_ev);
            assert_eq!(convert_to_bytes(sha_gen), expected);
        }
    }

    #[tokio::test]
    async fn test_sha256_circuit_set_state() {
        let skip = 2;
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut generator, mut evaluator) = mock_vm();

        let (test_iter, expected_iter) = test_fixtures();
        for (test, expected) in test_iter.zip(expected_iter) {
            let state = compress_256(Sha256::IV, &test[..skip]);
            let test = test[skip..].to_vec();

            let input_ref_gen: Vector<U8> = generator.alloc_vec(test.len()).unwrap();
            generator.mark_public(input_ref_gen).unwrap();
            generator.assign(input_ref_gen, test.clone()).unwrap();
            generator.commit(input_ref_gen).unwrap();

            let state_ref_gen: Array<U32, 8> = generator.alloc().unwrap();
            generator.mark_public(state_ref_gen).unwrap();
            generator.assign(state_ref_gen, state).unwrap();
            generator.commit(state_ref_gen).unwrap();

            let mut sha_gen = Sha256::new();
            sha_gen.set_state(state_ref_gen, skip).update(input_ref_gen);
            let sha_out_gen = sha_gen.alloc(&mut generator).unwrap();
            let sha_out_gen = generator.decode(sha_out_gen).unwrap();

            let input_ref_ev: Vector<U8> = evaluator.alloc_vec(test.len()).unwrap();
            evaluator.mark_public(input_ref_ev).unwrap();
            evaluator.assign(input_ref_ev, test).unwrap();
            evaluator.commit(input_ref_ev).unwrap();

            let state_ref_ev: Array<U32, 8> = evaluator.alloc().unwrap();
            evaluator.mark_public(state_ref_ev).unwrap();
            evaluator.assign(state_ref_ev, state).unwrap();
            evaluator.commit(state_ref_ev).unwrap();

            let mut sha_ev = Sha256::new();
            sha_ev.set_state(state_ref_ev, skip).update(input_ref_ev);
            let sha_out_ev = sha_ev.alloc(&mut evaluator).unwrap();
            let sha_out_ev = evaluator.decode(sha_out_ev).unwrap();

            let (sha_gen, sha_ev) = tokio::try_join!(
                async {
                    generator.execute_all(&mut ctx_a).await.unwrap();
                    sha_out_gen.await
                },
                async {
                    evaluator.execute_all(&mut ctx_b).await.unwrap();
                    sha_out_ev.await
                }
            )
            .unwrap();

            assert_eq!(sha_gen, sha_ev);
            assert_eq!(convert_to_bytes(sha_gen), expected);
        }
    }

    #[test]
    fn test_sha256_reference() {
        let (test_iter, expected_iter) = test_fixtures();
        for (test, expected) in test_iter.zip(expected_iter) {
            let sha = sha256(Sha256::IV, 0, &test);
            assert_eq!(convert_to_bytes(sha), expected);
        }
    }

    #[test]
    fn test_sha256_reference_set_state() {
        let skip = 2;
        let (test_iter, expected_iter) = test_fixtures();
        for (test, expected) in test_iter.zip(expected_iter) {
            let state = compress_256(Sha256::IV, &test[..skip]);
            let test = test[skip..].to_vec();

            let sha = sha256(state, skip, &test);
            assert_eq!(convert_to_bytes(sha), expected);
        }
    }

    fn mock_vm() -> (Garbler<IdealCOTSender>, Evaluator<IdealCOTReceiver>) {
        let mut rng = StdRng::seed_from_u64(0);
        let delta = Delta::random(&mut rng);

        let (cot_send, cot_recv) = ideal_cot(delta.into_inner());

        let gen = Garbler::new(cot_send, [0u8; 16], delta);
        let ev = Evaluator::new(cot_recv);

        (gen, ev)
    }

    fn test_fixtures() -> (
        impl Iterator<Item = Vec<u8>>,
        impl Iterator<Item = [u8; 32]>,
    ) {
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

        (test_vectors.into_iter(), expected.into_iter())
    }

    fn compress_256(mut state: [u32; 8], msg: &[u8]) -> [u32; 8] {
        use sha2::{
            compress256,
            digest::{
                block_buffer::{BlockBuffer, Eager},
                generic_array::typenum::U64,
            },
        };

        let mut buffer = BlockBuffer::<U64, Eager>::default();
        buffer.digest_blocks(msg, |b| compress256(&mut state, b));
        state
    }
}
