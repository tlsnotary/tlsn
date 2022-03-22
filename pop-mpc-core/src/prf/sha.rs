use core::slice::from_ref;
use digest::{
    block_buffer::{BlockBuffer, Eager},
    core_api::{BlockSizeUser, Buffer},
    generic_array::GenericArray,
    typenum::{U32, U64},
};
use sha2::compress256;

#[inline]
fn partial_sha256_digest(state: &mut [u32; 8], input: &[u8]) {
    if input.len() % 64 != 0 {
        panic!("input length must be a multiple of 64");
    }

    for b in input.chunks_exact(64) {
        let mut block = GenericArray::<u8, U64>::default();
        block[..].copy_from_slice(b);
        compress256(state, &[block]);
    }
}

/// Takes existing state from SHA2 hash and finishes it with additional data
#[inline]
fn finalize_sha256_digest(mut state: [u32; 8], pos: usize, input: &[u8]) -> [u8; 32] {
    let mut buffer = BlockBuffer::<U64, Eager>::new(input);
    buffer.digest_pad(0x80, &((input.len() + pos) * 8).to_be_bytes(), |b| {
        compress256(&mut state, from_ref(b))
    });

    let mut out: [u8; 32] = [0; 32];
    for (chunk, v) in out.chunks_exact_mut(4).zip(state.iter()) {
        chunk.copy_from_slice(&v.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_sha2_initial_state() {
        let s = b"test string";

        // initial state for sha2
        let mut state = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        let digest = finalize_sha256_digest(state, 0, s);

        let mut hasher = Sha256::new();
        hasher.update(s);
        assert_eq!(digest, hasher.finalize().as_slice());
    }

    #[test]
    fn test_sha2_resume_state() {
        let s = b"test string test string test string test string test string test";

        // initial state for sha2
        let mut state = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        partial_sha256_digest(&mut state, s);

        let s2 = b"additional data";

        let digest = finalize_sha256_digest(state, s.len(), s2);

        let mut hasher = Sha256::new();
        hasher.update(s);
        hasher.update(s2);
        assert_eq!(digest, hasher.finalize().as_slice());
    }
}
