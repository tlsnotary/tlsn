//! Helper functions for HMAC-SHA256 PRF testing.

use std::slice::from_ref;

use hmac::{
    digest::{
        block_buffer::{BlockBuffer, Eager},
        typenum::U64,
    },
    Hmac, Mac,
};

pub static SHA256_INITIAL_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub fn partial_sha256_digest(input: &[u8]) -> [u32; 8] {
    let mut state = SHA256_INITIAL_STATE.clone();
    for b in input.chunks(64) {
        let mut block = [0u8; 64];
        block[..b.len()].copy_from_slice(b);
        sha2::compress256(&mut state, &[block.into()]);
    }
    state
}

pub fn finalize_sha256_digest(mut state: [u32; 8], pos: usize, input: &[u8]) -> [u8; 32] {
    let mut buffer = BlockBuffer::<U64, Eager>::default();
    buffer.digest_blocks(input, |b| sha2::compress256(&mut state, b));
    buffer.digest_pad(
        0x80,
        &(((input.len() + pos) * 8) as u64).to_be_bytes(),
        |b| sha2::compress256(&mut state, from_ref(b)),
    );

    let mut out: [u8; 32] = [0; 32];
    for (chunk, v) in out.chunks_exact_mut(4).zip(state.iter()) {
        chunk.copy_from_slice(&v.to_be_bytes());
    }
    out
}

pub fn partial_hmac(key: &[u8]) -> ([u32; 8], [u32; 8]) {
    let mut key_opad = [0x5cu8; 64];
    let mut key_ipad = [0x36u8; 64];

    key_opad.iter_mut().zip(key).for_each(|(a, b)| *a ^= b);
    key_ipad.iter_mut().zip(key).for_each(|(a, b)| *a ^= b);

    let outer_state = partial_sha256_digest(&key_opad);
    let inner_state = partial_sha256_digest(&key_ipad);

    (outer_state, inner_state)
}

pub fn hmac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut hmac = Hmac::<sha2::Sha256>::new_from_slice(key).unwrap();
    hmac.update(msg);
    hmac.finalize().into_bytes().to_vec()
}

pub fn prf_a(key: &[u8], seed: &[u8], i: usize) -> Vec<u8> {
    (0..i).fold(seed.to_vec(), |a_prev, _| hmac(key, &a_prev))
}

fn prf_p_hash(key: &[u8], seed: &[u8], iterations: usize) -> Vec<u8> {
    (0..iterations)
        .map(|i| {
            let msg = {
                let mut msg = prf_a(key, seed, i + 1);
                msg.extend_from_slice(seed);
                msg
            };
            hmac(key, &msg)
        })
        .flatten()
        .collect()
}

pub fn prf(key: &[u8], label: &[u8], seed: &[u8], bytes: usize) -> Vec<u8> {
    let iterations = bytes / 32 + (bytes % 32 != 0) as usize;

    let mut label_seed = label.to_vec();
    label_seed.extend_from_slice(seed);

    prf_p_hash(key, &label_seed, iterations)[..bytes].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_sha2_initial_state() {
        let s = b"test string";

        // initial state for sha2
        let state = [
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

        let state = partial_sha256_digest(s);

        let s2 = b"additional data ";

        let digest = finalize_sha256_digest(state, s.len(), s2);

        let mut hasher = Sha256::new();
        hasher.update(s);
        hasher.update(s2);
        assert_eq!(digest, hasher.finalize().as_slice());
    }
}
