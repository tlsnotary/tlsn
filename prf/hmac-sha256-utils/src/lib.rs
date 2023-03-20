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
    let mut state = SHA256_INITIAL_STATE;
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
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};

    type HmacSha256 = Hmac<Sha256>;

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

    #[test]
    fn test_partial_hmac() {
        let key = [42u8; 32];
        let msg = b"test string";
        let (outer_state, inner_state) = partial_hmac(&key);

        let hmac = finalize_sha256_digest(
            outer_state,
            64,
            finalize_sha256_digest(inner_state, 64, msg).as_slice(),
        );

        let expected_hmac: [u8; 32] = {
            let mut hmac = HmacSha256::new_from_slice(&key).unwrap();
            hmac.update(msg);
            hmac.finalize().into_bytes().into()
        };

        assert_eq!(hmac, expected_hmac);
    }

    #[test]
    fn test_hmac() {
        let key = [42u8; 32];
        let msg = b"test string";

        let hmac = hmac(&key, msg);

        let expected_hmac = {
            let mut hmac = HmacSha256::new_from_slice(&key).unwrap();
            hmac.update(msg);
            hmac.finalize().into_bytes().to_vec()
        };

        assert_eq!(hmac, expected_hmac);
    }

    #[test]
    fn test_prf() {
        let key = [42u8; 32];
        let seed = [69u8; 64];
        let label = b"test label";

        let output = prf(&key, label, &seed, 32);

        let mut expected_output = [0u8; 32];
        ring_prf::prf(&mut expected_output, &key, label, &seed);

        assert_eq!(output, expected_output);
    }

    // Borrowed from Rustls for testing (we don't want ring as a dependency)
    // https://github.com/rustls/rustls/blob/main/rustls/src/tls12/prf.rs
    mod ring_prf {
        use ring::{hmac, hmac::HMAC_SHA256};

        fn concat_sign(key: &hmac::Key, a: &[u8], b: &[u8]) -> hmac::Tag {
            let mut ctx = hmac::Context::with_key(key);
            ctx.update(a);
            ctx.update(b);
            ctx.sign()
        }

        fn p(out: &mut [u8], secret: &[u8], seed: &[u8]) {
            let hmac_key = hmac::Key::new(HMAC_SHA256, secret);

            // A(1)
            let mut current_a = hmac::sign(&hmac_key, seed);
            let chunk_size = HMAC_SHA256.digest_algorithm().output_len;
            for chunk in out.chunks_mut(chunk_size) {
                // P_hash[i] = HMAC_hash(secret, A(i) + seed)
                let p_term = concat_sign(&hmac_key, current_a.as_ref(), seed);
                chunk.copy_from_slice(&p_term.as_ref()[..chunk.len()]);

                // A(i+1) = HMAC_hash(secret, A(i))
                current_a = hmac::sign(&hmac_key, current_a.as_ref());
            }
        }

        fn concat(a: &[u8], b: &[u8]) -> Vec<u8> {
            let mut ret = Vec::new();
            ret.extend_from_slice(a);
            ret.extend_from_slice(b);
            ret
        }

        pub fn prf(out: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]) {
            let joined_seed = concat(label, seed);
            p(out, secret, &joined_seed);
        }
    }
}
