//! Helper functions for HMAC-SHA256 PRF testing.

use hmac::{Hmac, Mac};

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
