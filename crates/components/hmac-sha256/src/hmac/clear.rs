//! Computation of HMAC-SHA256 on cleartext values.
use crate::{
    compress_256,
    hmac::{IPAD, OPAD, SHA256_IV},
    sha256, state_to_bytes,
};

/// Depending on the provided `mask` computes and returns outer_partial or
/// inner_partial for HMAC-SHA256.
fn compute_partial(key: &[u8], mask: &[u8; 64]) -> [u32; 8] {
    assert!(key.len() <= 64);
    let mut key = key.to_vec();

    key.resize(64, 0_u8);
    let key_padded: [u8; 64] = key
        .into_iter()
        .zip(mask)
        .map(|(b, mask)| b ^ mask)
        .collect::<Vec<u8>>()
        .try_into()
        .expect("output length is 64 bytes");

    compress_256(SHA256_IV, &key_padded)
}

/// Computes and returns inner_partial for HMAC-SHA256.
pub(crate) fn compute_inner_partial(key: &[u8]) -> [u32; 8] {
    compute_partial(key, &IPAD)
}

/// Computes and returns outer_partial for HMAC-SHA256.
pub(crate) fn compute_outer_partial(key: &[u8]) -> [u32; 8] {
    compute_partial(key, &OPAD)
}

/// Computes and returns inner_local for HMAC-SHA256.
fn compute_inner_local(key: &[u8], msg: &[u8]) -> [u32; 8] {
    sha256(compute_inner_partial(key), 64, msg)
}

/// Computes and returns the HMAC-SHA256 output.
pub(crate) fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let outer_partial = compute_outer_partial(key);
    let inner_local = compute_inner_local(key, msg);

    let hmac = sha256(outer_partial, 64, &state_to_bytes(inner_local));
    state_to_bytes(hmac)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use sha2::Sha256;

    #[test]
    fn test_hmac_sha256() {
        let mut rng = StdRng::from_seed([1; 32]);

        for _ in 0..10 {
            let key: [u8; 32] = rng.random();
            let msg: [u8; 32] = rng.random();

            let mut mac =
                Hmac::<Sha256>::new_from_slice(&key).expect("HMAC can take key of any size");
            mac.update(&msg);

            assert_eq!(hmac_sha256(&key, &msg), *mac.finalize().into_bytes())
        }
    }
}
