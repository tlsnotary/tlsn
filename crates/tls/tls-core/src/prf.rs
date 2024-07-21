//! Implementation of the TLS Pseudo-Random Function (PRF) as defined in RFC 5246.

use hmac::Mac;

type Hmac = hmac::Hmac<sha2::Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("invalid prf key length")]
pub struct InvalidKeyLength;

/// Fills the given buffer with the output of the TLS PRF.
///
/// # Arguments
///
/// * `out` - The buffer to fill with the output.
/// * `secret` - prf secret.
/// * `label` - prf label, e.g. "master secret".
/// * `seed` - prf seed, e.g. client_random + server_random.
pub fn prf(
    out: &mut [u8],
    secret: &[u8],
    label: &[u8],
    seed: &[u8],
) -> Result<(), InvalidKeyLength> {
    let keyed_hmac = Hmac::new_from_slice(secret).map_err(|_| InvalidKeyLength)?;

    let mut current_a = keyed_hmac.clone();
    current_a.update(label);
    current_a.update(seed);

    for chunk in out.chunks_mut(32) {
        let a = std::mem::replace(&mut current_a, keyed_hmac.clone())
            .finalize()
            .into_bytes();

        // P_hash[i] = HMAC_hash(secret, A(i) + seed)
        let mut p_term = keyed_hmac.clone();
        p_term.update(&a);
        p_term.update(label);
        p_term.update(seed);

        chunk.copy_from_slice(&p_term.finalize().into_bytes()[..chunk.len()]);

        // A(i+1) = HMAC_hash(secret, A(i))
        current_a.update(&a);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prf() {
        let secret = [42u8; 48];
        let seed = [69u8; 64];
        let label = b"master secret";

        let mut out = [0u8; 48];
        prf(&mut out, &secret, label, &seed).unwrap();

        let mut ring_out = [0u8; 48];
        ring_prf::prf(&mut ring_out, &secret, label, &seed);

        assert_eq!(out, ring_out);
    }

    // Borrowed from Rustls for testing
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
            let chunk_size = HMAC_SHA256.digest_algorithm().output_len();
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

        pub(crate) fn prf(out: &mut [u8], secret: &[u8], label: &[u8], seed: &[u8]) {
            let joined_seed = concat(label, seed);
            p(out, secret, &joined_seed);
        }
    }
}
