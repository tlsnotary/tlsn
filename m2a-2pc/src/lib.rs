//! This subcrate implements a secure two-party (2PC) multiplication-to-addition (M2A) algorithm
//! with semi-honest security.
//!
//! Let `A` be an element of some finite field with `A = a * b`, where `a` is only known to Alice
//! and `b` is only known to Bob. A is unknown to both parties and it is their goal that each of
//! them ends up with an additive share of A. So both parties start with `a` and `b` and want to
//! end up with `x` and `y`, where `A = a * b = x + y`.
//!
//! This is an implementation for the extension field GF(2^128), which uses the oblivious transfer
//! method in chapter 4.1 of <https://link.springer.com/content/pdf/10.1007/3-540-48405-1_8.pdf>

mod receiver;
mod sender;
pub use {receiver::Receiver, sender::Sender};

use thiserror::Error;

/// R is GCM polynomial in little-endian. In hex: "E1000000000000000000000000000000"
const R: u128 = 299076299051606071403356588563077529600;

/// Galois field multiplication of two 128-bit blocks reduced by the GCM polynomial
fn mul_gf2_128(mut x: u128, y: u128) -> u128 {
    let mut result: u128 = 0;
    for i in (0..128).rev() {
        result ^= x * ((y >> i) & 1);
        x = (x >> 1) ^ ((x & 1) * R);
    }
    result
}

#[derive(Debug, Error)]
pub enum M2AError {
    #[error("Choices are still missing")]
    ChoicesMissing,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghash_rc::universal_hash::NewUniversalHash;
    use ghash_rc::universal_hash::UniversalHash;
    use ghash_rc::GHash;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    fn ot_mock(envelopes: ([u128; 128], [u128; 128]), choices: u128) -> [u128; 128] {
        let mut out = [0_u128; 128];
        for (k, digit) in out.iter_mut().enumerate() {
            let mask = (choices >> k) & 1;
            *digit = (mask * envelopes.1[k]) ^ ((mask ^ 1) * envelopes.0[k]);
        }
        out
    }

    #[test]
    fn test_m2a_2pc() {
        let mut rng = ChaCha12Rng::from_entropy();
        let a: u128 = rng.gen();
        let b: u128 = rng.gen();

        let mut receiver = Receiver::new(a);
        let sender = Sender::new(b);

        let envelopes = sender.send();
        receiver.receive(ot_mock(envelopes, receiver.a()));

        assert_eq!(
            mul_gf2_128(a, b),
            sender.finalize() ^ receiver.finalize().unwrap()
        );
    }

    #[test]
    // Test multiplication against RustCrypto
    fn test_mul_gf2_128() {
        let mut rng = ChaCha12Rng::from_entropy();
        let a: u128 = rng.gen();
        let b: u128 = rng.gen();

        let mut g = GHash::new(&a.to_be_bytes().into());
        g.update(&b.to_be_bytes().into());
        // Ghash will internally multiply a and b
        let expected = g.finalize();

        assert_eq!(
            mul_gf2_128(a, b),
            u128::from_be_bytes(expected.into_bytes().try_into().unwrap())
        );
    }
}
