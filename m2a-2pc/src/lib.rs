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

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

/// Encodes masked values for an oblivious transfer
pub struct MaskedEncoding(pub [u128; 128], pub [u128; 128]);

/// A multiplicative share of `A = a * b`
pub struct MulShare(u128);

impl MulShare {
    /// Create a new `MulShare` holding a factor of `A`
    pub fn new(share: u128) -> Self {
        Self(share)
    }

    /// Return inner share
    pub fn inner(&self) -> u128 {
        self.0
    }

    /// Turn into an additive share and masked encodings
    ///
    /// This function returns
    ///   * `AddShare` - The sender's additive share; this is `y` in the paper
    ///   * `MaskedEncoding` - Used for oblivious transfer; t0 and t1 in the paper
    pub fn to_additive(&self) -> (AddShare, MaskedEncoding) {
        let mut rng = ChaCha12Rng::from_entropy();

        let t0: [u128; 128] = std::array::from_fn(|_| rng.gen());
        let t1: [u128; 128] = std::array::from_fn(|i| mul_gf2_128(self.inner(), 1 << i) ^ t0[i]);

        let add_share = AddShare::new(t0.into_iter().fold(0, |acc, i| acc ^ i));
        (add_share, MaskedEncoding(t0, t1))
    }
}

/// An additive share of `A = x + y`
pub struct AddShare(u128);

impl AddShare {
    /// Create a new `AddShare` holding a summand of `A`
    pub fn new(share: u128) -> Self {
        Self(share)
    }

    /// Return inner share
    pub fn inner(&self) -> u128 {
        self.0
    }

    /// Create an additive share from the output of an OT
    ///
    /// The `value` needs to be built by choices of an oblivious transfer
    pub fn from_encoding(value: [u128; 128]) -> Self {
        Self::new(value.into_iter().fold(0, |acc, i| acc ^ i))
    }
}

/// R is GCM polynomial in little-endian. In hex: "E1000000000000000000000000000000"
const R: u128 = 299076299051606071403356588563077529600;

/// Galois field multiplication of two 128-bit blocks reduced by the GCM polynomial
pub fn mul_gf2_128(mut x: u128, y: u128) -> u128 {
    let mut result: u128 = 0;
    for i in (0..128).rev() {
        result ^= x * ((y >> i) & 1);
        x = (x >> 1) ^ ((x & 1) * R);
    }
    result
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
        for (k, number) in out.iter_mut().enumerate() {
            let bit = (choices >> k) & 1;
            *number = (bit * envelopes.1[k]) ^ ((bit ^ 1) * envelopes.0[k]);
        }
        out
    }

    #[test]
    fn test_m2a_2pc() {
        let mut rng = ChaCha12Rng::from_entropy();
        let a: MulShare = MulShare::new(rng.gen());
        let b: MulShare = MulShare::new(rng.gen());

        let (x, MaskedEncoding(t0, t1)) = a.to_additive();

        let choices = ot_mock((t0, t1), b.inner());
        let y = AddShare::from_encoding(choices);

        assert_eq!(mul_gf2_128(a.inner(), b.inner()), x.inner() ^ y.inner());
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
