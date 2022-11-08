//! This subcrate implements secure two-party (2PC) multiplication-to-addition (M2A) and
//! addition-to-multiplication (A2M) algorithms, both with semi-honest security for elements
//! of GF(2^128).
//!
//! ### M2A algorithm
//! Let `A` be an element of some finite field with `A = a * b`, where `a` is only known to Alice
//! and `b` is only known to Bob. A is unknown to both parties and it is their goal that each of
//! them ends up with an additive share of A. So both parties start with `a` and `b` and want to
//! end up with `x` and `y`, where `A = a * b = x + y`.
//!
//! This is an implementation for the extension field GF(2^128), which uses the oblivious transfer
//! method in chapter 4.1 of <https://link.springer.com/content/pdf/10.1007/3-540-48405-1_8.pdf>
//!
//! ### A2M algorithm
//! This is the other way round.
//! Let `A` be an element of some finite field with `A = x + y`, where `x` is only known to Alice
//! and `y` is only known to Bob. A is unknown to both parties and it is their goal that each of
//! them ends up with a multiplicative share of A. So both parties start with `x` and `y` and want to
//! end up with `a` and `b`, where `A = x + y = a * b`.
//!
//! This is an implementation for the extension field GF(2^128), which is a semi-honest adaptation
//! of the "A2M Protocol" in chapter 4 of <https://www.cs.umd.edu/~fenghao/paper/modexp.pdf>

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

/// Masked values for an oblivious transfer
#[derive(Clone, Copy, Debug)]
pub struct MaskedPartialValue(pub [u128; 128], pub [u128; 128]);

/// A multiplicative share of `A = a * b`
#[derive(Clone, Copy, Debug)]
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

    /// Turn into an additive share and masked partial values
    ///
    /// This function returns
    ///   * `AddShare` - The sender's additive share; this is `y` in the paper
    ///   * `MaskedPartialValue` - Used for oblivious transfer; t0 and t1 in the paper
    pub fn to_additive(&self) -> (AddShare, MaskedPartialValue) {
        let mut rng = ChaCha12Rng::from_entropy();

        let t0: [u128; 128] = std::array::from_fn(|_| rng.gen());
        let t1: [u128; 128] = std::array::from_fn(|i| mul(self.inner(), 1 << i) ^ t0[i]);

        let add_share = AddShare::new(t0.into_iter().fold(0, |acc, i| acc ^ i));
        (add_share, MaskedPartialValue(t0, t1))
    }

    /// Create a multiplicative share from the output of an OT
    ///
    /// The `value` needs to be built by choices of an oblivious transfer
    pub fn from_choice(value: [u128; 128]) -> Self {
        Self::new(value.into_iter().fold(0, |acc, i| acc ^ i))
    }
}

/// An additive share of `A = x + y`
#[derive(Clone, Copy, Debug)]
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

    /// Turn into a multiplicative share and masked partial values
    ///
    /// This function returns
    ///   * `MulShare` - The sender's multiplicative share
    ///   * `MaskedPartialValue` - Used for oblivious transfer
    pub fn to_multiplicative(&self) -> (MulShare, MaskedPartialValue) {
        let mut rng = ChaCha12Rng::from_entropy();

        let random: u128 = rng.gen();
        if random == 0 {
            panic!("Random u128 is 0");
        }

        let mut masks: [u128; 128] = std::array::from_fn(|_| rng.gen());
        // set the last mask such that the sum of all 128 masks equals 0
        masks[127] = masks.into_iter().take(127).fold(0, |acc, i| acc ^ i);

        let mul_share = MulShare::new(inverse(random));

        // `self.inner() & (1 << i)` extracts bit of `self.inner()` in position `i` (counting from
        // the right) shifted left by `i`
        let b0: [u128; 128] =
            std::array::from_fn(|i| mul(self.inner() & (1 << i), random) ^ masks[i]);
        let b1: [u128; 128] =
            std::array::from_fn(|i| mul((self.inner() & (1 << i)) ^ (1 << i), random) ^ masks[i]);

        (mul_share, MaskedPartialValue(b0, b1))
    }

    /// Create an additive share from the output of an OT
    ///
    /// The `value` needs to be built by choices of an oblivious transfer
    pub fn from_choice(value: [u128; 128]) -> Self {
        Self::new(value.into_iter().fold(0, |acc, i| acc ^ i))
    }
}

/// R is GCM polynomial in little-endian. In hex: "E1000000000000000000000000000000"
const R: u128 = 299076299051606071403356588563077529600;

/// Galois field multiplication of two 128-bit blocks reduced by the GCM polynomial
pub fn mul(mut x: u128, y: u128) -> u128 {
    let mut result: u128 = 0;
    for i in (0..128).rev() {
        result ^= x * ((y >> i) & 1);
        x = (x >> 1) ^ ((x & 1) * R);
    }
    result
}

/// Galois field inversion of 128-bit block
pub fn inverse(mut x: u128) -> u128 {
    let one = 1 << 127;
    let mut out = one;

    for _ in 0..127 {
        x = mul(x, x);
        out = mul(out, x);
    }
    out
}

/// Compute powers of some field element
///
/// This function computes `missing` higher powers and pushes it to some vector. So what you
/// get is a vector of [a, a^2, a^3, ...] This function assumes that `powers[1] == a` is present,
/// as it is needed for exponentiation
///
/// * `powers` - The vector to which the new higher powers get pushed
/// * `missing` - How many more higher powers are needed
pub fn compute_higher_powers(powers: &mut Vec<u128>, missing: usize) {
    for _ in 0..missing {
        let last_power = *powers.last().expect("Vector is empty");
        let base = *powers
            .get(1)
            .expect("Vector does not contain a base for exponentiation");
        powers.push(mul(base, last_power));
    }
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
    fn test_m2a() {
        let mut rng = ChaCha12Rng::from_entropy();
        let a: MulShare = MulShare::new(rng.gen());
        let b: MulShare = MulShare::new(rng.gen());

        let (x, MaskedPartialValue(t0, t1)) = a.to_additive();

        let choice = ot_mock((t0, t1), b.inner());
        let y = AddShare::from_choice(choice);

        assert_eq!(mul(a.inner(), b.inner()), x.inner() ^ y.inner());
    }

    #[test]
    fn test_a2m() {
        let mut rng = ChaCha12Rng::from_entropy();
        let x: AddShare = AddShare::new(rng.gen());
        let y: AddShare = AddShare::new(rng.gen());

        let (a, MaskedPartialValue(t0, t1)) = x.to_multiplicative();

        let choice = ot_mock((t0, t1), y.inner());
        let b = MulShare::from_choice(choice);

        assert_eq!(x.inner() ^ y.inner(), mul(a.inner(), b.inner()));
    }

    #[test]
    // Test multiplication against RustCrypto
    fn test_mul() {
        let mut rng = ChaCha12Rng::from_entropy();
        let a: u128 = rng.gen();
        let b: u128 = rng.gen();

        let mut g = GHash::new(&a.to_be_bytes().into());
        g.update(&b.to_be_bytes().into());
        // Ghash will internally multiply a and b
        let expected = g.finalize();

        assert_eq!(
            mul(a, b),
            u128::from_be_bytes(expected.into_bytes().try_into().unwrap())
        );
    }

    #[test]
    fn test_inverse() {
        let mut rng = ChaCha12Rng::from_entropy();
        let a: u128 = rng.gen();
        let inverse_a = inverse(a);

        assert_eq!(mul(a, inverse_a), 1_u128 << 127);
        assert_eq!(inverse(1_u128 << 127), 1_u128 << 127);
    }

    #[test]
    fn test_compute_powers() {
        let mut rng = ChaCha12Rng::from_entropy();
        let a: u128 = rng.gen();

        let mut powers = vec![1 << 127, a];

        compute_higher_powers(&mut powers, 4);

        assert_eq!(powers[0], 1 << 127);
        assert_eq!(powers[1], a);
        assert_eq!(powers[2], mul(a, a));
        assert_eq!(powers[3], mul(powers[2], powers[1]));
    }
}
