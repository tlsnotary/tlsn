//! This module provides the share-conversion algorithms inside the module `conversion` for
//! elements of GF(2^128), as well as some arithmetic functions for these field elements.

mod conversion;

pub use conversion::{AddShare, Gf2_128ShareConvert, MulShare, OTEnvelope};

/// R is the GCM polynomial in little-endian. In hex: "E1000000000000000000000000000000"
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

/// Iteratively multiplies some field element with another field element
///
/// This function multiplies the last element in `powers` with some other field element `factor`
/// and appends the result to `powers`. This process is repeated `count` times.
///
/// * `powers` - The vector to which the new higher powers get pushed
/// * `factor` - The field element with which the last element of the vector is multiplied
/// * `count` - How many products are computed
pub fn compute_product_repeated(powers: &mut Vec<u128>, factor: u128, count: usize) {
    for _ in 0..count {
        let last_power = *powers
            .last()
            .expect("Vector is empty. Cannot compute higher powers");
        powers.push(mul(factor, last_power));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghash_rc::{
        universal_hash::{NewUniversalHash, UniversalHash},
        GHash,
    };
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    #[test]
    // Test multiplication against RustCrypto
    fn test_mul() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
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
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let a: u128 = rng.gen();
        let inverse_a = inverse(a);

        assert_eq!(mul(a, inverse_a), 1_u128 << 127);
        assert_eq!(inverse(1_u128 << 127), 1_u128 << 127);
    }

    #[test]
    fn test_compute_product_repeated() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let a: u128 = rng.gen();

        let mut powers = vec![a];
        let factor = mul(a, a);

        compute_product_repeated(&mut powers, factor, 2);

        assert_eq!(powers[0], a);
        assert_eq!(powers[1], mul(powers[0], factor));
        assert_eq!(powers[2], mul(powers[1], factor));
    }
}
