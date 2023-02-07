pub mod gf2_128;
pub mod p256;

use rand::{distributions::Standard, prelude::Distribution, Rng};
use std::{
    fmt::Debug,
    ops::{Add, Mul, Neg},
};

// A trait for finite fields
pub trait Field:
    Add<Output = Self>
    + Mul<Output = Self>
    + Neg<Output = Self>
    + Copy
    + Clone
    + Debug
    + 'static
    + Send
    + Sync
    + UniformRand
    + PartialOrd
    + Ord
    + PartialEq
    + Eq
{
    const BIT_SIZE: u32;

    // Return the additive neutral element
    fn zero() -> Self;

    // Return the multiplicative neutral element
    fn one() -> Self;

    // Return 2^rhs
    fn two_pow(rhs: u32) -> Self;

    // Return the n-th bit big-endian
    fn get_bit_be(&self, n: u32) -> bool;

    // Return the multiplicative inverse
    fn inverse(self) -> Self;

    // Create a field element from bits in big-endian
    fn from_bits_be(bits: &[bool]) -> Self;
}

// A trait for sampling random elements of the field
//
// This is helpful, because we do not need to import other traits since this is a supertrait of
// field (which is not possible with `Standard` and `Distribution`)
pub trait UniformRand: Sized {
    // Return a random field element
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self;
}

impl<T> UniformRand for T
where
    Standard: Distribution<T>,
{
    #[inline]
    fn rand<R: Rng + ?Sized>(rng: &mut R) -> Self {
        rng.sample(Standard)
    }
}

/// Iteratively multiplies some field element with another field element
///
/// This function multiplies the last element in `powers` with some other field element `factor`
/// and appends the result to `powers`. This process is repeated `count` times.
///
/// * `powers` - The vector to which the new higher powers get pushed
/// * `factor` - The field element with which the last element of the vector is multiplied
/// * `count` - How many products are computed
pub fn compute_product_repeated<T: Field>(powers: &mut Vec<T>, factor: T, count: usize) {
    for _ in 0..count {
        let last_power = *powers
            .last()
            .expect("Vector is empty. Cannot compute higher powers");
        powers.push(factor * last_power);
    }
}

#[cfg(test)]
mod tests {
    use super::{compute_product_repeated, Field};
    use rand::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    pub fn test_field_basic<T: Field>() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let a = T::rand(&mut rng);

        let zero = T::zero();
        let one = T::one();

        assert_eq!(a + zero, a);
        assert_eq!(a * zero, zero);
        assert_eq!(a * one, a);
        assert_eq!(a * a.inverse(), one);
        assert_eq!(one.inverse(), one);
        assert_eq!(a + -a, zero);
    }

    pub fn test_field_compute_product_repeated<T: Field>() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let a = T::rand(&mut rng);

        let mut powers = vec![a];
        let factor = a * a;

        compute_product_repeated(&mut powers, factor, 2);

        assert_eq!(powers[0], a);
        assert_eq!(powers[1], powers[0] * factor);
        assert_eq!(powers[2], powers[1] * factor);
    }

    pub fn test_field_bit_ops<T: Field>() {
        let mut a = vec![false; T::BIT_SIZE as usize];
        a[T::BIT_SIZE as usize - 1] = true;

        let out = T::from_bits_be(&a);
        assert_eq!(out, T::one());
        assert_eq!(out.get_bit_be(T::BIT_SIZE - 1), true);
    }
}
