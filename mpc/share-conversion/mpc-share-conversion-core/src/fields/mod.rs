//! Types for working with finite fields

pub mod gf2_128;
pub mod p256;

use std::{
    fmt::Debug,
    ops::{Add, Mul, Neg},
};

use mpc_core::BlockSerialize;
use rand::{distributions::Standard, prelude::Distribution, Rng};
use utils::bits::{FromBits, ToBits};

/// A trait for finite fields
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
    + BlockSerialize
    + FromBits
    + ToBits
{
    /// The number of bits of a field element
    const BIT_SIZE: u32;

    /// Return the additive identity element
    fn zero() -> Self;

    /// Return the multiplicative identity element
    fn one() -> Self;

    /// Return a field element from a power of two.
    fn two_pow(rhs: u32) -> Self;

    /// Return the n-th bit, where n=0 returns the least-significant bit
    fn get_bit(&self, n: usize) -> bool;

    /// Return the multiplicative inverse
    fn inverse(self) -> Self;

    /// Return field element as little-endian bytes
    fn to_le_bytes(&self) -> Vec<u8>;

    /// Return field element as big-endian bytes
    fn to_be_bytes(&self) -> Vec<u8>;
}

/// A trait for sampling random elements of the field
///
/// This is helpful, because we do not need to import other traits since this is a supertrait of
/// field (which is not possible with `Standard` and `Distribution`)
pub trait UniformRand: Sized {
    /// Return a random field element
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

    pub(crate) fn test_field_basic<T: Field>() {
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

    pub(crate) fn test_field_compute_product_repeated<T: Field>() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let a = T::rand(&mut rng);

        let mut powers = vec![a];
        let factor = a * a;

        compute_product_repeated(&mut powers, factor, 2);

        assert_eq!(powers[0], a);
        assert_eq!(powers[1], powers[0] * factor);
        assert_eq!(powers[2], powers[1] * factor);
    }

    pub(crate) fn test_field_bit_ops<T: Field>() {
        let mut a = vec![false; T::BIT_SIZE as usize];
        let mut b = vec![false; T::BIT_SIZE as usize];

        a[0] = true;
        b[T::BIT_SIZE as usize - 1] = true;

        let a = T::from_lsb0(a);
        let b = T::from_lsb0(b);

        assert_eq!(a, T::one());
        assert!(a.get_bit(0));

        assert_eq!(b, T::two_pow(T::BIT_SIZE - 1));
        assert!(b.get_bit((T::BIT_SIZE - 1) as usize));
    }
}
