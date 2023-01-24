use super::Field;
use ark_ff::{Field as ArkField, One, Zero};
use ark_secp256r1::fq::Fq;
use num_bigint::{BigUint, ToBigUint};
use rand::{distributions::Standard, prelude::Distribution};
use std::ops::{Add, Mul, Sub};

#[derive(Copy, Clone, Debug, PartialOrd, Ord, PartialEq, Eq)]
pub struct P256(pub(crate) Fq);

impl P256 {
    pub fn new(input: impl ToBigUint) -> Self {
        let input = input.to_biguint().expect("Unable to create field element");
        P256::from(input)
    }

    pub fn zero() -> Self {
        P256(Fq::zero())
    }

    pub fn one() -> Self {
        P256(Fq::one())
    }
}

impl From<BigUint> for P256 {
    fn from(value: BigUint) -> Self {
        P256(Fq::from(value))
    }
}

impl Distribution<P256> for Standard {
    fn sample<R: rand::Rng + ?Sized>(&self, rng: &mut R) -> P256 {
        P256(self.sample(rng))
    }
}

impl Add for P256 {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        self.0 += rhs.0;
        self
    }
}

impl Sub for P256 {
    type Output = Self;

    fn sub(mut self, rhs: Self) -> Self::Output {
        self.0 -= rhs.0;
        self
    }
}

impl Mul for P256 {
    type Output = Self;

    fn mul(mut self, rhs: Self) -> Self::Output {
        self.0 *= rhs.0;
        self
    }
}

impl Field for P256 {
    const BIT_SIZE: u32 = 256;

    fn inverse(mut self) -> Self {
        self.0 = ArkField::inverse(&self.0).expect("Unable to invert field element");
        self
    }
}

#[cfg(test)]
mod tests {
    use crate::fields::{compute_product_repeated, Field};

    use super::P256;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha12Rng;

    #[test]
    fn test_p256_basic() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let a: P256 = rng.gen();

        let zero = P256::zero();
        let one = P256::one();

        assert_eq!(a + zero, a);
        assert_eq!(a * zero, zero);
        assert_eq!(a * one, a);
        assert_eq!(a * a.inverse(), one);
        assert_eq!(a - a, zero);
        assert_eq!(P256::new(1), P256::one())
    }

    #[test]
    fn test_inverse() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let a: P256 = rng.gen();

        assert_eq!(a * a.inverse(), P256::one());
        assert_eq!(P256::one().inverse(), P256::one());
    }

    #[test]
    fn test_p256_compute_product_repeated() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);
        let a: P256 = rng.gen();

        let mut powers = vec![a];
        let factor = a * a;

        compute_product_repeated(&mut powers, factor, 2);

        assert_eq!(powers[0], a);
        assert_eq!(powers[1], powers[0] * factor);
        assert_eq!(powers[2], powers[1] * factor);
    }
}
