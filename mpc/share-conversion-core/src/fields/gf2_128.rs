use super::Field;
use std::ops::{Add, Mul};

#[derive(Copy, Clone, Debug)]
pub struct Gf2_128(u128);

impl Field for Gf2_128 {
    const BIT_SIZE: usize = 128;

    fn inverse(mut self) -> Self {
        let one = Self(1 << 127);
        let mut out = one;

        for _ in 0..127 {
            self = self * self;
            out = out * self;
        }
        out
    }
}

impl Add for Gf2_128 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl Mul for Gf2_128 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        /// R is the GCM polynomial in little-endian. In hex: "E1000000000000000000000000000000"
        const R: u128 = 299076299051606071403356588563077529600;

        let mut x = self.0;
        let y = rhs.0;

        let mut result: u128 = 0;
        for i in (0..128).rev() {
            result ^= x * ((y >> i) & 1);
            x = (x >> 1) ^ ((x & 1) * R);
        }
        Self(result)
    }
}
