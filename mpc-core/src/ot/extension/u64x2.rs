use core::num::Wrapping;
use rand::Rng;
use rand_core::CryptoRng;
use std::ops::BitXor;
use std::ops::Mul;

/// two `u64` values used to perform carryless multiplication
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct U64x2(u64, u64);

impl U64x2 {
    #[inline]
    pub fn new(high: u64, low: u64) -> Self {
        Self(high, low)
    }

    #[inline]
    pub fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        Self::new(rng.gen(), rng.gen())
    }

    pub fn to_array(self) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..8].copy_from_slice(&self.0.to_le_bytes());
        b[8..16].copy_from_slice(&self.1.to_le_bytes());
        b
    }
}

fn from_vec(vec: Vec<u8>) -> U64x2 {
    let mut high = [0u8; 8];
    let mut low = [0u8; 8];
    high.copy_from_slice(&vec[0..8]);
    low.copy_from_slice(&vec[8..16]);
    U64x2(u64::from_le_bytes(high), u64::from_le_bytes(low))
}

impl From<[u8; 16]> for U64x2 {
    fn from(bytes: [u8; 16]) -> U64x2 {
        from_vec(bytes.to_vec())
    }
}

impl From<&Vec<u8>> for U64x2 {
    fn from(bytes: &Vec<u8>) -> U64x2 {
        assert!(bytes.len() == 16);
        from_vec(bytes.clone())
    }
}

impl From<Vec<u8>> for U64x2 {
    fn from(bytes: Vec<u8>) -> U64x2 {
        assert!(bytes.len() == 16);
        from_vec(bytes)
    }
}

impl From<U64x2> for u128 {
    #[inline]
    fn from(m: U64x2) -> u128 {
        let mut b = [0u8; 16];
        b[0..8].copy_from_slice(&m.0.to_le_bytes());
        b[8..16].copy_from_slice(&m.1.to_le_bytes());
        u128::from_le_bytes(b)
    }
}

impl BitXor for U64x2 {
    type Output = Self;

    #[inline]
    fn bitxor(self, other: Self) -> Self::Output {
        Self::new(self.0 ^ other.0, self.1 ^ other.1)
    }
}

impl Mul for U64x2 {
    type Output = (U64x2, U64x2);
    /// Carryless multiplication of two 128-bit integers. Operates on 64-bit limbs.
    /// adapted from https://github.com/RustCrypto/universal-hashes/blob/master/polyval/src/backend/soft64.rs
    /// (The final steps which perform polynomial reduction were removed since we
    /// don't need that reduction).
    fn mul(self, rhs: Self) -> (U64x2, U64x2) {
        let h0 = self.0;
        let h1 = self.1;
        let h0r = rev64(h0);
        let h1r = rev64(h1);
        let h2 = h0 ^ h1;
        let h2r = h0r ^ h1r;

        let y0 = rhs.0;
        let y1 = rhs.1;
        let y0r = rev64(y0);
        let y1r = rev64(y1);
        let y2 = y0 ^ y1;
        let y2r = y0r ^ y1r;
        let z0 = bmul64(y0, h0);
        let z1 = bmul64(y1, h1);

        let mut z2 = bmul64(y2, h2);
        let mut z0h = bmul64(y0r, h0r);
        let mut z1h = bmul64(y1r, h1r);
        let mut z2h = bmul64(y2r, h2r);

        z2 ^= z0 ^ z1;
        z2h ^= z0h ^ z1h;
        z0h = rev64(z0h) >> 1;
        z1h = rev64(z1h) >> 1;
        z2h = rev64(z2h) >> 1;

        (U64x2::new(z0, z0h ^ z2), U64x2(z1 ^ z2h, z1h))
    }
}

/// copied from https://github.com/RustCrypto/universal-hashes/blob/master/polyval/src/backend/soft64.rs
/// Multiplication in GF(2)[X], truncated to the low 64-bits, with “holes”
/// (sequences of zeroes) to avoid carry spilling.
///
/// When carries do occur, they wind up in a "hole" and are subsequently masked
/// out of the result.
fn bmul64(x: u64, y: u64) -> u64 {
    let x0 = Wrapping(x & 0x1111_1111_1111_1111);
    let x1 = Wrapping(x & 0x2222_2222_2222_2222);
    let x2 = Wrapping(x & 0x4444_4444_4444_4444);
    let x3 = Wrapping(x & 0x8888_8888_8888_8888);
    let y0 = Wrapping(y & 0x1111_1111_1111_1111);
    let y1 = Wrapping(y & 0x2222_2222_2222_2222);
    let y2 = Wrapping(y & 0x4444_4444_4444_4444);
    let y3 = Wrapping(y & 0x8888_8888_8888_8888);

    let mut z0 = ((x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1)).0;
    let mut z1 = ((x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2)).0;
    let mut z2 = ((x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3)).0;
    let mut z3 = ((x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0)).0;

    z0 &= 0x1111_1111_1111_1111;
    z1 &= 0x2222_2222_2222_2222;
    z2 &= 0x4444_4444_4444_4444;
    z3 &= 0x8888_8888_8888_8888;

    z0 | z1 | z2 | z3
}

/// copied from https://github.com/RustCrypto/universal-hashes/blob/master/polyval/src/backend/soft64.rs
/// Bit-reverse a `u64` in constant time
fn rev64(mut x: u64) -> u64 {
    x = ((x & 0x5555_5555_5555_5555) << 1) | ((x >> 1) & 0x5555_5555_5555_5555);
    x = ((x & 0x3333_3333_3333_3333) << 2) | ((x >> 2) & 0x3333_3333_3333_3333);
    x = ((x & 0x0f0f_0f0f_0f0f_0f0f) << 4) | ((x >> 4) & 0x0f0f_0f0f_0f0f_0f0f);
    x = ((x & 0x00ff_00ff_00ff_00ff) << 8) | ((x >> 8) & 0x00ff_00ff_00ff_00ff);
    x = ((x & 0xffff_0000_ffff) << 16) | ((x >> 16) & 0xffff_0000_ffff);
    (x << 32) | (x >> 32)
}

#[cfg(test)]
mod tests {
    use super::U64x2;
    use rand::Rng;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;
    use std::arch::x86_64::*;

    /// Carryless multiplication. Reference implementation.
    ///
    /// This code was adapted from swanky
    /// https://github.com/GaloisInc/swanky/blob/ac7d5d1e8286bbcddcdaf5501d5d925fe79d0591/scuttlebutt/src/block.rs#L51
    /// which in turn adapted it from the EMP toolkit's implementation.
    pub fn clmul128(a: u128, b: u128) -> (u128, u128) {
        unsafe {
            let x = std::mem::transmute(a);
            let y = std::mem::transmute(b);
            let zero = _mm_clmulepi64_si128(x, y, 0x00);
            let one = _mm_clmulepi64_si128(x, y, 0x10);
            let two = _mm_clmulepi64_si128(x, y, 0x01);
            let three = _mm_clmulepi64_si128(x, y, 0x11);
            let tmp = _mm_xor_si128(one, two);
            let ll = _mm_slli_si128(tmp, 8);
            let rl = _mm_srli_si128(tmp, 8);
            let x = _mm_xor_si128(zero, ll);
            let y = _mm_xor_si128(three, rl);
            (std::mem::transmute(x), std::mem::transmute(y))
        }
    }

    #[test]
    fn test_clmul() {
        let mut rng = ChaCha12Rng::from_entropy();
        let a_: [u8; 16] = rng.gen();
        let b_: [u8; 16] = rng.gen();
        let (expected_c, expected_d) = clmul128(u128::from_le_bytes(a_), u128::from_le_bytes(b_));

        let a = U64x2::from(a_);
        let b = U64x2::from(b_);
        let (c, d) = a * b;

        assert_eq!(expected_c, c.into());
        assert_eq!(expected_d, d.into());
    }
}
