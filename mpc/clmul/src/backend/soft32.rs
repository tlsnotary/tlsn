//! Constant-time software implementation of carryless multiplication for 32-bit architectures
//! Adapted from BearSSL's `ghash_ctmul32.c`:
//!
//! <https://bearssl.org/gitweb/?p=BearSSL;a=blob;f=src/hash/ghash_ctmul32.c;hb=4b6046412>
//!
//! Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
//!
//! This implementation uses 32-bit multiplications, and only the low
//! 32 bits for each multiplication result. This is meant primarily for
//! the ARM Cortex M0 and M0+, whose multiplication opcode does not yield
//! the upper 32 bits; but it might also be useful on architectures where
//! access to the upper 32 bits requires use of specific registers that
//! create contention (e.g. on i386, "mul" necessarily outputs the result
//! in edx:eax, while "imul" can use any registers but is limited to the
//! low 32 bits).
//!
//! The implementation trick that is used here is bit-reversing (bit 0
//! is swapped with bit 31, bit 1 with bit 30, and so on). In GF(2)[X],
//! for all values x and y, we have:
//!
//! ```text
//! rev32(x) * rev32(y) = rev64(x * y)
//! ```
//!
//! In other words, if we bit-reverse (over 32 bits) the operands, then we
//! bit-reverse (over 64 bits) the result.

use core::{num::Wrapping, ops::BitXor};

pub type Clmul = U32x4;

/// 4 x `u32` values
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct U32x4(u32, u32, u32, u32);

impl From<U32x4> for [u8; 16] {
    #[inline]
    fn from(m: U32x4) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0..4].copy_from_slice(&m.0.to_le_bytes());
        b[4..8].copy_from_slice(&m.1.to_le_bytes());
        b[8..12].copy_from_slice(&m.2.to_le_bytes());
        b[12..16].copy_from_slice(&m.3.to_le_bytes());
        b
    }
}

impl BitXor for U32x4 {
    type Output = Self;

    #[inline]
    fn bitxor(self, other: Self) -> Self::Output {
        Self(
            self.0 ^ other.0,
            self.1 ^ other.1,
            self.2 ^ other.2,
            self.3 ^ other.3,
        )
    }
}

impl U32x4 {
    pub fn new(bytes: &[u8; 16]) -> Self {
        Self(
            u32::from_le_bytes(bytes[..4].try_into().unwrap()),
            u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            u32::from_le_bytes(bytes[12..].try_into().unwrap()),
        )
    }

    pub fn clmul(self, rhs: Self) -> (U32x4, U32x4) {
        let hw = [self.0, self.1, self.2, self.3];
        let yw = [rhs.0, rhs.1, rhs.2, rhs.3];
        let hwr = [rev32(hw[0]), rev32(hw[1]), rev32(hw[2]), rev32(hw[3])];

        // We are using Karatsuba: the 128x128 multiplication is
        // reduced to three 64x64 multiplications, hence nine
        // 32x32 multiplications. With the bit-reversal trick,
        // we have to perform 18 32x32 multiplications.

        let mut a = [0u32; 18];

        a[0] = yw[0];
        a[1] = yw[1];
        a[2] = yw[2];
        a[3] = yw[3];
        a[4] = a[0] ^ a[1];
        a[5] = a[2] ^ a[3];
        a[6] = a[0] ^ a[2];
        a[7] = a[1] ^ a[3];
        a[8] = a[6] ^ a[7];
        a[9] = rev32(yw[0]);
        a[10] = rev32(yw[1]);
        a[11] = rev32(yw[2]);
        a[12] = rev32(yw[3]);
        a[13] = a[9] ^ a[10];
        a[14] = a[11] ^ a[12];
        a[15] = a[9] ^ a[11];
        a[16] = a[10] ^ a[12];
        a[17] = a[15] ^ a[16];

        let mut b = [0u32; 18];

        b[0] = hw[0];
        b[1] = hw[1];
        b[2] = hw[2];
        b[3] = hw[3];
        b[4] = b[0] ^ b[1];
        b[5] = b[2] ^ b[3];
        b[6] = b[0] ^ b[2];
        b[7] = b[1] ^ b[3];
        b[8] = b[6] ^ b[7];
        b[9] = hwr[0];
        b[10] = hwr[1];
        b[11] = hwr[2];
        b[12] = hwr[3];
        b[13] = b[9] ^ b[10];
        b[14] = b[11] ^ b[12];
        b[15] = b[9] ^ b[11];
        b[16] = b[10] ^ b[12];
        b[17] = b[15] ^ b[16];

        let mut c = [0u32; 18];

        for i in 0..18 {
            c[i] = bmul32(a[i], b[i]);
        }

        c[4] ^= c[0] ^ c[1];
        c[5] ^= c[2] ^ c[3];
        c[8] ^= c[6] ^ c[7];

        c[13] ^= c[9] ^ c[10];
        c[14] ^= c[11] ^ c[12];
        c[17] ^= c[15] ^ c[16];

        let mut zw = [0u32; 8];

        zw[0] = c[0];
        zw[1] = c[4] ^ rev32(c[9]) >> 1;
        zw[2] = c[1] ^ c[0] ^ c[2] ^ c[6] ^ rev32(c[13]) >> 1;
        zw[3] = c[4] ^ c[5] ^ c[8] ^ rev32(c[10] ^ c[9] ^ c[11] ^ c[15]) >> 1;
        zw[4] = c[2] ^ c[1] ^ c[3] ^ c[7] ^ rev32(c[13] ^ c[14] ^ c[17]) >> 1;
        zw[5] = c[5] ^ rev32(c[11] ^ c[10] ^ c[12] ^ c[16]) >> 1;
        zw[6] = c[3] ^ rev32(c[14]) >> 1;
        zw[7] = rev32(c[12]) >> 1;

        (
            U32x4(zw[0], zw[1], zw[2], zw[3]),
            U32x4(zw[4], zw[5], zw[6], zw[7]),
        )
    }
}

/// Multiplication in GF(2)[X], truncated to the low 32-bits, with “holes”
/// (sequences of zeroes) to avoid carry spilling.
///
/// When carries do occur, they wind up in a "hole" and are subsequently masked
/// out of the result.
fn bmul32(x: u32, y: u32) -> u32 {
    let x0 = Wrapping(x & 0x1111_1111);
    let x1 = Wrapping(x & 0x2222_2222);
    let x2 = Wrapping(x & 0x4444_4444);
    let x3 = Wrapping(x & 0x8888_8888);
    let y0 = Wrapping(y & 0x1111_1111);
    let y1 = Wrapping(y & 0x2222_2222);
    let y2 = Wrapping(y & 0x4444_4444);
    let y3 = Wrapping(y & 0x8888_8888);

    let mut z0 = ((x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1)).0;
    let mut z1 = ((x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2)).0;
    let mut z2 = ((x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3)).0;
    let mut z3 = ((x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0)).0;

    z0 &= 0x1111_1111;
    z1 &= 0x2222_2222;
    z2 &= 0x4444_4444;
    z3 &= 0x8888_8888;

    z0 | z1 | z2 | z3
}

/// Bit-reverse a 32-bit word in constant time.
fn rev32(mut x: u32) -> u32 {
    x = ((x & 0x5555_5555) << 1) | (x >> 1 & 0x5555_5555);
    x = ((x & 0x3333_3333) << 2) | (x >> 2 & 0x3333_3333);
    x = ((x & 0x0f0f_0f0f) << 4) | (x >> 4 & 0x0f0f_0f0f);
    x = ((x & 0x00ff_00ff) << 8) | (x >> 8 & 0x00ff_00ff);
    (x << 16) | (x >> 16)
}
