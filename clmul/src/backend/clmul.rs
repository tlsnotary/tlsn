//! Intel `CLMUL`-accelerated implementation for modern x86/x86_64 CPUs
//! (i.e. Intel Sandy Bridge-compatible or newer)

use core::ops::BitXor;

#[cfg(target_arch = "x86")]
use core::arch::x86::*;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::*;

pub type Clmul = ClmulX86;

#[derive(Clone, Copy)]
pub struct ClmulX86(pub __m128i);

impl From<ClmulX86> for [u8; 16] {
    #[inline]
    fn from(m: ClmulX86) -> [u8; 16] {
        unsafe {
            let b: [u8; 16] = core::mem::transmute(m);
            b
        }
    }
}

impl From<ClmulX86> for u128 {
    #[inline]
    fn from(m: ClmulX86) -> u128 {
        unsafe { u128::from_le_bytes(core::mem::transmute(m)) }
    }
}

impl BitXor for ClmulX86 {
    type Output = Self;

    #[inline]
    fn bitxor(self, other: Self) -> Self::Output {
        unsafe { Self(_mm_xor_si128(self.0, other.0)) }
    }
}

impl PartialEq for ClmulX86 {
    fn eq(&self, other: &Self) -> bool {
        unsafe {
            u128::from_le_bytes(core::mem::transmute(self.0))
                == u128::from_le_bytes(core::mem::transmute(other.0))
        }
    }
}

impl ClmulX86 {
    pub fn new(bytes: &[u8; 16]) -> Self {
        unsafe {
            // `_mm_loadu_si128` performs an unaligned load
            #[allow(clippy::cast_ptr_alignment)]
            Self(_mm_loadu_si128(bytes.as_ptr() as *const __m128i))
        }
    }

    #[inline]
    pub fn clmul(self, x: Self) -> (ClmulX86, ClmulX86) {
        unsafe { self.clmul_unsafe(x) }
    }

    #[inline]
    #[target_feature(enable = "pclmulqdq")]
    unsafe fn clmul_unsafe(self, x: Self) -> (ClmulX86, ClmulX86) {
        let h = self.0;
        let y = x.0;

        let h0 = h;
        let h1 = _mm_shuffle_epi32(h, 0x0E);
        let h2 = _mm_xor_si128(h0, h1);
        let y0 = y;

        // Multiply values partitioned to 64-bit parts
        let y1 = _mm_shuffle_epi32(y, 0x0E);
        let y2 = _mm_xor_si128(y0, y1);
        let t0 = _mm_clmulepi64_si128(y0, h0, 0x00);
        let t1 = _mm_clmulepi64_si128(y, h, 0x11);
        let t2 = _mm_clmulepi64_si128(y2, h2, 0x00);
        let t2 = _mm_xor_si128(t2, _mm_xor_si128(t0, t1));
        let v0 = t0;
        let v1 = _mm_xor_si128(_mm_shuffle_epi32(t0, 0x0E), t2);
        let v2 = _mm_xor_si128(t1, _mm_shuffle_epi32(t2, 0x0E));
        let v3 = _mm_shuffle_epi32(t1, 0x0E);

        (
            ClmulX86(_mm_unpacklo_epi64(v0, v1)),
            ClmulX86(_mm_unpacklo_epi64(v2, v3)),
        )
    }
}

#[test]
fn clmul_xor_eq() {
    let mut one = [0u8; 16];
    one[15] = 1;
    let mut two = [0u8; 16];
    two[15] = 2;
    let mut three = [0u8; 16];
    three[15] = 3;
    let mut six = [0u8; 16];
    six[15] = 6;

    let a1 = Clmul::new(&one);
    let a2 = Clmul::new(&two);
    let a3 = Clmul::new(&three);
    let a6 = Clmul::new(&six);

    assert!(a1 ^ a2 == a3);
    assert!(a1 ^ a6 != a3);

    let b = a1.clmul(a6);
    let c = a2.clmul(a3);
    let d = a3.clmul(a6);
    assert!(b.0 == c.0);
    assert!(b.1 == c.1);
    // d.0 is zero
    assert!(b.1 != d.1);
}
