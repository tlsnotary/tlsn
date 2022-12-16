//! ARMv8 `PMULL`-accelerated implementation of POLYVAL.
//!
//! Based on this C intrinsics implementation:
//! <https://github.com/noloader/AES-Intrinsics/blob/master/clmul-arm.c>
//!
//! Original C written and placed in public domain by Jeffrey Walton.
//! Based on code from ARM, and by Johannes Schneiders, Skip Hovsmith and
//! Barry O'Rourke for the mbedTLS project.
//!
//! For more information about PMULL, see:
//! - <https://developer.arm.com/documentation/100069/0608/A64-SIMD-Vector-Instructions/PMULL--PMULL2--vector->
//! - <https://eprint.iacr.org/2015/688.pdf>

use core::{arch::aarch64::*, mem, ops::BitXor};

pub type Clmul = ClmulArm;

#[derive(Clone, Copy)]
pub struct ClmulArm(pub uint8x16_t);

impl From<ClmulArm> for [u8; 16] {
    #[inline]
    fn from(m: ClmulArm) -> [u8; 16] {
        unsafe {
            let b: [u8; 16] = core::mem::transmute(m);
            b
        }
    }
}

impl From<ClmulArm> for u128 {
    #[inline]
    fn from(m: ClmulArm) -> u128 {
        unsafe { mem::transmute(m) }
    }
}

impl BitXor for ClmulArm {
    type Output = Self;

    #[inline]
    fn bitxor(self, other: Self) -> Self::Output {
        unsafe { Self(veorq_u8(self.0, other.0)) }
    }
}

impl PartialEq for ClmulArm {
    fn eq(&self, other: &Self) -> bool {
        unsafe {
            u128::from_le_bytes(core::mem::transmute(self.0))
                == u128::from_le_bytes(core::mem::transmute(other.0))
        }
    }
}

impl ClmulArm {
    pub fn new(bytes: &[u8; 16]) -> Self {
        unsafe { Self(vld1q_u8(bytes.as_ptr())) }
    }

    #[inline]
    pub fn clmul(mut self, x: Self) -> (ClmulArm, ClmulArm) {
        unsafe { self.clmul_unsafe(&x) }
    }

    #[inline]
    #[target_feature(enable = "neon")]
    unsafe fn clmul_unsafe(&mut self, x: &Self) -> (ClmulArm, ClmulArm) {
        let h = self.0;
        let y = x.0;

        // polynomial multiply
        let z = vdupq_n_u8(0);
        let r0 = pmull::<0, 0>(h, y);
        let r1 = pmull::<1, 1>(h, y);
        let t0 = pmull::<0, 1>(h, y);
        let t1 = pmull::<1, 0>(h, y);
        let t0 = veorq_u8(t0, t1);
        let t1 = vextq_u8(z, t0, 8);
        let r0 = veorq_u8(r0, t1);
        let t1 = vextq_u8(t0, z, 8);
        let r1 = veorq_u8(r1, t1);

        (ClmulArm(r0), ClmulArm(r1))
    }
}

/// Wrapper for the ARM64 `PMULL` instruction.
#[inline(always)]
unsafe fn pmull<const A_LANE: i32, const B_LANE: i32>(a: uint8x16_t, b: uint8x16_t) -> uint8x16_t {
    mem::transmute(vmull_p64(
        vgetq_lane_u64(vreinterpretq_u64_u8(a), A_LANE),
        vgetq_lane_u64(vreinterpretq_u64_u8(b), B_LANE),
    ))
}
