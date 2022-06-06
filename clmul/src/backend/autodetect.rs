//! Autodetection for CPU intrinsics, with fallback to the "soft" backend when
//! they are unavailable.

use crate::backend::soft;
use core::ops::{BitXor, BitXorAssign};

#[cfg(all(target_arch = "aarch64", feature = "armv8"))]
use super::pmull as intrinsics;

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
use super::clmul as intrinsics;

#[cfg(all(target_arch = "aarch64", feature = "armv8"))]
cpufeatures::new!(mul_intrinsics, "aes"); // `aes` implies PMULL

#[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
cpufeatures::new!(mul_intrinsics, "pclmulqdq");

/// Carryless multiplication
#[derive(Clone, Copy)]
pub struct Clmul {
    // has_intrinsics is a flag that intrinsics are available
    has_intrinsics: bool,
    intrinsics: Option<intrinsics::Clmul>,
    soft: Option<soft::Clmul>,
}

impl Clmul {
    pub fn new(h: &[u8; 16]) -> Self {
        let has_intrinsics = mul_intrinsics::get();
        if has_intrinsics {
            Self {
                has_intrinsics,
                intrinsics: Some(intrinsics::Clmul::new(h)),
                soft: None,
            }
        } else {
            Self {
                has_intrinsics,
                intrinsics: None,
                soft: Some(soft::Clmul::new(h)),
            }
        }
    }

    pub fn clmul(self, x: Self) -> (Self, Self) {
        if self.has_intrinsics {
            let (r0, r1) = self.intrinsics.unwrap().clmul(x.intrinsics.unwrap());
            (
                Self {
                    has_intrinsics: self.has_intrinsics,
                    intrinsics: Some(r0),
                    soft: None,
                },
                Self {
                    has_intrinsics: self.has_intrinsics,
                    intrinsics: Some(r1),
                    soft: None,
                },
            )
        } else {
            let (r0, r1) = self.soft.unwrap().clmul(x.soft.unwrap());
            (
                Self {
                    has_intrinsics: self.has_intrinsics,
                    intrinsics: None,
                    soft: Some(r0),
                },
                Self {
                    has_intrinsics: self.has_intrinsics,
                    intrinsics: None,
                    soft: Some(r1),
                },
            )
        }
    }
}

impl From<Clmul> for [u8; 16] {
    #[inline]
    fn from(m: Clmul) -> [u8; 16] {
        if m.has_intrinsics {
            m.intrinsics.unwrap().into()
        } else {
            m.soft.unwrap().into()
        }
    }
}

impl BitXor for Clmul {
    type Output = Self;

    #[inline]
    fn bitxor(self, other: Self) -> Self::Output {
        if self.has_intrinsics {
            Self {
                has_intrinsics: self.has_intrinsics,
                intrinsics: Some(self.intrinsics.unwrap() ^ other.intrinsics.unwrap()),
                soft: None,
            }
        } else {
            Self {
                has_intrinsics: self.has_intrinsics,
                intrinsics: None,
                soft: Some(self.soft.unwrap() ^ other.soft.unwrap()),
            }
        }
    }
}

impl BitXorAssign for Clmul {
    #[inline]
    fn bitxor_assign(&mut self, other: Self) {
        if self.has_intrinsics {
            self.intrinsics = Some(self.intrinsics.unwrap() ^ other.intrinsics.unwrap());
        } else {
            self.soft = Some(self.soft.unwrap() ^ other.soft.unwrap());
        }
    }
}

impl PartialEq for Clmul {
    fn eq(&self, other: &Self) -> bool {
        if self.has_intrinsics {
            self.intrinsics.as_ref() == other.intrinsics.as_ref()
        } else {
            self.soft.unwrap() == other.soft.unwrap()
        }
    }
}
