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
    intrinsics: Option<intrinsics::Clmul>,
    soft: Option<soft::Clmul>,
}

impl Clmul {
    pub fn new(h: &[u8; 16]) -> Self {
        if mul_intrinsics::get() {
            Self {
                intrinsics: Some(intrinsics::Clmul::new(h)),
                soft: None,
            }
        } else {
            Self {
                intrinsics: None,
                soft: Some(soft::Clmul::new(h)),
            }
        }
    }

    /// Performs carryless multiplication
    pub fn clmul(self, x: Self) -> (Self, Self) {
        match self.intrinsics {
            Some(s_intr) => match x.intrinsics {
                Some(x_intr) => {
                    let (r0, r1) = s_intr.clmul(x_intr);
                    (
                        Self {
                            intrinsics: Some(r0),
                            soft: None,
                        },
                        Self {
                            intrinsics: Some(r1),
                            soft: None,
                        },
                    )
                }
                None => unreachable!(),
            },
            None => match self.soft {
                Some(s_soft) => match x.soft {
                    Some(x_soft) => {
                        let (r0, r1) = s_soft.clmul(x_soft);
                        (
                            Self {
                                intrinsics: None,
                                soft: Some(r0),
                            },
                            Self {
                                intrinsics: None,
                                soft: Some(r1),
                            },
                        )
                    }
                    None => unreachable!(),
                },
                None => unreachable!(),
            },
        }
    }
}

impl From<Clmul> for [u8; 16] {
    #[inline]
    fn from(m: Clmul) -> [u8; 16] {
        match m.intrinsics {
            Some(intr) => intr.into(),
            None => match m.soft {
                Some(soft) => soft.into(),
                None => unreachable!(),
            },
        }
    }
}

impl BitXor for Clmul {
    type Output = Self;

    #[inline]
    fn bitxor(self, other: Self) -> Self::Output {
        match self.intrinsics {
            Some(a) => match other.intrinsics {
                Some(b) => Self {
                    intrinsics: Some(a ^ b),
                    soft: None,
                },
                None => unreachable!(),
            },
            None => match self.soft {
                Some(a) => match other.soft {
                    Some(b) => Self {
                        intrinsics: None,
                        soft: Some(a ^ b),
                    },
                    None => unreachable!(),
                },
                None => unreachable!(),
            },
        }
    }
}

impl BitXorAssign for Clmul {
    #[inline]
    fn bitxor_assign(&mut self, other: Self) {
        match self.intrinsics {
            Some(a) => match other.intrinsics {
                Some(b) => {
                    self.intrinsics = Some(a ^ b);
                }
                None => unreachable!(),
            },
            None => match self.soft {
                Some(a) => match other.soft {
                    Some(b) => {
                        self.soft = Some(a ^ b);
                    }
                    None => unreachable!(),
                },
                None => unreachable!(),
            },
        }
    }
}

impl PartialEq for Clmul {
    fn eq(&self, other: &Self) -> bool {
        match self.intrinsics {
            Some(a) => match other.intrinsics {
                Some(b) => a == b,
                None => unreachable!(),
            },
            None => match self.soft {
                Some(a) => match other.soft {
                    Some(b) => a == b,
                    None => unreachable!(),
                },
                None => unreachable!(),
            },
        }
    }
}
