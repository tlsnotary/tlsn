//! Autodetection for CPU intrinsics, with fallback to the "soft" backend when
//! they are unavailable.

use cfg_if::cfg_if;
use core::ops::{BitXor, BitXorAssign};

#[cfg_attr(not(target_pointer_width = "64"), path = "backend/soft32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "backend/soft64.rs")]
mod soft;

cfg_if! {
    if #[cfg(all(target_arch = "aarch64", feature = "armv8"))] {
        #[path = "backend/pmull.rs"]
        mod pmull;
        use pmull as intrinsics;
        cpufeatures::new!(mul_intrinsics, "aes"); // `aes` implies PMULL
    } else if #[cfg(any(target_arch = "x86_64", target_arch = "x86"))] {
        #[path = "backend/clmul.rs"]
        mod clmul_intr;
        use clmul_intr as intrinsics;
        cpufeatures::new!(mul_intrinsics, "pclmulqdq");
    }
}

cfg_if! {
    if #[cfg(any(all(target_arch = "aarch64", feature = "armv8"), any(target_arch = "x86_64", target_arch = "x86")))]{
        #[derive(Clone, Copy)]
        /// Carryless multiplication
        pub struct Clmul {
            intrinsics: Option<intrinsics::Clmul>,
            soft: Option<soft::Clmul>,
        }
    } else {
        #[derive(Clone, Copy)]
        /// Carryless multiplication
        pub struct Clmul {
            // intrinsics will never be used on a non-supported arch but Rust
            // won't allow to declare it with a None type, so we need to
            // provide some type
            intrinsics: Option<soft::Clmul>,
            soft: Option<soft::Clmul>,
        }
    }
}

// #[derive(Clone, Copy)]
// pub struct Clmul {
//     intrinsics: Option<intrinsics::Clmul>,
//     soft: Option<soft::Clmul>,
// }

impl Clmul {
    pub fn new(h: &[u8; 16]) -> Self {
        cfg_if! {
            if #[cfg(feature = "force-soft")] {
                Self {
                    intrinsics: None,
                    soft: Some(soft::Clmul::new(h)),
                }
            } else if #[cfg(any(all(target_arch = "aarch64", feature = "armv8"), any(target_arch = "x86_64", target_arch = "x86")))]{
                if mul_intrinsics::get() {
                    Self {
                        intrinsics: Some(intrinsics::Clmul::new(h)),
                        soft: None,
                    }
                } else {
                    // supported arch was found but intrinsics are not available
                    Self {
                        intrinsics: None,
                        soft: Some(soft::Clmul::new(h)),
                    }
                }
            } else {
                // "force-soft" feature was not enabled but neither was
                //  supported arch found. Falling back to soft backend.
                Self {
                    intrinsics: None,
                    soft: Some(soft::Clmul::new(h)),
                }
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

    /// Performs carryless multiplication. Same as clmul() but reusing the
    /// operands to return the result. This gives a ~6x speed up compared
    /// to clmul() where we create new objects containing the result.
    /// The high bits will be placed in `self`, the low bits - in `x`.
    pub fn clmul_reuse(&mut self, x: &mut Self) {
        match self.intrinsics {
            Some(s_intr) => match x.intrinsics {
                Some(x_intr) => {
                    let (r0, r1) = s_intr.clmul(x_intr);
                    self.intrinsics = Some(r0);
                    x.intrinsics = Some(r1);
                }
                None => unreachable!(),
            },
            None => match self.soft {
                Some(s_soft) => match x.soft {
                    Some(x_soft) => {
                        let (r0, r1) = s_soft.clmul(x_soft);
                        self.soft = Some(r0);
                        x.soft = Some(r1);
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
