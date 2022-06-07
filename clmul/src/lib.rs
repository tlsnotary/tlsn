//! CarryLess MULtiplication (clmul) based on the crate:
//! https://github.com/RustCrypto/universal-hashes/tree/master/polyval
//!
//! Only those comments from the original file are preserved which are relevant
//! to carryless multiplication.
//!
//! # Minimum Supported Rust Version
//! Rust **1.56** or higher.
//!
//! # Supported backends
//! This crate provides multiple backends including a portable pure Rust
//! backend as well as ones based on CPU intrinsics.
//!
//! ## "soft" portable backend
//! As a baseline implementation, this crate provides a constant-time pure Rust
//! implementation based on [BearSSL], which is a straightforward and
//! compact implementation which uses a clever but simple technique to avoid
//! carry-spilling.
//!
//! ## ARMv8 intrinsics (`PMULL`, nightly-only)
//! On `aarch64` targets including `aarch64-apple-darwin` (Apple M1) and Linux
//! targets such as `aarch64-unknown-linux-gnu` and `aarch64-unknown-linux-musl`,
//! support for using the `PMULL` instructions in ARMv8's Cryptography Extensions
//! is available when using the nightly compiler, and can be enabled using the
//! `armv8` crate feature.
//!
//! On Linux and macOS, when the `armv8` feature is enabled support for AES
//! intrinsics is autodetected at runtime. On other platforms the `crypto`
//! target feature must be enabled via RUSTFLAGS.
//!
//! ## `x86`/`x86_64` intrinsics (`CMLMUL`)
//! By default this crate uses runtime detection on `i686`/`x86_64` targets
//! in order to determine if `CLMUL` is available, and if it is not, it will
//! fallback to using a constant-time software implementation.
//!
//! For optimal performance, set `target-cpu` in `RUSTFLAGS` to `sandybridge`
//! or newer:
//!
//! Example:
//!
//! ```text
//! $ RUSTFLAGS="-Ctarget-cpu=sandybridge" cargo bench
//! ```

#![cfg_attr(not(test), no_std)]
#![cfg_attr(all(feature = "armv8", target_arch = "aarch64"), feature(stdsimd))]

mod backend;
pub use crate::backend::Clmul;

#[cfg(test)]
mod tests {
    use cfg_if::cfg_if;
    use rand::Rng;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha12Rng;

    cfg_if! {
        if #[cfg(all(any(target_arch = "x86_64", target_arch = "x86")))] {
            #[path = "../backend/clmul.rs"]
            mod clmul;
            use std::arch::x86_64::*;

            /// Carryless multiplication. Reference implementation.
            ///
            /// This code was adapted from swanky
            /// https://github.com/GaloisInc/swanky/blob/ac7d5d1e8286bbcddcdaf5501d5d925fe79d0591/scuttlebutt/src/block.rs#L51
            /// which in turn adapted it from the EMP toolkit's implementation.
            fn clmul128(a: u128, b: u128) -> (u128, u128) {
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
        }
        else if #[cfg(all(target_arch = "aarch64", feature = "armv8"))] {
            #[path = "../backend/pmull.rs"]
            mod pmull;
        }
    }

    // TODO I had to create an empty tests folder otherwise the path
    // tests/../backend/soft32.rs was not found. Is this expected???
    #[path = "../backend/soft32.rs"]
    mod soft32;
    #[path = "../backend/soft64.rs"]
    mod soft64;

    #[test]
    fn clmul_test() {
        use soft32::Clmul as s32;
        use soft64::Clmul as s64;

        let mut rng = ChaCha12Rng::from_entropy();
        let a: [u8; 16] = rng.gen();
        let b: [u8; 16] = rng.gen();

        let (r64_0, r64_1) = s64::new(&a).clmul(s64::new(&b));
        let (r32_0, r32_1) = s32::new(&a).clmul(s32::new(&b));
        assert_eq!(u128::from(r64_0), u128::from(r32_0));
        assert_eq!(u128::from(r64_1), u128::from(r32_1));

        cfg_if! {
            if #[cfg(all(any(target_arch = "x86_64", target_arch = "x86")))] {
                use clmul::Clmul as clm;
                let (rclm_0, rclm_1) = clm::new(&a).clmul(clm::new(&b));
                assert_eq!(u128::from(r64_0), u128::from(rclm_0));
                assert_eq!(u128::from(r64_1), u128::from(rclm_1));

                let (ref_0, ref_1) = clmul128(u128::from_le_bytes(a), u128::from_le_bytes(b));
                assert_eq!(u128::from(r64_0), ref_0);
                assert_eq!(u128::from(r64_1), ref_1);
            }
            else if #[cfg(all(target_arch = "aarch64", feature = "armv8", not(feature = "force-soft")))] {
                use pmull::Clmul as pm;
                let (rpm_0, rpm_1) = pm::new(&a).clmul(pm::new(&b));
                assert_eq!(u128::from(r64_0), u128::from(rpm_0));
                assert_eq!(u128::from(r64_1), u128::from(rpm_1));
            }
        }
    }
}
