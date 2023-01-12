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
pub use backend::Clmul;

#[cfg(test)]
#[path = ""]
mod tests {
    use rand::Rng;
    use rand_chacha::{rand_core::SeedableRng, ChaCha12Rng};

    #[path = "backend/soft32.rs"]
    mod soft32;

    #[path = "backend/soft64.rs"]
    mod soft64;

    #[test]
    // test backends against each other
    fn clmul_test() {
        // test soft backends
        use soft32::Clmul as s32;
        use soft64::Clmul as s64;

        let mut rng = ChaCha12Rng::from_entropy();
        let a: [u8; 16] = rng.gen();
        let b: [u8; 16] = rng.gen();

        let (r64_0, r64_1) = s64::new(&a).clmul(s64::new(&b));
        let (r32_0, r32_1) = s32::new(&a).clmul(s32::new(&b));
        let r64_0: [u8; 16] = r64_0.into();
        let r64_1: [u8; 16] = r64_1.into();
        let r32_0: [u8; 16] = r32_0.into();
        let r32_1: [u8; 16] = r32_1.into();
        assert_eq!(r64_0, r32_0);
        assert_eq!(r64_1, r32_1);

        // this will test the hard backend (if "force-soft" was set then it will
        // test the soft backend again)
        use super::Clmul;

        let (c, d) = Clmul::new(&a).clmul(Clmul::new(&b));
        let c: [u8; 16] = c.into();
        let d: [u8; 16] = d.into();
        assert_eq!(r64_0, c);
        assert_eq!(r64_1, d);
    }

    #[test]
    // test soft32 backend
    fn clmul_xor_eq_soft32() {
        use soft32::Clmul;

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

    #[test]
    // test soft64 backend
    fn clmul_xor_eq_soft64() {
        use soft64::Clmul;

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

    #[test]
    // test CPU intrinsics backend (if "force-soft" was set then it will
    // test the soft backend again)
    fn clmul_xor_eq_hard() {
        use super::Clmul;

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
}
