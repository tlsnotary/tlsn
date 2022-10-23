//! This subcrate implements a secure two-party (2PC) multiplication algorithm
//!
//! Let `A` be an element of some finite field with `A = a * b`, where `a` is only known to Alice
//! and `b` is only known to Bob. A is unknown to both parties and it is their goal that each of
//! them ends up with an additive share of A. So both parties start with `a` and `b` and want to
//! end up with `x` and `y`, where `A = a * b = x + y`.
//!
//! This is an implementation of the oblivious transfer method in chapter 4.1 of
//! <https://link.springer.com/content/pdf/10.1007/3-540-48405-1_8.pdf>

mod receiver;
mod sender;
pub use {receiver::Receiver, sender::Sender};

use thiserror::Error;

/// R is GCM polynomial in little-endian. In hex: "E1000000000000000000000000000000"
const R: u128 = 299076299051606071403356588563077529600;

/// Galois field multiplication of two 128-bit blocks reduced by the GCM polynomial
fn mul_gf2_128(mut x: u128, y: u128) -> u128 {
    let mut result: u128 = 0;
    for i in (0..128).rev() {
        result ^= x * ((y >> i) & 1);
        x = (x >> 1) ^ ((x & 1) * R);
    }
    result
}

/// Error for 2PC mulitplication
#[derive(Debug, Error)]
pub enum Mul2PCError {
    #[error("Choices are still missing")]
    ChoicesMissing,
}
