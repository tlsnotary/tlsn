//! This subcrate implements a secure two-party (2PC) multiplication algorithm
//!
//! Let `A` be an element of some finite field with `A = a*b`, where `a` is only known to Alice and `b` is
//! only known to Bob. A is unknown to both parties and it is their goal to end up with an additive
//! share of A.
//! So both parties start with `a` and `b` and want to end up with `x` and `y`, where `A = a*b = x + y`.
//! This is an implementation of the oblivious transfer method in chapter 4.1 of
//! <https://link.springer.com/content/pdf/10.1007/3-540-48405-1_8.pdf>

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;
use thiserror::Error;

struct Sender {
    number: u32,
    t0: [u32; 32],
    t1: [u32; 32],
}

impl Sender {
    pub fn new(number: u32) -> Self {
        let mut rng = ChaCha12Rng::from_entropy();
        let s: [u32; 32] = rng.gen();
        let t1: [u32; 32] = std::array::from_fn(|i| (number * (1 << i)).wrapping_add(s[i]));

        Self { number, t0: s, t1 }
    }

    pub fn send(&self) -> ([u32; 32], [u32; 32]) {
        (self.t0, self.t1)
    }

    pub fn finalize(&self) -> u32 {
        0_u32.wrapping_sub(self.t0.into_iter().fold(0, |acc, i| acc.wrapping_add(i)))
    }
}

struct Receiver {
    number: u32,
    ta: Option<u32>,
}

impl Receiver {
    pub fn new(number: u32) -> Self {
        Self { number, ta: None }
    }

    pub fn receive(&mut self, choices: ([u32; 32], [u32; 32])) {
        todo!()
    }

    pub fn finalize(&self) -> Result<u32, Mul2PCError> {
        self.ta.ok_or(Mul2PCError::ChoicesMissing)
    }
}

#[derive(Debug, Error)]
pub enum Mul2PCError {
    #[error("Choices are still missing")]
    ChoicesMissing,
}
