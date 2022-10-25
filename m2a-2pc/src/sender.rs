use super::mul_gf2_128;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha12Rng;

/// The sender side of the protocol
///
/// The sender masks his number `b` with random elements and offers
/// them as choices for the oblivious transfer
pub struct Sender {
    b: u128,
    t0: [u128; 128],
    t1: [u128; 128],
}

impl Sender {
    /// Create a new sender holding factor `b`
    pub fn new(b: u128) -> Self {
        let mut rng = ChaCha12Rng::from_entropy();
        let s: [u128; 128] = std::array::from_fn(|_| rng.gen());
        let t1: [u128; 128] = std::array::from_fn(|i| mul_gf2_128(b, 1 << i) ^ s[i]);

        Self { b, t0: s, t1 }
    }

    /// Return factor `b`
    ///
    /// This is the factor `b` in `a * b = x + y`
    pub fn b(&self) -> u128 {
        self.b
    }

    /// Send both choices to receiver
    ///
    /// These are the choices for the receiver to choose from
    pub fn send(&self) -> ([u128; 128], [u128; 128]) {
        (self.t0, self.t1)
    }

    /// Return final additive share
    ///
    /// This is the summand `y` in `a * b = x + y`
    pub fn finalize(&self) -> u128 {
        self.t0.into_iter().fold(0, |acc, i| acc ^ i)
    }
}
