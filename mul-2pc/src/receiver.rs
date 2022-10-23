use super::Mul2PCError;

/// The receiver side of the protocol
///
/// The receiver obliviously receives choices depending
/// on his factor `a` in binary representation
pub struct Receiver {
    a: u128,
    ta: Option<[u128; 128]>,
}

impl Receiver {
    /// Create a new receiver holding factor `a`
    pub fn new(a: u128) -> Self {
        Self { a, ta: None }
    }

    /// Return factor `a`
    ///
    /// This is the factor `a` in `a * b = x + y`
    pub fn a(&self) -> u128 {
        self.a
    }

    /// Receive choices from the sender
    ///
    /// Depending on `a` the receiver makes his choices
    /// and builds `ta`
    pub fn receive(&mut self, choices: ([u128; 128], [u128; 128])) {
        let mut ta = [0_u128; 128];

        let mut a = self.a;
        for k in 0..128 {
            a = (a >> k) & 1;
            ta[k] = a * choices.1[k] + !a * choices.0[k];
        }
        self.ta = Some(ta);
    }

    /// Return final additive share
    ///
    /// This is the summand `x` in `a * b = x + y`
    pub fn finalize(&self) -> Result<u128, Mul2PCError> {
        self.ta
            .map(|ta| ta.into_iter().fold(0, |acc, i| acc ^ i))
            .ok_or(Mul2PCError::ChoicesMissing)
    }
}
