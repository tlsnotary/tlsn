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
    pub fn receive(&mut self, choices: [u128; 128]) {
        self.ta = Some(choices);
    }

    /// Return final additive share
    ///
    /// This is the summand `x` in `a * b = x + y`
    pub fn finalize(&self) -> Result<u128, M2AError> {
        self.ta
            .map(|ta| ta.into_iter().fold(0, |acc, i| acc ^ i))
            .ok_or(M2AError::ChoicesMissing)
    }
}
