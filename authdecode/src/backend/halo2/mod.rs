mod circuit;
pub mod onetimesetup;
mod poseidon;
pub mod prover;
mod utils;
pub mod verifier;

/// The amount of LSBs of a field element that are being used.
const USEFUL_BITS: usize = 253;

/// The size of the chunk of plaintext
/// We use 14 field elements. Only [USEFUL_BITS] of each field element are used.
const CHUNK_SIZE: usize = 3542;

#[cfg(test)]
pub(crate) mod tests {
    use super::{prover::Prover, verifier::Verifier};

    pub fn backend_pair() -> (Prover, Verifier) {
        let params = super::onetimesetup::OneTimeSetup::params();

        let proving_key = super::onetimesetup::OneTimeSetup::proving_key(params.clone());
        let verification_key = super::onetimesetup::OneTimeSetup::verification_key(params);

        (Prover::new(proving_key), Verifier::new(verification_key))
    }
}
