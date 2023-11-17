mod circuit;
pub mod onetimesetup;
mod poseidon;
pub mod prover;
mod utils;
pub mod verifier;

/// The amount of useful bits, see [crate::prover::Prove::useful_bits].
/// This value is hard-coded into the circuit regardless of whether we use the
/// Pallas curve (field size 255) or the bn254 curve (field size 254).
const USEFUL_BITS: usize = 253;

/// The size of the chunk, see [crate::prover::Prove::chunk_size].
/// We use 14 field elements of 253 bits and 128 bits of the 15th field
/// element: 14 * 253 + 128 == 3670 bits total. The low 125 bits
/// of the last field element will be used for the salt.
const CHUNK_SIZE: usize = 3670;

/// The elliptic curve on which the Poseidon hash will be computed.
pub enum Curve {
    Pallas,
    BN254,
}

#[cfg(test)]
mod tests {
    use super::{onetimesetup::OneTimeSetup, prover::Prover, verifier::Verifier, *};
    use crate::tests::e2e_test;

    /// Run the whole authdecode protocol end-to-end, optionally corrupting the proof
    /// if `will_corrupt_proof` is set to true.
    fn halo2_e2e_test(will_corrupt_proof: bool) {
        // The Prover should have generated the proving key (before the authdecode
        // protocol starts) like this:
        let proving_key = OneTimeSetup::proving_key();

        // The Verifier should have generated the verifying key (before the authdecode
        // protocol starts) like this:
        let verification_key = OneTimeSetup::verification_key();

        let prover = Box::new(Prover::new(proving_key));
        let verifier = Box::new(Verifier::new(verification_key));
        e2e_test(prover, verifier, will_corrupt_proof);
    }

    #[test]
    // As of Oct 2022 there appears to be a bug in halo2 which causes the prove
    // times with MockProver be as long as with a real prover. Marking this test
    // as expensive.
    #[ignore = "expensive"]
    /// Tests that the protocol runs successfully
    fn halo2_e2e_test_success() {
        // This test causes the "thread ... has overflowed its stack" error
        // The only way to increase the stack size is to spawn a new thread with
        // the test.
        // See https://github.com/rust-lang/rustfmt/issues/3473
        use std::thread;
        thread::Builder::new()
            .stack_size(8388608)
            .spawn(|| halo2_e2e_test(false))
            .expect("Failed to create a test thread")
            .join()
            .expect("Failed to join a test thread");
    }

    #[test]
    // As of Oct 2022 there appears to be a bug in halo2 which causes the prove
    // times with MockProver be as long as with a real prover. Marking this test
    // as expensive.
    #[ignore = "expensive"]
    /// Tests that a corrupted proof causes verification to fail
    fn halo2_e2e_test_failure() {
        // This test causes the "thread ... has overflowed its stack" error
        // The only way to increase the stack size is to spawn a new thread with
        // the test.
        // See https://github.com/rust-lang/rustfmt/issues/3473
        use std::thread;
        thread::Builder::new()
            .stack_size(8388608)
            .spawn(|| halo2_e2e_test(true))
            .expect("Failed to create a test thread")
            .join()
            .expect("Failed to join a test thread");
    }
}
