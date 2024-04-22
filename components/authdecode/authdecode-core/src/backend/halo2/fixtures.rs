use super::{prover::Prover, verifier::Verifier};
use crate::backend::halo2::onetimesetup::{proving_key, verification_key};

pub fn backend_pair() -> (Prover, Verifier) {
    (
        Prover::new(proving_key()),
        Verifier::new(verification_key()),
    )
}
