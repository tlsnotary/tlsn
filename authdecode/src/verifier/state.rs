//! AuthDecode verifier states.

use crate::{
    backend::traits::Field,
    bitid::IdSet,
    verifier::commitment::{UnverifiedCommitment, VerifiedCommitment},
};

/// Entry state
pub struct Initialized {}
opaque_debug::implement!(Initialized);

/// State after verifier received prover's commitment.
pub struct CommitmentReceived<T, F> {
    /// Details pertaining to each commitment.
    pub commitments: Vec<UnverifiedCommitment<T, F>>,
}
opaque_debug::implement!(CommitmentReceived<T, F>);

pub struct VerifiedSuccessfully<T, F> {
    /// Commitments which have been succesfully verified.
    pub commitments: Vec<VerifiedCommitment<T, F>>,
}
opaque_debug::implement!(VerifiedSuccessfully<T, F>);

#[allow(missing_docs)]
pub trait VerifierState: sealed::Sealed {}

impl VerifierState for Initialized {}
impl<T, F> VerifierState for CommitmentReceived<T, F>
where
    T: IdSet,
    F: Field,
{
}
impl<T, F> VerifierState for VerifiedSuccessfully<T, F> {}

mod sealed {
    use crate::{backend::traits::Field, bitid::IdSet};
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl<T, F> Sealed for super::CommitmentReceived<T, F>
    where
        T: IdSet,
        F: Field,
    {
    }
    impl<T, F> Sealed for super::VerifiedSuccessfully<T, F> {}
}
