//! AuthDecode verifier states.

use crate::{
    backend::traits::Field,
    id::IdCollection,
    verifier::commitment::{UnverifiedCommitment, VerifiedCommitment},
};

/// The initial state.
pub struct Initialized {}
opaque_debug::implement!(Initialized);

/// The state after the verifier received the prover's commitment.
pub struct CommitmentReceived<I, F> {
    /// Details pertaining to each commitment.
    pub commitments: Vec<UnverifiedCommitment<I, F>>,
}
opaque_debug::implement!(CommitmentReceived<I, F>);

/// The state after the commitments have been successfully verified.
pub struct VerifiedSuccessfully<I, F> {
    /// Commitments which have been succesfully verified.
    pub commitments: Vec<VerifiedCommitment<I, F>>,
}
opaque_debug::implement!(VerifiedSuccessfully<I, F>);

#[allow(missing_docs)]
pub trait VerifierState: sealed::Sealed {}

impl VerifierState for Initialized {}
impl<I, F> VerifierState for CommitmentReceived<I, F>
where
    I: IdCollection,
    F: Field,
{
}
impl<I, F> VerifierState for VerifiedSuccessfully<I, F> {}

mod sealed {
    use crate::{backend::traits::Field, id::IdCollection};
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl<I, F> Sealed for super::CommitmentReceived<I, F>
    where
        I: IdCollection,
        F: Field,
    {
    }
    impl<I, F> Sealed for super::VerifiedSuccessfully<I, F> {}
}
