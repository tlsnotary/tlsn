//! AuthDecode prover states.

use crate::{backend::traits::Field, id::IdCollection, prover::commitment::CommitmentDetails};

/// The state of the Prover throughout the AuthDecode protocol.
pub trait ProverState: sealed::Sealed {}

/// The initial state.
pub struct Initialized {}
opaque_debug::implement!(Initialized);

/// The state after the prover has made a commitment.
pub struct Committed<I, F> {
    pub commitments: Vec<CommitmentDetails<I, F>>,
}
opaque_debug::implement!(Committed<T, F>);

/// The state after the prover generated proofs.
pub struct ProofGenerated<I, F> {
    pub commitments: Vec<CommitmentDetails<I, F>>,
}
opaque_debug::implement!(ProofGenerated<T, F>);

impl ProverState for Initialized {}
impl<I, F> ProverState for Committed<I, F>
where
    I: IdCollection,
    F: Field + Clone,
{
}
impl<I, F> ProverState for ProofGenerated<I, F>
where
    I: IdCollection,
    F: Field + Clone,
{
}

mod sealed {
    use crate::{id::IdCollection, prover::state::Field};
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl<I, F> Sealed for super::Committed<I, F>
    where
        I: IdCollection,
        F: Field + Clone,
    {
    }
    impl<I, F> Sealed for super::ProofGenerated<I, F>
    where
        I: IdCollection,
        F: Field + Clone,
    {
    }
}
