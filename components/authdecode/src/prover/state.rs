//! AuthDecode prover states.

use crate::{backend::traits::Field, id::IdSet, prover::commitment::CommitmentDetails};

/// Initial state.
pub struct Initialized {}
opaque_debug::implement!(Initialized);

/// State after prover has made a commitment.
pub struct Committed<T, F> {
    pub commitments: Vec<CommitmentDetails<T, F>>,
}
opaque_debug::implement!(Committed<T, F>);

/// State after the prover generated proofs.
pub struct ProofGenerated<T, F> {
    pub commitments: Vec<CommitmentDetails<T, F>>,
}
opaque_debug::implement!(ProofGenerated<T, F>);

#[allow(missing_docs)]
pub trait ProverState: sealed::Sealed {}

impl ProverState for Initialized {}
impl<T, F> ProverState for Committed<T, F>
where
    T: IdSet,
    F: Field + Clone,
{
}
impl<T, F> ProverState for ProofGenerated<T, F>
where
    T: IdSet,
    F: Field + Clone,
{
}

mod sealed {
    use crate::{id::IdSet, prover::state::Field};
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl<T, F> Sealed for super::Committed<T, F>
    where
        T: IdSet,
        F: Field + Clone,
    {
    }
    impl<T, F> Sealed for super::ProofGenerated<T, F>
    where
        T: IdSet,
        F: Field + Clone,
    {
    }
}
