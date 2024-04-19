//! AuthDecode prover states.

use crate::{
    backend::traits::Field, bitid::IdSet, encodings::FullEncodings,
    prover::commitment::CommitmentDetails, Proof,
};

/// Initial state.
pub struct Initialized {}
opaque_debug::implement!(Initialized);

/// State after prover has made a commitment.
pub struct Committed<T, F> {
    pub commitments: Vec<CommitmentDetails<T, F>>,
}
opaque_debug::implement!(Committed<T, F>);

/// State after prover checked the authenticity of the encodings.
pub struct Checked<T, F> {
    pub commitments: Vec<CommitmentDetails<T, F>>,
    /// A collection of authenticated encodings.
    /// The order of the collection matches the order of the commitments.
    pub full_encodings: Vec<FullEncodings<T>>,
}
opaque_debug::implement!(Checked<T, F>);

pub struct ProofCreated<T, F> {
    pub commitments: Vec<CommitmentDetails<T, F>>,
    pub proofs: Vec<Proof>,
}
opaque_debug::implement!(ProofCreated<T, F>);

#[allow(missing_docs)]
pub trait ProverState: sealed::Sealed {}

impl ProverState for Initialized {}
impl<T, F> ProverState for Committed<T, F>
where
    T: IdSet,
    F: Field + Clone,
{
}
impl<T, F> ProverState for Checked<T, F>
where
    T: IdSet,
    F: Field + Clone,
{
}
impl<T, F> ProverState for ProofCreated<T, F>
where
    T: IdSet,
    F: Field + Clone,
{
}

mod sealed {
    use crate::{bitid::IdSet, prover::state::Field};
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl<T, F> Sealed for super::Committed<T, F>
    where
        T: IdSet,
        F: Field + Clone,
    {
    }
    impl<T, F> Sealed for super::Checked<T, F>
    where
        T: IdSet,
        F: Field + Clone,
    {
    }
    impl<T, F> Sealed for super::ProofCreated<T, F>
    where
        T: IdSet,
        F: Field + Clone,
    {
    }
}
