//! AuthDecode prover states.

use crate::{
    backend::traits::Field,
    bitid::IdSet,
    encodings::{state::Converted, FullEncodings},
    prover::commitment::CommitmentDetails,
    Proof,
};

use super::prover::ProofInput;

/// Initial state.
pub struct Initialized {}

opaque_debug::implement!(Initialized);

/// State after prover has made a commitment.
pub struct Committed<T, F>
where
    T: IdSet,
    F: Field + Clone,
{
    pub commitments: Vec<CommitmentDetails<T, F>>,
}

// TODO how to use opaque_debug with generics
//opaque_debug::implement!(Committed<T>);

/// State after prover checked the authenticity of the encodings.
pub struct Checked<T, F>
where
    T: IdSet,
    F: Field + Clone,
{
    pub commitments: Vec<CommitmentDetails<T, F>>,
    /// A collection of authenticated encodings.
    /// The order of the collection matches the order of the commitments.
    pub full_encodings: Vec<FullEncodings<T, Converted>>,
}

//opaque_debug::implement!(Checked<T>);

pub struct ProofCreated<T, F>
where
    T: IdSet,
    F: Field + Clone,
{
    pub commitments: Vec<CommitmentDetails<T, F>>,
    pub proofs: Vec<Proof>,
    #[cfg(testdd)]
    pub proof_inputs: Vec<ProofInput<F>>,
}

//opaque_debug::implement!(ProofCreated);

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
    use crate::prover::{state::Field, IdSet};
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
