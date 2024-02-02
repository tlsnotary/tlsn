//! AuthDecode prover states.

use crate::{
    encodings::FullEncodings,
    prover::{
        backend::Backend,
        prover::{ChunkCommitmentDetails, CommitmentDetails},
    },
    Proof, ProofProperties,
};
use num::BigUint;

/// Entry state
pub struct Initialized {}

opaque_debug::implement!(Initialized);

/// State after prover has made a commitment.
pub struct Committed {
    pub commitments: Vec<CommitmentDetails>,
}

opaque_debug::implement!(Committed);

pub struct Checked {
    pub commitments: Vec<CommitmentDetails>,
    /// Authenticated encodings, uncorrelated and truncated.
    /// Each set corresponds to each commitment
    pub full_encodings_sets: Vec<FullEncodings>,
}

opaque_debug::implement!(Checked);

pub struct ProofCreated {
    pub commitments: Vec<CommitmentDetails>,
    pub proofs: Vec<Proof>,
}

opaque_debug::implement!(ProofCreated);

#[allow(missing_docs)]
pub trait ProverState: sealed::Sealed {}

impl ProverState for Initialized {}
impl ProverState for Committed {}
impl ProverState for Checked {}
impl ProverState for ProofCreated {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl Sealed for super::Committed {}
    impl Sealed for super::Checked {}
    impl Sealed for super::ProofCreated {}
}
