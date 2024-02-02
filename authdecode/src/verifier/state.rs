//! AuthDecode verifier states.

use crate::{
    encodings::FullEncodings,
    prover::{prover::CommitmentDetails, state::ProofCreated},
    verifier::backend::Backend,
    Proof, ProofProperties,
};
use num::BigUint;

/// Entry state
pub struct Initialized {}

opaque_debug::implement!(Initialized);

/// State after verifier received prover's commitment.
pub struct CommitmentReceived {
    pub commitments: Vec<CommitmentDetails>,
    pub full_encodings_sets: Vec<FullEncodings>,
}

opaque_debug::implement!(CommitmentReceived);

pub struct VerifiedSuccessfully {
    // TODO this should be just Poseidon hashes
    // with the corresponding ranges and direction
    // each hash of a chunk should have its own metadata
    pub commitments: Vec<CommitmentDetails>,
}
opaque_debug::implement!(VerifiedSuccessfully);

#[allow(missing_docs)]
pub trait VerifierState: sealed::Sealed {}

impl VerifierState for Initialized {}
impl VerifierState for CommitmentReceived {}
impl VerifierState for VerifiedSuccessfully {}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Initialized {}
    impl Sealed for super::CommitmentReceived {}
    impl Sealed for super::VerifiedSuccessfully {}
}
