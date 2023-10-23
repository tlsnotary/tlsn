//! This module exposes different variants for building substring proofs
//!
//! Depending on the TLS verifier the prover is interacting with, different approaches to building
//! substring proofs of the transcripts are required.
//!
//! - If the TLS verifier is a public notary server, substring proofs are built on commitments.
//! - If the TLS verifier is an application-specific verifier, substring proofs can be directly
//!   built without relying on commitments.

mod commit;
mod direct;

pub use commit::{
    SubstringsProof, SubstringsProofBuilder, SubstringsProofBuilderError, SubstringsProofError,
};

pub use direct::{DirectSubstringsProof, DirectSubstringsProofBuilder};
