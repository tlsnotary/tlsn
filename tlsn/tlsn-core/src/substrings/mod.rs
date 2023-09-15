//! Types for substring commitments and proofs.

mod commitment;
mod opening;
mod proof;

pub use commitment::{Blake3SubstringsCommitment, SubstringsCommitment};
pub use opening::SubstringsOpening;
pub use proof::{SubstringsProof, SubstringsProofBuilder, SubstringsProofBuilderError};
