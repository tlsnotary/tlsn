//! Types for substring commitments and proofs.

mod commitment;
mod error;
mod opening;
mod proof;

pub use commitment::{Blake3SubstringsCommitment, SubstringsCommitment, SubstringsCommitmentKind};
pub use error::{SubstringsProofBuilderError, SubstringsProofError};
pub use opening::SubstringsOpening;
pub use proof::{SubstringsProof, SubstringsProofBuilder};
