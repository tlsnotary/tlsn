//! Contains logic for working with substring proofs, commitments and openings

mod commitment;
mod opening;
mod proof;

pub use commitment::{Blake3SubstringsCommitment, SubstringsCommitment};
pub use opening::SubstringsOpening;
pub use proof::{SubstringsProof, SubstringsProofBuilder, SubstringsProofBuilderError};
