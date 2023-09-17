use crate::{commitment::CommitmentId, MAX_TOTAL_COMMITTED_DATA};

/// An error relating to [`SubstringsProof`]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SubstringsProofError {
    /// The proof contains more data than the maximum allowed.
    #[error(
        "substrings proof opens more data than the maximum allowed: {0} > {}",
        MAX_TOTAL_COMMITTED_DATA
    )]
    MaxDataExceeded(usize),
    /// The proof contains duplicate transcript data.
    #[error("proof contains duplicate transcript data")]
    DuplicateData,
    /// Range of the opening is out of bounds.
    #[error("range of opening {0:?} is out of bounds: {1}")]
    RangeOutOfBounds(CommitmentId, usize),
    /// The proof contains an invalid commitment opening.
    #[error("invalid opening for commitment id: {0:?}")]
    InvalidOpening(CommitmentId),
    /// The proof contains an invalid inclusion proof.
    #[error("invalid inclusion proof")]
    InvalidInclusionProof,
}

/// An error for [`SubstringsOpening`]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SubstringsOpeningError {
    /// The provided encodings and data have different lengths.
    #[error("invalid encoding length: {0} != {1}")]
    InvalidEncodingLength(usize, usize),
}

/// An error for [`SubstringsProofBuilder`]
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SubstringsProofBuilderError {
    /// Invalid commitment id.
    #[error("invalid commitment id: {0:?}")]
    InvalidCommitmentId(CommitmentId),
    /// Invalid commitment type.
    #[error("commitment {0:?} is not a substrings commitment")]
    InvalidCommitmentType(CommitmentId),
    /// Attempted to add a commitment with a duplicate id.
    #[error("commitment with id {0:?} already exists")]
    DuplicateCommitmentId(CommitmentId),
}
