//! Types associated with various stages of the notarization document
pub mod checks;
pub mod unchecked;
pub mod validated;
pub mod verified;

/// The maximum total size of all committed data in one document. Used to prevent DoS
/// during verification.
/// (this will cause the verifier to hash up to a max of 1GB * 128 = 128GB of labels if the
/// commitment type is [transcript_core::commitment::CommitmentType::labels_blake3])
const MAX_TOTAL_COMMITTED_DATA: u64 = 1000000000;

/// The maximum count of commitments in one document. Used to prevent DoS since searching for
/// overlapping commitments in the naive way which we implemented has quadratic cost.
const MAX_COMMITMENT_COUNT: u16 = 1000;
