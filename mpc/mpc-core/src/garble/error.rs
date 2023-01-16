use mpc_circuits::{CircuitId, GroupId};

/// Error associated with garbled circuits
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Invalid input: {0:?}")]
    InvalidInput(#[from] InputError),
    #[error("Label Error: {0:?}")]
    LabelError(#[from] LabelError),
    #[error("Missing label decoding info")]
    MissingDecoding,
    #[error("Detected corrupted garbled circuit")]
    CorruptedGarbledCircuit,
    #[error("Validation error: {0}")]
    ValidationError(String),
    #[error("Invalid opening")]
    InvalidOpening,
    #[error("Circuit error: {0:?}")]
    CircuitError(#[from] mpc_circuits::CircuitError),
    #[error("General error: {0}")]
    General(String),
    #[error("Peer behaved unexpectedly: {0}")]
    PeerError(String),
}

/// Error associated with garbled circuit inputs
#[derive(Debug, thiserror::Error)]
pub enum InputError {
    #[error("Invalid input id: {0}")]
    InvalidId(usize),
    #[error("Input from wrong circuit: expected {0:?} got {1:?}")]
    InvalidCircuit(CircuitId, CircuitId),
    #[error("Invalid input count: expected {0}, got {1}")]
    InvalidCount(usize, usize),
    #[error("Invalid wire count: expected {0}, got {1}")]
    InvalidWireCount(usize, usize),
    #[error("Duplicate wire labels")]
    Duplicate,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum LabelError {
    #[error("Uninitialized Label, id: {0}")]
    UninitializedLabel(usize),
    #[error("Labels are not authentic for group {0:?}")]
    InauthenticLabels(GroupId),
    #[error("Invalid number of labels for group {0:?}, expected {1} got {2}")]
    InvalidLabelCount(GroupId, usize, usize),
    #[error("Invalid value, expected {0} bits got {1}")]
    InvalidValue(usize, usize),
    #[error("Invalid decoding, expected {0} bits got {1}")]
    InvalidDecodingLength(usize, usize),
    #[error("Invalid decoding id, expected {0} got {1}")]
    InvalidDecodingId(usize, usize),
    #[error("Incorrect number of decodings, expected {0} got {1}")]
    InvalidDecodingCount(usize, usize),
    #[error("Invalid label commitment for group {0:?}")]
    InvalidLabelCommitment(GroupId),
    #[error("Labels set must contain at least 1 element")]
    EmptyLabelsSet,
    #[error("All elements in a set must correspond to the same circuit")]
    CircuitMismatch,
    #[error("A set cannot contain duplicate elements")]
    DuplicateLabels,
    #[error("All elements in a set must have the same delta")]
    DeltaMismatch,
    #[error("Invalid count in set for {0:?}: expected {1}, got {2}")]
    InvalidCount(CircuitId, usize, usize),
    #[error("Invalid id {1}, group not in {0:?}")]
    InvalidId(CircuitId, usize),
}
