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
    #[error("Invalid input count: expected {0}, got {1}")]
    InvalidCount(usize, usize),
    #[error("Invalid wire count: expected {0}, got {1}")]
    InvalidWireCount(usize, usize),
    #[error("Duplicate wire labels")]
    Duplicate,
}

#[derive(Debug, thiserror::Error)]
pub enum LabelError {
    #[error("Uninitialized Label, id: {0}")]
    UninitializedLabel(usize),
    #[error("Labels are not authentic for group {0:?}")]
    InauthenticLabels(String),
    #[error("Invalid label id for group: {0:?}, expected {1} got {2}")]
    InvalidLabelId(String, usize, usize),
    #[error("Invalid number of labels for group {0:?}, expected {1} got {2}")]
    InvalidLabelCount(String, usize, usize),
    #[error("Invalid value, expected {0} bits got {1}")]
    InvalidValue(usize, usize),
    #[error("Invalid decoding, expected {0} bits got {1}")]
    InvalidDecodingLength(usize, usize),
    #[error("Invalid decoding id, expected {0} got {1}")]
    InvalidDecodingId(usize, usize),
    #[error("Incorrect number of decodings, expected {0} got {1}")]
    InvalidDecodingCount(usize, usize),
    #[error("Invalid label commitment for group {0:?}")]
    InvalidLabelCommitment(String),
}
