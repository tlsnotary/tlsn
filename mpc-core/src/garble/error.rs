/// Error associated with garbled circuits
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Uninitialized Label, id: {0}")]
    UninitializedLabel(usize),
    #[error("Invalid input: {0:?}")]
    InvalidInput(InputError),
    #[error("Invalid label decoding info")]
    InvalidLabelDecodingInfo,
    #[error("Invalid output label commitment")]
    InvalidOutputLabelCommitment,
    #[error("Invalid input labels")]
    InvalidInputLabels,
    #[error("Invalid output labels")]
    InvalidOutputLabels,
    #[error("Detected corrupted garbled circuit")]
    CorruptedGarbledCircuit,
    #[error("Detected corrupted decoding information")]
    CorruptedDecodingInfo,
    #[error("Validation error: {0}")]
    ValidationError(String),
    #[error("Invalid opening")]
    InvalidOpening,
    #[error("Circuit error: {0:?}")]
    CircuitError(#[from] mpc_circuits::CircuitError),
    #[error("Value error: {0:?}")]
    ValueError(#[from] mpc_circuits::ValueError),
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
