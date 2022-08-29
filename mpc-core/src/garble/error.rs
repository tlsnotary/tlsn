#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Uninitialized Label, id: {0}")]
    UninitializedLabel(usize),
    #[error("Invalid input: {0:?}")]
    InvalidInput(InputError),
    #[error("Invalid label encoding")]
    InvalidLabelEncoding,
    #[error("Invalid input labels")]
    InvalidInputLabels,
    #[error("Invalid output labels")]
    InvalidOutputLabels,
    #[error("Circuit error: {0:?}")]
    CircuitError(#[from] mpc_circuits::CircuitError),
    #[error("General error: {0}")]
    General(String),
    #[error("Peer behaved unexpectedly: {0}")]
    PeerError(String),
}

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
