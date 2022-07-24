#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Uninitialized Label, id: {0}")]
    UninitializedLabel(usize),
    #[error("Invalid input: {0:?}")]
    InvalidInput(InputError),
    #[error("Invalid label decoding")]
    InvalidLabelDecoding,
    #[error("Invalid output labels")]
    InvalidOutputLabels,
}

#[derive(Debug, thiserror::Error)]
pub enum InputError {
    #[error("Invalid input count: expected {0}, got {1}")]
    InvalidCount(usize, usize),
    #[error("Duplicate wire labels")]
    Duplicate,
}
