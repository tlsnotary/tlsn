#[derive(Debug, thiserror::Error)]
pub enum GeneratorError {
    /// Error encountered during garbling when an input label is uninitialized
    #[error("Encountered uninitialized input label during garbling")]
    UninitializedLabel(usize),
}

#[derive(Debug, thiserror::Error)]
pub enum EvaluatorError {
    /// Error encountered during evaluation when an input label is uninitialized
    #[error("Encountered uninitialized input label during evaluation")]
    UninitializedLabel(usize),
    /// Evaluator received invalid input counts for provided circuit
    #[error("Evaluator received invalid input counts for provided circuit")]
    InvalidInputCount(usize, usize),
}
