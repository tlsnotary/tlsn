#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    /// Error encountered while mapping proto model to core model
    #[error("Error encountered while mapping proto model to core model")]
    MappingError(#[from] anyhow::Error),
}
