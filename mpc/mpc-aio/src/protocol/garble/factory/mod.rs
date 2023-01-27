pub mod deap;
pub mod dual;

#[derive(Debug, thiserror::Error)]
pub enum GCFactoryError {
    #[error("MuxerError: {0}")]
    MuxerError(#[from] utils_aio::mux::MuxerError),
}
