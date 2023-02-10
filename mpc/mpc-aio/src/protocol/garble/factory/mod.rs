pub mod deap;
pub mod dual;
pub mod zk;

#[derive(Debug, thiserror::Error)]
pub enum GCFactoryError {
    #[error("MuxerError: {0}")]
    MuxerError(#[from] utils_aio::mux::MuxerError),
}
