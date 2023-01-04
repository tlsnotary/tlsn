use share_conversion_aio::ShareConversionError;
use utils_aio::mux::MuxerError;

pub mod gf2_128;

#[derive(Debug, thiserror::Error)]
pub enum ActorConversionError {
    #[error("ShareConversionError: {0}")]
    ShareConversionError(#[from] ShareConversionError),
    #[error("MuxerError: {0}")]
    MuxerError(#[from] MuxerError),
    #[error("ActorError: {0}")]
    ActorError(#[from] xtra::Error),
    #[error("Actor has already been shut down")]
    Shutdown,
}
