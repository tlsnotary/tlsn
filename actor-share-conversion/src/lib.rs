use share_conversion_aio::ShareConversionError;
use utils_aio::mux::MuxerError;

mod receiver;
mod sender;

pub use {receiver::Receiver, sender::Sender};

#[derive(Debug, thiserror::Error)]
pub enum ActorConversionError {
    #[error("ShareConversionError: {0}")]
    ShareConversionError(#[from] ShareConversionError),
    #[error("MuxerError: {0}")]
    MuxerError(#[from] MuxerError),
}
