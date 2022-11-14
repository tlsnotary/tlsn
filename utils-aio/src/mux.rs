use super::Channel;
use crate::duplex::DuplexByteStream;
use async_trait::async_trait;

#[derive(Debug, thiserror::Error)]
pub enum MuxerError {
    #[error("Connection error occurred: {0}")]
    ConnectionError(String),
    #[error("IO error")]
    IOError(#[from] std::io::Error),
    #[error("Duplicate stream id: {0:?}")]
    DuplicateStreamId(String),
    #[error("Encountered internal error: {0:?}")]
    InternalError(String),
}

#[async_trait]
pub trait MuxControl: Clone {
    /// Opens a new substream with the remote using the provided id
    async fn get_substream(
        &mut self,
        id: String,
    ) -> Result<Box<dyn DuplexByteStream + Send>, MuxerError>;
}

/// This trait is similar to [`MuxControl`] except it provides a substream
/// with a codec attached which handles serialization.
#[async_trait]
pub trait MuxChannelControl<T> {
    /// Opens a new channel with the remote using the provided id
    ///
    /// Attaches a codec to the underlying substream
    async fn get_channel(
        &mut self,
        id: String,
    ) -> Result<Box<dyn Channel<T, Error = std::io::Error>>, MuxerError>;
}
