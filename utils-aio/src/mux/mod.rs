pub mod yamux;

use super::Channel;
use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};

pub trait DuplexByteStream: AsyncWrite + AsyncRead {}

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

/// This trait extends [`MuxControl`] by attaching a codec to the substream
#[async_trait]
pub trait MuxChannelControl: MuxControl {
    type Message;

    /// Opens a new channel with the remote using the provided id
    ///
    /// Attaches a codec to the underlying substream
    async fn get_channel(
        &mut self,
        id: String,
    ) -> Result<Box<dyn Channel<Self::Message, Error = std::io::Error>>, MuxerError>;
}
