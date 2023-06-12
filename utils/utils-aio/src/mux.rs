use super::Channel;
use async_trait::async_trait;
use futures_util::{AsyncRead, AsyncWrite};

#[derive(Debug, thiserror::Error)]
pub enum MuxerError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("internal error: {0:?}")]
    InternalError(String),
    #[error("duplicate stream id: {0:?}")]
    DuplicateStreamId(String),
}

/// A trait for opening a new duplex byte stream with a remote peer.
#[async_trait]
pub trait MuxStream: Clone {
    type Stream: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static;

    /// Opens a new stream with the remote using the provided id
    async fn get_stream(&mut self, id: &str) -> Result<Self::Stream, MuxerError>;
}

/// A trait for opening a new duplex channel with a remote peer.
#[async_trait]
pub trait MuxChannelSerde: Sized {
    /// Opens a new channel with the remote using the provided id
    async fn get_channel<
        T: serde::Serialize + serde::de::DeserializeOwned + Send + Sync + Unpin + 'static,
    >(
        &mut self,
        id: &str,
    ) -> Result<Box<dyn Channel<T> + 'static>, MuxerError>;
}

/// A trait for opening a new duplex channel with a remote peer.
///
/// This trait is similar to [`MuxChannelSized`] except it is object safe.
#[async_trait]
pub trait MuxChannel<T> {
    /// Opens a new channel with the remote using the provided id
    ///
    /// Attaches a codec to the underlying stream
    async fn get_channel(&mut self, id: &str) -> Result<Box<dyn Channel<T> + 'static>, MuxerError>;
}

#[async_trait]
impl<T, U> MuxChannel<T> for U
where
    T: serde::Serialize + serde::de::DeserializeOwned + Send + Sync + Unpin + 'static,
    U: MuxChannelSerde + Send,
{
    async fn get_channel(&mut self, id: &str) -> Result<Box<dyn Channel<T> + 'static>, MuxerError> {
        self.get_channel::<T>(id).await
    }
}

pub mod mock {
    use tokio_util::compat::TokioAsyncReadCompatExt;

    use super::*;

    use std::{
        any::Any,
        collections::{HashMap, HashSet},
        sync::{Arc, Mutex},
    };

    use crate::duplex::DuplexChannel;

    #[derive(Default)]
    struct FactoryState {
        exists: HashSet<String>,
        buffer: HashMap<String, Box<dyn Any + Send + 'static>>,
    }

    #[derive(Default, Clone)]
    pub struct MockMuxChannelFactory {
        state: Arc<Mutex<FactoryState>>,
    }

    impl MockMuxChannelFactory {
        /// Creates a new mock mux channel factory
        pub fn new() -> Self {
            Self {
                state: Arc::new(Mutex::new(FactoryState {
                    exists: HashSet::new(),
                    buffer: HashMap::new(),
                })),
            }
        }
    }

    #[async_trait]
    impl MuxStream for MockMuxChannelFactory {
        type Stream = tokio_util::compat::Compat<tokio::io::DuplexStream>;

        async fn get_stream(&mut self, id: &str) -> Result<Self::Stream, MuxerError> {
            let mut state = self.state.lock().unwrap();

            if let Some(stream) = state.buffer.remove(id) {
                if let Ok(stream) = stream.downcast::<tokio::io::DuplexStream>() {
                    Ok((*stream).compat())
                } else {
                    Err(MuxerError::InternalError(
                        "failed to downcast stream".to_string(),
                    ))
                }
            } else {
                if !state.exists.insert(id.to_string()) {
                    return Err(MuxerError::DuplicateStreamId(id.to_string()));
                }

                let (stream_0, stream_1) = tokio::io::duplex(1 << 23);
                state.buffer.insert(id.to_string(), Box::new(stream_1));
                Ok(stream_0.compat())
            }
        }
    }

    #[async_trait]
    impl MuxChannelSerde for MockMuxChannelFactory {
        async fn get_channel<T: Send + 'static>(
            &mut self,
            id: &str,
        ) -> Result<Box<dyn Channel<T> + 'static>, MuxerError> {
            let mut state = self.state.lock().unwrap();

            if let Some(channel) = state.buffer.remove(id) {
                if let Ok(channel) = channel.downcast::<DuplexChannel<T>>() {
                    Ok(channel)
                } else {
                    Err(MuxerError::InternalError(
                        "failed to downcast channel".to_string(),
                    ))
                }
            } else {
                if !state.exists.insert(id.to_string()) {
                    return Err(MuxerError::DuplicateStreamId(id.to_string()));
                }

                let (channel_0, channel_1) = DuplexChannel::new();
                state.buffer.insert(id.to_string(), Box::new(channel_1));

                Ok(Box::new(channel_0))
            }
        }
    }

    #[cfg(test)]
    mod test {
        use futures::{SinkExt, StreamExt};

        use super::{MockMuxChannelFactory, MuxChannelSerde};

        #[tokio::test]
        async fn test_mock_mux_channel_factory() {
            let mut factory = MockMuxChannelFactory::new();
            let mut channel_0 = factory.get_channel("test").await.unwrap();
            let mut channel_1 = factory.get_channel("test").await.unwrap();

            channel_0.send(0).await.unwrap();
            let received = channel_1.next().await.unwrap().unwrap();

            assert_eq!(received, 0);

            channel_1.send(0).await.unwrap();
            let received = channel_0.next().await.unwrap().unwrap();

            assert_eq!(received, 0);
        }
    }
}
