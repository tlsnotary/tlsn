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
    /// Opens a new stream with the remote using the provided id
    async fn get_stream(
        &mut self,
        id: String,
    ) -> Result<Box<dyn DuplexByteStream + Send>, MuxerError>;
}

/// This trait is similar to [`MuxControl`] except it provides a stream
/// with a codec attached which handles serialization.
#[async_trait]
pub trait MuxChannelControl<T> {
    /// Opens a new channel with the remote using the provided id
    ///
    /// Attaches a codec to the underlying stream
    async fn get_channel(
        &mut self,
        id: String,
    ) -> Result<Box<dyn Channel<T, Error = std::io::Error>>, MuxerError>;
}

pub mod mock {
    use super::*;

    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };

    use crate::duplex::DuplexChannel;

    struct FactoryState<T> {
        channel_buffer: HashMap<String, DuplexChannel<T>>,
    }

    #[derive(Clone)]
    pub struct MockMuxChannelFactory<T> {
        state: Arc<Mutex<FactoryState<T>>>,
    }

    impl<T> MockMuxChannelFactory<T>
    where
        T: Send + 'static,
    {
        pub fn new() -> Self {
            Self {
                state: Arc::new(Mutex::new(FactoryState {
                    channel_buffer: HashMap::new(),
                })),
            }
        }
    }

    #[async_trait]
    impl<T> MuxChannelControl<T> for MockMuxChannelFactory<T>
    where
        T: Send + 'static,
    {
        async fn get_channel(
            &mut self,
            id: String,
        ) -> Result<Box<dyn Channel<T, Error = std::io::Error>>, MuxerError> {
            let mut state = self.state.lock().unwrap();
            let channel = if let Some(channel) = state.channel_buffer.remove(&id) {
                Box::new(channel)
            } else {
                let (channel_0, channel_1) = DuplexChannel::new();
                state.channel_buffer.insert(id, channel_1);
                Box::new(channel_0)
            };
            Ok(channel)
        }
    }

    #[cfg(test)]
    mod test {
        use futures::{SinkExt, StreamExt};

        use super::*;

        #[tokio::test]
        async fn test_mock_mux_channel_factory() {
            let mut factory = MockMuxChannelFactory::new();
            let mut channel_0 = factory.get_channel("test".to_string()).await.unwrap();
            let mut channel_1 = factory.get_channel("test".to_string()).await.unwrap();

            channel_0.send(0).await.unwrap();
            let received = channel_1.next().await.unwrap();

            assert_eq!(received, 0);

            channel_1.send(0).await.unwrap();
            let received = channel_0.next().await.unwrap();

            assert_eq!(received, 0);
        }
    }
}
