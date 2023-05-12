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

        /// Sets up a channel with the provided id
        pub fn setup_channel<T: Send + 'static>(
            &self,
            id: &str,
        ) -> Result<DuplexChannel<T>, MuxerError> {
            let mut state = self.state.lock().unwrap();

            if let Some(channel) = state.buffer.remove(id) {
                if let Ok(channel) = channel.downcast::<DuplexChannel<T>>() {
                    Ok(*channel)
                } else {
                    Err(MuxerError::InternalError(
                        "Failed to downcast channel".to_string(),
                    ))
                }
            } else {
                if !state.exists.insert(id.to_string()) {
                    return Err(MuxerError::DuplicateStreamId(id.to_string()));
                }

                let (channel_0, channel_1) = DuplexChannel::new();
                state.buffer.insert(id.to_string(), Box::new(channel_1));
                Ok(channel_0)
            }
        }
    }

    #[async_trait]
    impl<T> MuxChannelControl<T> for MockMuxChannelFactory
    where
        T: Send + 'static,
    {
        async fn get_channel(
            &mut self,
            id: String,
        ) -> Result<Box<dyn Channel<T, Error = std::io::Error>>, MuxerError> {
            self.setup_channel(&id)
                .map(|c| Box::new(c) as Box<dyn Channel<T, Error = std::io::Error>>)
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
