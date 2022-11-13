use std::{
    any::Any,
    collections::{HashMap, HashSet},
    marker::PhantomData,
};

use crate::{duplex::DuplexChannel, Channel};

use super::{DuplexByteStream, MuxChannelControl, MuxControl, MuxerError};
use async_trait::async_trait;
use futures::{
    channel::{mpsc, oneshot},
    Future, SinkExt, StreamExt,
};

pub enum Event {
    ClientOpen(
        String,
        Box<dyn Any + Send>,
        oneshot::Sender<Result<(), MuxerError>>,
    ),
    ServerOpen(
        String,
        oneshot::Sender<Result<Box<dyn Any + Send>, MuxerError>>,
    ),
}

const MAX_COMMAND_BACKLOG: usize = 32;

pub fn new_mock_mux() -> (
    MockControl<Client>,
    MockControl<Server>,
    impl Future<Output = Result<(), MuxerError>>,
) {
    let (mux, client, server) = MockMuxer::new();

    (client, server, mux.run())
}

pub struct MockMuxer {
    client_channel_ids: HashSet<String>,
    server_channel_ids: HashSet<String>,
    control_receiver: mpsc::Receiver<Event>,
    client_buffer: HashMap<String, Box<dyn Any + Send>>,
    server_buffer: HashMap<String, oneshot::Sender<Result<Box<dyn Any + Send>, MuxerError>>>,
}

#[derive(Clone)]
pub struct Client;
#[derive(Clone)]
pub struct Server;

#[derive(Clone)]
pub struct MockControl<M> {
    _mode: PhantomData<M>,
    sender: mpsc::Sender<Event>,
}

#[async_trait]
impl<M: Clone + Send> MuxControl for MockControl<M> {
    async fn get_substream(
        &mut self,
        _id: String,
    ) -> Result<Box<dyn DuplexByteStream + Send>, MuxerError> {
        // We bypass bytestreams and send objects directly
        // via channels so we don't have to deal with serialization
        unimplemented!()
    }
}

#[async_trait]
impl<T: Send + 'static> MuxChannelControl<T> for MockControl<Client> {
    async fn get_channel(
        &mut self,
        id: String,
    ) -> Result<Box<dyn Channel<T, Error = std::io::Error>>, MuxerError> {
        let (sender, receiver) = oneshot::channel();
        let (client_channel, server_channel) = DuplexChannel::<T>::new();

        self.sender
            .send(Event::ClientOpen(id, Box::new(server_channel), sender))
            .await
            .map_err(|_| MuxerError::InternalError("Failed to get channel".to_string()))?;

        receiver
            .await
            .map_err(|_| MuxerError::InternalError("Failed to get channel".to_string()))??;

        Ok(Box::new(client_channel) as Box<dyn Channel<T, Error = std::io::Error>>)
    }
}

#[async_trait]
impl<T: Send + 'static> MuxChannelControl<T> for MockControl<Server> {
    async fn get_channel(
        &mut self,
        id: String,
    ) -> Result<Box<dyn Channel<T, Error = std::io::Error>>, MuxerError> {
        let (sender, receiver) = oneshot::channel();

        self.sender
            .send(Event::ServerOpen(id, sender))
            .await
            .map_err(|_| MuxerError::InternalError("Failed to get channel".to_string()))?;

        let channel = receiver
            .await
            .map_err(|_| MuxerError::InternalError("Failed to get channel".to_string()))??;

        let channel = channel
            .downcast::<DuplexChannel<T>>()
            .expect("Should downcast to DuplexChannel");

        Ok(channel as Box<dyn Channel<T, Error = std::io::Error>>)
    }
}

impl MockMuxer {
    pub fn new() -> (Self, MockControl<Client>, MockControl<Server>) {
        let (control_client_sender, control_receiver) = mpsc::channel(MAX_COMMAND_BACKLOG);
        let control_server_sender = control_client_sender.clone();

        (
            Self {
                control_receiver,
                client_channel_ids: HashSet::default(),
                server_channel_ids: HashSet::default(),
                client_buffer: HashMap::default(),
                server_buffer: HashMap::default(),
            },
            MockControl {
                _mode: PhantomData,
                sender: control_client_sender,
            },
            MockControl {
                _mode: PhantomData,
                sender: control_server_sender,
            },
        )
    }

    pub async fn run(mut self) -> Result<(), MuxerError> {
        loop {
            match self.control_receiver.next().await {
                Some(Event::ClientOpen(id, channel, sender)) => {
                    // Check if a channel has been opened with this id before
                    if self.client_channel_ids.contains(&id) {
                        _ = sender.send(Err(MuxerError::DuplicateStreamId(id)));
                        continue;
                    }

                    // Insert id into set to avoid duplicates
                    self.client_channel_ids.insert(id.clone());

                    if let Some(server_sender) = self.server_buffer.remove(&id) {
                        // Send to server control if it's already waiting
                        _ = server_sender.send(Ok(channel));
                    } else {
                        // Insert channel into buffer
                        self.client_buffer.insert(id, channel);
                    }

                    _ = sender.send(Ok(()));
                }
                Some(Event::ServerOpen(id, sender)) => {
                    // Check if a channel has been opened with this id before
                    if self.server_channel_ids.contains(&id) {
                        _ = sender.send(Err(MuxerError::DuplicateStreamId(id)));
                        continue;
                    }

                    // Insert id into set to avoid duplicates
                    self.server_channel_ids.insert(id.clone());

                    if let Some(channel) = self.client_buffer.remove(&id) {
                        // Return channel if it's already in the buffer
                        _ = sender.send(Ok(channel))
                    } else {
                        // Otherwise put the oneshot into waiting
                        self.server_buffer.insert(id, sender);
                    }
                }
                None => {
                    return Err(MuxerError::InternalError(
                        "Muxer task ended unexpectedly".to_string(),
                    ))
                }
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[derive(Clone)]
    pub struct Message(String);

    #[tokio::test]
    async fn test_open_channel() {
        let (mut client_control, mut server_control, mux_fut) = new_mock_mux();

        tokio::spawn(mux_fut);

        let mut client_channel = client_control
            .get_channel("test".to_string())
            .await
            .unwrap();
        let mut server_channel = server_control
            .get_channel("test".to_string())
            .await
            .unwrap();

        let msg_s = Message("test".to_string());
        client_channel.send(msg_s.clone()).await.unwrap();

        let msg_r: Message = server_channel.next().await.unwrap();

        assert_eq!(msg_s.0, msg_r.0);
    }
}
