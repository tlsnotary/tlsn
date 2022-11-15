use std::{
    any::Any,
    collections::{HashMap, HashSet},
    marker::PhantomData,
};

use async_trait::async_trait;

use futures::channel::oneshot;
use utils_aio::{
    duplex::DuplexChannel,
    mux::{MuxChannelControl, MuxerError},
    Channel,
};
use xtra::prelude::*;

pub struct OpenChannel<T> {
    id: String,
    _typ: PhantomData<T>,
}

impl<T> OpenChannel<T> {
    pub fn new(id: String) -> Self {
        Self {
            id,
            _typ: PhantomData,
        }
    }
}

struct ChannelOpened<T> {
    id: String,
    channel: DuplexChannel<T>,
}

#[derive(xtra::Actor)]
pub struct MockClientChannelMuxer {
    channel_ids: HashSet<String>,
    server_addr: Address<MockServerChannelMuxer>,
}

impl MockClientChannelMuxer {
    pub fn new(server_addr: Address<MockServerChannelMuxer>) -> Self {
        Self {
            channel_ids: HashSet::default(),
            server_addr,
        }
    }
}

#[derive(Default, xtra::Actor)]
pub struct MockServerChannelMuxer {
    channel_ids: HashSet<String>,
    channel_buffer: HashMap<String, Box<dyn Any + Send>>,
    pending_buffer: HashMap<String, Box<dyn Any + Send>>,
}

#[async_trait]
impl<T> Handler<OpenChannel<T>> for MockClientChannelMuxer
where
    T: Send + 'static,
{
    type Return = Result<DuplexChannel<T>, MuxerError>;

    async fn handle(
        &mut self,
        msg: OpenChannel<T>,
        _ctx: &mut Context<Self>,
    ) -> Result<DuplexChannel<T>, MuxerError> {
        if self.channel_ids.contains(&msg.id) {
            return Err(MuxerError::DuplicateStreamId(msg.id));
        }

        let (client, server) = DuplexChannel::<T>::new();
        self.server_addr
            .send(ChannelOpened {
                id: msg.id.clone(),
                channel: server,
            })
            .await
            .map_err(|e| MuxerError::InternalError(e.to_string()))?;
        self.channel_ids.insert(msg.id);

        Ok(client)
    }
}

#[async_trait]
impl<T> Handler<ChannelOpened<T>> for MockServerChannelMuxer
where
    T: Send + 'static,
{
    type Return = ();

    async fn handle(&mut self, msg: ChannelOpened<T>, _ctx: &mut Context<Self>) {
        if let Some(sender) = self.pending_buffer.remove(&msg.id) {
            let sender = sender
                .downcast::<oneshot::Sender<DuplexChannel<T>>>()
                .expect("channel type should be correct");
            _ = sender.send(msg.channel);
        } else {
            self.channel_buffer
                .insert(msg.id, Box::new(msg.channel) as Box<dyn Any + Send>);
        }
    }
}

#[async_trait]
impl<T> Handler<OpenChannel<T>> for MockServerChannelMuxer
where
    T: Send + 'static,
{
    type Return = oneshot::Receiver<Result<DuplexChannel<T>, MuxerError>>;

    async fn handle(
        &mut self,
        msg: OpenChannel<T>,
        _ctx: &mut Context<Self>,
    ) -> oneshot::Receiver<Result<DuplexChannel<T>, MuxerError>> {
        let (sender, receiver) = oneshot::channel();
        if self.channel_ids.contains(&msg.id) {
            _ = sender.send(Err(MuxerError::DuplicateStreamId(msg.id)));
            return receiver;
        }

        if let Some(channel) = self.channel_buffer.remove(&msg.id) {
            let channel = *channel
                .downcast::<DuplexChannel<T>>()
                .expect("channel type should be correct");
            _ = sender.send(Ok(channel));
        } else {
            let sender = Box::new(sender) as Box<dyn Any + Send>;
            self.pending_buffer.insert(msg.id.clone(), sender);
        }
        self.channel_ids.insert(msg.id);

        receiver
    }
}

#[derive(Clone)]
pub struct MockClientControl(Address<MockClientChannelMuxer>);

impl MockClientControl {
    pub fn new(addr: Address<MockClientChannelMuxer>) -> Self {
        Self(addr)
    }
}

#[derive(Clone)]
pub struct MockServerControl(Address<MockServerChannelMuxer>);

impl MockServerControl {
    pub fn new(addr: Address<MockServerChannelMuxer>) -> Self {
        Self(addr)
    }
}

#[async_trait]
impl<T: Send + 'static> MuxChannelControl<T> for MockClientControl {
    async fn get_channel(
        &mut self,
        id: String,
    ) -> Result<Box<dyn Channel<T, Error = std::io::Error>>, MuxerError> {
        self.0
            .send(OpenChannel::new(id))
            .await
            .map_err(|_| MuxerError::InternalError("Failed to get channel".to_string()))?
            .map(|channel| Box::new(channel) as Box<dyn Channel<T, Error = std::io::Error>>)
    }
}

#[async_trait]
impl<T: Send + 'static> MuxChannelControl<T> for MockServerControl {
    async fn get_channel(
        &mut self,
        id: String,
    ) -> Result<Box<dyn Channel<T, Error = std::io::Error>>, MuxerError> {
        self.0
            .send(OpenChannel::new(id))
            .await
            .map_err(|_| MuxerError::InternalError("Failed to get channel".to_string()))?
            .await
            .map_err(|_| MuxerError::InternalError("Failed to get channel".to_string()))?
            .map(|channel| Box::new(channel) as Box<dyn Channel<T, Error = std::io::Error>>)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[derive(Debug, Clone)]
    pub struct Message(String);

    fn create_pair() -> (
        Address<MockClientChannelMuxer>,
        Address<MockServerChannelMuxer>,
    ) {
        let server_addr =
            xtra::spawn_tokio(MockServerChannelMuxer::default(), Mailbox::unbounded());

        let client_addr = xtra::spawn_tokio(
            MockClientChannelMuxer::new(server_addr.clone()),
            Mailbox::unbounded(),
        );

        (client_addr, server_addr)
    }

    #[tokio::test]
    async fn test_open_channel() {
        let (client_addr, server_addr) = create_pair();
        let mut client_control = MockClientControl::new(client_addr);
        let mut server_control = MockServerControl::new(server_addr);

        let id = "test".to_string();

        let _: Box<dyn Channel<Message, Error = std::io::Error>> =
            client_control.get_channel(id.clone()).await.unwrap();
        let _: Box<dyn Channel<Message, Error = std::io::Error>> =
            server_control.get_channel(id.clone()).await.unwrap();
    }

    #[tokio::test]
    async fn test_no_duplicates() {
        let (client_addr, server_addr) = create_pair();
        let mut client_control = MockClientControl::new(client_addr);
        let mut server_control = MockServerControl::new(server_addr);

        let id = "test".to_string();

        let _: Box<dyn Channel<Message, Error = std::io::Error>> =
            client_control.get_channel(id.clone()).await.unwrap();
        let err: Result<Box<dyn Channel<Message, Error = std::io::Error>>, _> =
            client_control.get_channel(id.clone()).await;

        assert!(matches!(err, Err(MuxerError::DuplicateStreamId(_))));

        let _: Box<dyn Channel<Message, Error = std::io::Error>> =
            server_control.get_channel(id.clone()).await.unwrap();
        let err: Result<Box<dyn Channel<Message, Error = std::io::Error>>, _> =
            server_control.get_channel(id.clone()).await;

        assert!(matches!(err, Err(MuxerError::DuplicateStreamId(_))));
    }
}
