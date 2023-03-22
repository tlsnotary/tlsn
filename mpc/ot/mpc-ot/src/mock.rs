use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use super::{
    config::{OTReceiverConfig, OTSenderConfig},
    OTError, OTFactoryError, ObliviousReceive, ObliviousReveal, ObliviousSend, ObliviousVerify,
};
use async_trait::async_trait;
use futures::{channel::mpsc, StreamExt};
use utils_aio::factory::AsyncFactory;

struct FactoryState<T> {
    sender_buffer: HashMap<String, MockOTSender<T>>,
    receiver_buffer: HashMap<String, MockOTReceiver<T>>,
}

#[derive(Clone)]
pub struct MockOTFactory<T> {
    state: Arc<Mutex<FactoryState<T>>>,
}

impl<T> MockOTFactory<T> {
    pub fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(FactoryState {
                sender_buffer: HashMap::new(),
                receiver_buffer: HashMap::new(),
            })),
        }
    }
}

#[async_trait]
impl<T> AsyncFactory<MockOTSender<T>> for MockOTFactory<T>
where
    T: Send + 'static,
{
    type Config = OTSenderConfig;

    type Error = OTFactoryError;

    async fn create(
        &mut self,
        id: String,
        _config: Self::Config,
    ) -> Result<MockOTSender<T>, Self::Error> {
        let mut factory = self.state.lock().unwrap();
        let sender = if let Some(sender) = factory.sender_buffer.remove(&id) {
            sender
        } else {
            let (sender, receiver) = mock_ot_pair::<T>();
            factory.receiver_buffer.insert(id, receiver);
            sender
        };
        Ok(sender)
    }
}

#[async_trait]
impl<T> AsyncFactory<MockOTReceiver<T>> for MockOTFactory<T>
where
    T: Send + 'static,
{
    type Config = OTReceiverConfig;

    type Error = OTFactoryError;

    async fn create(
        &mut self,
        id: String,
        _config: Self::Config,
    ) -> Result<MockOTReceiver<T>, Self::Error> {
        let mut factory = self.state.lock().unwrap();
        let receiver = if let Some(receiver) = factory.receiver_buffer.remove(&id) {
            receiver
        } else {
            let (sender, receiver) = mock_ot_pair::<T>();
            factory.sender_buffer.insert(id, sender);
            receiver
        };
        Ok(receiver)
    }
}

pub struct MockOTSender<T> {
    sender: mpsc::Sender<Vec<[T; 2]>>,
}

pub struct MockOTReceiver<T> {
    receiver: mpsc::Receiver<Vec<[T; 2]>>,
}

pub fn mock_ot_pair<T: Send + 'static>() -> (MockOTSender<T>, MockOTReceiver<T>) {
    let (sender, receiver) = mpsc::channel::<Vec<[T; 2]>>(10);
    (MockOTSender { sender }, MockOTReceiver { receiver })
}

#[async_trait]
impl<T> ObliviousSend<[T; 2]> for MockOTSender<T>
where
    T: Send + 'static,
{
    async fn send(&mut self, inputs: Vec<[T; 2]>) -> Result<(), OTError> {
        self.sender
            .try_send(inputs)
            .expect("DummySender should be able to send");
        Ok(())
    }
}

#[async_trait]
impl<T> ObliviousReceive<bool, T> for MockOTReceiver<T>
where
    T: Send + 'static,
{
    async fn receive(&mut self, choices: Vec<bool>) -> Result<Vec<T>, OTError> {
        let payload = self
            .receiver
            .next()
            .await
            .expect("DummySender should send a value");
        Ok(payload
            .into_iter()
            .zip(choices)
            .map(|(v, c)| {
                let [low, high] = v;
                if c {
                    high
                } else {
                    low
                }
            })
            .collect::<Vec<T>>())
    }
}

#[async_trait]
impl<T> ObliviousVerify<[T; 2]> for MockOTReceiver<T>
where
    T: Send + 'static,
{
    async fn verify(self, _input: Vec<[T; 2]>) -> Result<(), OTError> {
        // MockOT is always honest
        Ok(())
    }
}

#[async_trait]
impl<T> ObliviousReveal for MockOTSender<T>
where
    T: Send + 'static,
{
    async fn reveal(mut self) -> Result<(), OTError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test that the sender and receiver can be used to send and receive values
    #[tokio::test]
    async fn test_mock_ot() {
        let values = vec![[0, 1], [2, 3]];
        let choice = vec![false, true];
        let (mut sender, mut receiver) = mock_ot_pair::<u8>();

        sender.send(values).await.unwrap();

        let received = receiver.receive(choice).await.unwrap();
        assert_eq!(received, vec![0, 3]);
    }

    // Test that the factory can be used to create a sender and receiver
    #[tokio::test]
    async fn test_mock_ot_factory() {
        let values = vec![[0, 1], [2, 3]];
        let choice = vec![false, true];
        let mut factory = MockOTFactory::new();

        let mut sender: MockOTSender<u8> = factory
            .create(
                "test".to_string(),
                OTSenderConfig {
                    count: values.len(),
                },
            )
            .await
            .unwrap();

        let mut receiver: MockOTReceiver<u8> = factory
            .create(
                "test".to_string(),
                OTReceiverConfig {
                    count: choice.len(),
                },
            )
            .await
            .unwrap();

        sender.send(values).await.unwrap();

        let received = receiver.receive(choice).await.unwrap();
        assert_eq!(received, vec![0, 3]);
    }
}
