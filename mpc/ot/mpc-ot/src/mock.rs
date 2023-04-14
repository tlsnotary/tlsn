use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::{ObliviousReceive, ObliviousReveal, ObliviousSend, ObliviousVerify};

use super::{
    OTError, ObliviousReceiveOwned, ObliviousRevealOwned, ObliviousSendOwned, ObliviousVerifyOwned,
};
use async_trait::async_trait;
use futures::{
    channel::{mpsc, oneshot},
    StreamExt,
};
use mpc_ot_core::config::{OTReceiverConfig, OTSenderConfig};
use utils_aio::factory::AsyncFactory;

pub struct MockOTSenderOwned<T> {
    sender: mpsc::Sender<Vec<[T; 2]>>,
}

pub struct MockOTReceiverOwned<T> {
    receiver: mpsc::Receiver<Vec<[T; 2]>>,
}

pub fn mock_ot_pair_owned<T: Send + 'static>() -> (MockOTSenderOwned<T>, MockOTReceiverOwned<T>) {
    let (sender, receiver) = mpsc::channel::<Vec<[T; 2]>>(10);
    (
        MockOTSenderOwned { sender },
        MockOTReceiverOwned { receiver },
    )
}

#[async_trait]
impl<T> ObliviousSendOwned<[T; 2]> for MockOTSenderOwned<T>
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
impl<T> ObliviousReceiveOwned<bool, T> for MockOTReceiverOwned<T>
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
impl<T> ObliviousVerifyOwned<[T; 2]> for MockOTReceiverOwned<T>
where
    T: Send + 'static,
{
    async fn verify(self, _input: Vec<[T; 2]>) -> Result<(), OTError> {
        // MockOT is always honest
        Ok(())
    }
}

#[async_trait]
impl<T> ObliviousRevealOwned for MockOTSenderOwned<T>
where
    T: Send + 'static,
{
    async fn reveal(mut self) -> Result<(), OTError> {
        Ok(())
    }
}

pub fn create_mock_ot_pair<T: Send + Copy>() -> (MockOTSender<[T; 2]>, MockOTReceiver<[T; 2]>) {
    let sender_buffer = Arc::new(Mutex::new(HashMap::new()));
    let receiver_buffer = Arc::new(Mutex::new(HashMap::new()));

    let sender = MockOTSender {
        sender_buffer: sender_buffer.clone(),
        receiver_buffer: receiver_buffer.clone(),
    };

    let receiver = MockOTReceiver {
        sender_buffer,
        receiver_buffer,
    };

    (sender, receiver)
}

#[derive(Clone)]
pub struct MockOTSender<T> {
    sender_buffer: Arc<Mutex<HashMap<String, T>>>,
    receiver_buffer: Arc<Mutex<HashMap<String, oneshot::Sender<T>>>>,
}

#[async_trait]
impl<T: std::fmt::Debug + Send> ObliviousSend<T> for MockOTSender<T> {
    async fn send(&self, id: &str, input: T) -> Result<(), OTError> {
        if let Some(sender) = self.receiver_buffer.lock().unwrap().remove(id) {
            sender
                .send(input)
                .expect("MockOTSenderControl should be able to send");
        } else {
            self.sender_buffer
                .lock()
                .unwrap()
                .insert(id.to_string(), input);
        }
        Ok(())
    }
}

#[async_trait]
impl<T: Send> ObliviousReveal for MockOTSender<T> {
    async fn reveal(&self) -> Result<(), OTError> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct MockOTReceiver<T> {
    sender_buffer: Arc<Mutex<HashMap<String, T>>>,
    receiver_buffer: Arc<Mutex<HashMap<String, oneshot::Sender<T>>>>,
}

#[async_trait]
impl<T: Send + Copy> ObliviousReceive<bool, T> for MockOTReceiver<[T; 2]> {
    async fn receive(&self, id: &str, choice: bool) -> Result<T, OTError> {
        if let Some(value) = self.sender_buffer.lock().unwrap().remove(id) {
            return Ok(value[choice as usize]);
        }

        let (sender, receiver) = oneshot::channel();
        self.receiver_buffer
            .lock()
            .unwrap()
            .insert(id.to_string(), sender);

        Ok(receiver.await.unwrap()[choice as usize])
    }
}

#[async_trait]
impl<T: Send + Copy> ObliviousReceive<Vec<bool>, Vec<T>> for MockOTReceiver<Vec<[T; 2]>> {
    async fn receive(&self, id: &str, choice: Vec<bool>) -> Result<Vec<T>, OTError> {
        if let Some(value) = self.sender_buffer.lock().unwrap().remove(id) {
            return Ok(value
                .into_iter()
                .zip(choice)
                .map(|(v, c)| v[c as usize])
                .collect::<Vec<T>>());
        }

        let (sender, receiver) = oneshot::channel();
        self.receiver_buffer
            .lock()
            .unwrap()
            .insert(id.to_string(), sender);

        Ok(receiver
            .await
            .unwrap()
            .into_iter()
            .zip(choice)
            .map(|(v, c)| v[c as usize])
            .collect::<Vec<T>>())
    }
}

#[async_trait]
impl<T: Send> ObliviousVerify<T> for MockOTReceiver<T> {
    async fn verify(&self, _id: &str, _input: T) -> Result<(), OTError> {
        // MockOT is always honest
        Ok(())
    }
}

struct FactoryState<T> {
    sender_buffer: HashMap<String, MockOTSenderOwned<T>>,
    receiver_buffer: HashMap<String, MockOTReceiverOwned<T>>,
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
impl<T> AsyncFactory<MockOTSenderOwned<T>> for MockOTFactory<T>
where
    T: Send + 'static,
{
    type Config = OTSenderConfig;

    type Error = OTError;

    async fn create(
        &mut self,
        id: String,
        _config: Self::Config,
    ) -> Result<MockOTSenderOwned<T>, Self::Error> {
        let mut factory = self.state.lock().unwrap();
        let sender = if let Some(sender) = factory.sender_buffer.remove(&id) {
            sender
        } else {
            let (sender, receiver) = mock_ot_pair_owned::<T>();
            factory.receiver_buffer.insert(id, receiver);
            sender
        };
        Ok(sender)
    }
}

#[async_trait]
impl<T> AsyncFactory<MockOTReceiverOwned<T>> for MockOTFactory<T>
where
    T: Send + 'static,
{
    type Config = OTReceiverConfig;

    type Error = OTError;

    async fn create(
        &mut self,
        id: String,
        _config: Self::Config,
    ) -> Result<MockOTReceiverOwned<T>, Self::Error> {
        let mut factory = self.state.lock().unwrap();
        let receiver = if let Some(receiver) = factory.receiver_buffer.remove(&id) {
            receiver
        } else {
            let (sender, receiver) = mock_ot_pair_owned::<T>();
            factory.sender_buffer.insert(id, sender);
            receiver
        };
        Ok(receiver)
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
        let (mut sender, mut receiver) = mock_ot_pair_owned::<u8>();

        sender.send(values).await.unwrap();

        let received = receiver.receive(choice).await.unwrap();
        assert_eq!(received, vec![0, 3]);
    }
}
