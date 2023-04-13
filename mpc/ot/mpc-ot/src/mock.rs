use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::{OTReceive, OTReveal, OTSend, OTVerify};

use super::{
    OTError, ObliviousReceiveOwned, ObliviousRevealOwned, ObliviousSendOwned, ObliviousVerifyOwned,
};
use async_trait::async_trait;
use futures::{
    channel::{mpsc, oneshot},
    StreamExt,
};

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
impl<T> ObliviousSendOwned<[T; 2]> for MockOTSender<T>
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
impl<T> ObliviousReceiveOwned<bool, T> for MockOTReceiver<T>
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
impl<T> ObliviousVerifyOwned<[T; 2]> for MockOTReceiver<T>
where
    T: Send + 'static,
{
    async fn verify(self, _input: Vec<[T; 2]>) -> Result<(), OTError> {
        // MockOT is always honest
        Ok(())
    }
}

#[async_trait]
impl<T> ObliviousRevealOwned for MockOTSender<T>
where
    T: Send + 'static,
{
    async fn reveal(mut self) -> Result<(), OTError> {
        Ok(())
    }
}

pub fn create_mock_ot_control_pair<T: Send + Copy>(
) -> (MockOTSenderControl<[T; 2]>, MockOTReceiverControl<[T; 2]>) {
    let sender_buffer = Arc::new(Mutex::new(HashMap::new()));
    let receiver_buffer = Arc::new(Mutex::new(HashMap::new()));

    let sender = MockOTSenderControl {
        sender_buffer: sender_buffer.clone(),
        receiver_buffer: receiver_buffer.clone(),
    };

    let receiver = MockOTReceiverControl {
        sender_buffer,
        receiver_buffer,
    };

    (sender, receiver)
}

#[derive(Clone)]
pub struct MockOTSenderControl<T> {
    sender_buffer: Arc<Mutex<HashMap<String, T>>>,
    receiver_buffer: Arc<Mutex<HashMap<String, oneshot::Sender<T>>>>,
}

#[async_trait]
impl<T: std::fmt::Debug + Send> OTSend<T> for MockOTSenderControl<T> {
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
impl<T: Send> OTReveal for MockOTSenderControl<T> {
    async fn reveal(&self) -> Result<(), OTError> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct MockOTReceiverControl<T> {
    sender_buffer: Arc<Mutex<HashMap<String, T>>>,
    receiver_buffer: Arc<Mutex<HashMap<String, oneshot::Sender<T>>>>,
}

#[async_trait]
impl<T: Send + Copy> OTReceive<bool, T> for MockOTReceiverControl<[T; 2]> {
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
impl<T: Send> OTVerify<T> for MockOTReceiverControl<T> {
    async fn verify(&self, _id: &str, _input: T) -> Result<(), OTError> {
        // MockOT is always honest
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
}
