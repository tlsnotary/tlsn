use std::sync::{Arc, Mutex};

use super::{
    config::{OTReceiverConfig, OTSenderConfig},
    OTError, OTFactoryError, ObliviousReceive, ObliviousReveal, ObliviousSend, ObliviousVerify,
};
use async_trait::async_trait;
use futures::{channel::mpsc, StreamExt};
use utils_aio::factory::AsyncFactory;

#[derive(Default)]
pub struct MockOTFactory<T> {
    waiting_sender: Option<MockOTSender<T>>,
    waiting_receiver: Option<MockOTReceiver<T>>,
}

#[async_trait]
impl<T: Send + 'static> AsyncFactory<MockOTSender<T>> for Arc<Mutex<MockOTFactory<T>>> {
    type Config = OTSenderConfig;
    type Error = OTFactoryError;

    async fn create(
        &mut self,
        _id: String,
        _config: OTSenderConfig,
    ) -> Result<MockOTSender<T>, OTFactoryError> {
        let mut inner = self.lock().unwrap();
        if inner.waiting_sender.is_some() {
            Ok(inner.waiting_sender.take().unwrap())
        } else {
            let (sender, receiver) = mock_ot_pair::<T>();
            inner.waiting_receiver = Some(receiver);
            Ok(sender)
        }
    }
}

#[async_trait]
impl<T: Send + 'static> AsyncFactory<MockOTReceiver<T>> for Arc<Mutex<MockOTFactory<T>>> {
    type Config = OTReceiverConfig;
    type Error = OTFactoryError;

    async fn create(
        &mut self,
        _id: String,
        _config: OTReceiverConfig,
    ) -> Result<MockOTReceiver<T>, OTFactoryError> {
        let mut inner = self.lock().unwrap();
        if inner.waiting_receiver.is_some() {
            Ok(inner.waiting_receiver.take().unwrap())
        } else {
            let (sender, receiver) = mock_ot_pair::<T>();
            inner.waiting_sender = Some(sender);
            Ok(receiver)
        }
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
