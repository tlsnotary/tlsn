use super::OTError;
use crate::{ObliviousReceive, ObliviousReveal, ObliviousSend, ObliviousVerify};
use async_trait::async_trait;
use futures::channel::oneshot;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

pub fn mock_ot_pair<T: Send + Copy>() -> (MockOTSender<T>, MockOTReceiver<T>) {
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
    sender_buffer: Arc<Mutex<HashMap<String, Vec<[T; 2]>>>>,
    receiver_buffer: Arc<Mutex<HashMap<String, oneshot::Sender<Vec<[T; 2]>>>>>,
}

#[async_trait]
impl<T: std::fmt::Debug + Send> ObliviousSend<[T; 2]> for MockOTSender<T> {
    async fn send(&self, id: &str, input: Vec<[T; 2]>) -> Result<(), OTError> {
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
    sender_buffer: Arc<Mutex<HashMap<String, Vec<[T; 2]>>>>,
    receiver_buffer: Arc<Mutex<HashMap<String, oneshot::Sender<Vec<[T; 2]>>>>>,
}

#[async_trait]
impl<T: Send + Copy> ObliviousReceive<bool, T> for MockOTReceiver<T> {
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
impl<T: Send> ObliviousVerify<[T; 2]> for MockOTReceiver<T> {
    async fn verify(&self, _id: &str, _input: Vec<[T; 2]>) -> Result<(), OTError> {
        // MockOT is always honest
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
        let (sender, receiver) = mock_ot_pair::<i32>();

        sender.send("", values).await.unwrap();

        let received = receiver.receive("", choice).await.unwrap();
        assert_eq!(received, vec![0, 3]);
    }
}
