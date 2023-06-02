use super::OTError;
use crate::{ObliviousReceive, ObliviousReveal, ObliviousSend, ObliviousVerify};
use async_trait::async_trait;
use futures::channel::oneshot;
use std::{
    any::Any,
    collections::HashMap,
    sync::{Arc, Mutex},
};

pub fn mock_ot_pair() -> (MockOTSender, MockOTReceiver) {
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

#[derive(Clone, Debug)]
pub struct MockOTSender {
    sender_buffer: Arc<Mutex<HashMap<String, Box<dyn Any + Send + 'static>>>>,
    receiver_buffer: Arc<Mutex<HashMap<String, oneshot::Sender<Box<dyn Any + Send + 'static>>>>>,
}

#[async_trait]
impl<T: std::fmt::Debug + Send + 'static> ObliviousSend<[T; 2]> for MockOTSender {
    async fn send(&self, id: &str, input: Vec<[T; 2]>) -> Result<(), OTError> {
        let input = Box::new(input);
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
impl ObliviousReveal for MockOTSender {
    async fn reveal(&self) -> Result<(), OTError> {
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct MockOTReceiver {
    sender_buffer: Arc<Mutex<HashMap<String, Box<dyn Any + Send + 'static>>>>,
    receiver_buffer: Arc<Mutex<HashMap<String, oneshot::Sender<Box<dyn Any + Send + 'static>>>>>,
}

#[async_trait]
impl<T: Send + Copy + 'static> ObliviousReceive<bool, T> for MockOTReceiver {
    async fn receive(&self, id: &str, choice: Vec<bool>) -> Result<Vec<T>, OTError> {
        if let Some(value) = self.sender_buffer.lock().unwrap().remove(id) {
            let value = *value
                .downcast::<Vec<[T; 2]>>()
                .expect("value type should be consistent");

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

        let values = receiver.await.unwrap();

        let values = *values
            .downcast::<Vec<[T; 2]>>()
            .expect("value type should be consistent");

        Ok(values
            .into_iter()
            .zip(choice)
            .map(|(v, c)| v[c as usize])
            .collect::<Vec<T>>())
    }
}

#[async_trait]
impl<T: Send + 'static> ObliviousVerify<[T; 2]> for MockOTReceiver {
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
        let (sender, receiver) = mock_ot_pair();

        sender.send("", values).await.unwrap();

        let received: Vec<i32> = receiver.receive("", choice).await.unwrap();
        assert_eq!(received, vec![0, 3]);
    }
}
