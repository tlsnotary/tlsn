use crate::{OTReceiveOwned, OTRevealOwned, OTSendOwned, OTVerifyOwned};
use async_trait::async_trait;
use futures::channel::oneshot;
use mpc_ot::OTError;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

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
impl<T: std::fmt::Debug + Send> OTSendOwned<T> for MockOTSenderControl<T> {
    async fn send(&self, id: &str, input: T) -> Result<(), OTError> {
        if let Some(sender) = self.receiver_buffer.lock().unwrap().remove(id) {
            sender
                .send(input)
                .expect("MockOTSend should be able to send");
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
impl<T: Send> OTRevealOwned for MockOTSenderControl<T> {
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
impl<T: Send + Copy> OTReceiveOwned<bool, T> for MockOTReceiverControl<[T; 2]> {
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
impl<T: Send> OTVerifyOwned<T> for MockOTReceiverControl<T> {
    async fn verify(&self, _id: &str, _input: T) -> Result<(), OTError> {
        // MockOT is always honest
        Ok(())
    }
}
