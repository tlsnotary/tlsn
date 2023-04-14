use super::{
    OTError, ObliviousReceiveOwned, ObliviousRevealOwned, ObliviousSendOwned, ObliviousVerifyOwned,
};
use async_trait::async_trait;
use mpc_ot_core::config::{OTReceiverConfig, OTSenderConfig};
use owned::{mock_ot_pair_owned, MockOTReceiverOwned, MockOTSenderOwned};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use utils_aio::factory::AsyncFactory;

pub mod borrowed;
pub mod owned;

pub use borrowed::*;
pub use owned::*;

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
