use super::{
    OTError, ObliviousReceiveOwned, ObliviousRevealOwned, ObliviousSendOwned, ObliviousVerifyOwned,
};
use async_trait::async_trait;
use futures::{channel::mpsc, StreamExt};

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

#[cfg(test)]
mod tests {
    use super::*;

    // Test that the sender and receiver can be used to send and receive values
    #[tokio::test]
    async fn test_mock_ot_owned() {
        let values = vec![[0, 1], [2, 3]];
        let choice = vec![false, true];
        let (mut sender, mut receiver) = mock_ot_pair_owned::<u8>();

        sender.send(values).await.unwrap();

        let received = receiver.receive(choice).await.unwrap();
        assert_eq!(received, vec![0, 3]);
    }
}
