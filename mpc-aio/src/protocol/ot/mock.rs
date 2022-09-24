use super::{OTError, ObliviousReceive, ObliviousSend};
use async_trait::async_trait;
use futures::{channel::mpsc, StreamExt};

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
impl<T> ObliviousSend for MockOTSender<T>
where
    T: Send + 'static,
{
    type Inputs = Vec<[T; 2]>;

    async fn send(&mut self, inputs: Self::Inputs) -> Result<(), OTError> {
        self.sender
            .try_send(inputs)
            .expect("DummySender should be able to send");
        Ok(())
    }
}

#[async_trait]
impl<T> ObliviousReceive for MockOTReceiver<T>
where
    T: Send + 'static,
{
    type Choice = bool;
    type Outputs = Vec<T>;

    async fn receive(&mut self, choices: &[bool]) -> Result<Vec<T>, OTError> {
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
                if *c {
                    high
                } else {
                    low
                }
            })
            .collect::<Vec<T>>())
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

        let received = receiver.receive(&choice).await.unwrap();
        assert_eq!(received, vec![0, 3]);
    }
}
