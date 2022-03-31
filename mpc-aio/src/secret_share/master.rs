use crate::twopc::TwoPCProtocol;
use async_trait::async_trait;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use mpc_core::secret_share::{SecretShare, SecretShareMasterCore, SecretShareMessage};
use p256::EncodedPoint;

pub struct SecretShareMaster;

impl SecretShareMaster {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TwoPCProtocol<SecretShareMessage> for SecretShareMaster {
    type Input = EncodedPoint;
    type Output = Result<SecretShare, ()>;

    async fn run<
        S: Sink<SecretShareMessage> + Stream<Item = Result<SecretShareMessage, E>> + Send + Unpin,
        E: std::fmt::Debug,
    >(
        &mut self,
        stream: &mut S,
        input: Self::Input,
    ) -> Self::Output
    where
        <S as Sink<SecretShareMessage>>::Error: std::fmt::Debug,
    {
        let master = SecretShareMasterCore::new(&input);

        // Step 1
        let (message, master) = master.next();
        stream.send(message.into()).await.unwrap();
        let slave_message = match stream.next().await {
            Some(Ok(SecretShareMessage::S1(m))) => m,
            _ => panic!("io error"),
        };

        // Step 2
        let (message, master) = master.next(slave_message.into());
        stream.send(message.into()).await.unwrap();
        let slave_message = match stream.next().await {
            Some(Ok(SecretShareMessage::S2(m))) => m,
            _ => panic!("io error"),
        };

        // Step 3
        let (message, master) = master.next(slave_message.into());
        stream.send(message.into()).await.unwrap();
        let slave_message = match stream.next().await {
            Some(Ok(SecretShareMessage::S3(m))) => m,
            _ => panic!("io error"),
        };

        // Complete
        let master = master.next(slave_message.into());

        Ok(master.secret())
    }
}
