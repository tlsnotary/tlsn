use crate::twopc::TwoPCProtocol;
use async_trait::async_trait;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use mpc_core::secret_share::{
    SecretShare, SecretShareMasterCore, SecretShareMessage, SecretShareSlaveCore,
};
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

pub struct SecretShareSlave;

impl SecretShareSlave {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl TwoPCProtocol<SecretShareMessage> for SecretShareSlave {
    type Input = EncodedPoint;
    type Output = Result<SecretShare, ()>;

    async fn run<
        S: Sink<SecretShareMessage> + Stream<Item = Result<SecretShareMessage, E>> + Send + Unpin,
        E: std::fmt::Debug,
    >(
        &mut self,
        stream: &mut S,
        input: EncodedPoint,
    ) -> Result<SecretShare, ()>
    where
        <S as Sink<SecretShareMessage>>::Error: std::fmt::Debug,
    {
        let slave = SecretShareSlaveCore::new(&input);

        // Step 1
        let master_message = match stream.next().await {
            Some(Ok(SecretShareMessage::M1(m))) => m,
            Some(Err(e)) => panic!("{:?}", e),
            _ => panic!("io error"),
        };
        let (message, slave) = slave.next(master_message.into());
        stream.send(message.into()).await.unwrap();

        // Step 2
        let master_message = match stream.next().await {
            Some(Ok(SecretShareMessage::M2(m))) => m,
            Some(Err(e)) => panic!("{:?}", e),
            _ => panic!("io error"),
        };
        let (message, slave) = slave.next(master_message.into());
        stream.send(message.into()).await.unwrap();

        // Complete
        let master_message = match stream.next().await {
            Some(Ok(SecretShareMessage::M3(m))) => m,
            _ => panic!("io error"),
        };

        let (message, slave) = slave.next(master_message.into());
        stream.send(message.into()).await.unwrap();

        Ok(slave.secret())
    }
}
