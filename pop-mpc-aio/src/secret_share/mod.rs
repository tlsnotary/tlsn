use futures_util::{SinkExt, StreamExt};
use p256::EncodedPoint;
use pop_mpc_core::proto;
use pop_mpc_core::secret_share::{SecretShare, SecretShareMaster, SecretShareSlave};
use prost::Message as ProtoMessage;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{tungstenite::protocol::Message, WebSocketStream};

pub struct AsyncSecretShareMaster;

impl AsyncSecretShareMaster {
    pub fn new() -> Self {
        Self
    }

    pub async fn run<S: AsyncWrite + AsyncRead + Unpin>(
        &mut self,
        stream: &mut WebSocketStream<S>,
        point: &EncodedPoint,
    ) -> Result<SecretShare, ()> {
        let master = SecretShareMaster::new(&point);

        // Step 1
        let (message, master) = master.next();
        stream
            .send(Message::Binary(
                proto::secret_share::MasterStepOne::from(message).encode_to_vec(),
            ))
            .await
            .unwrap();
        let slave_message = match stream.next().await {
            Some(message) => {
                proto::secret_share::SlaveStepOne::decode(message.unwrap().into_data().as_slice())
                    .expect("Expected SlaveStepOne")
            }
            _ => return Err(()),
        };

        // Step 2
        let (message, master) = master.next(slave_message.into());
        stream
            .send(Message::Binary(
                proto::secret_share::MasterStepTwo::from(message).encode_to_vec(),
            ))
            .await
            .unwrap();
        let slave_message = match stream.next().await {
            Some(message) => {
                proto::secret_share::SlaveStepTwo::decode(message.unwrap().into_data().as_slice())
                    .expect("Expected SlaveStepTwo")
            }
            _ => return Err(()),
        };

        // Step 3
        let (message, master) = master.next(slave_message.into());
        stream
            .send(Message::Binary(
                proto::secret_share::MasterStepThree::from(message).encode_to_vec(),
            ))
            .await
            .unwrap();
        let slave_message = match stream.next().await {
            Some(message) => {
                proto::secret_share::SlaveStepThree::decode(message.unwrap().into_data().as_slice())
                    .expect("Expected SlaveStepThree")
            }
            _ => return Err(()),
        };

        // Complete
        let master = master.next(slave_message.into());

        Ok(master.secret())
    }
}

pub struct AsyncSecretShareSlave;

impl AsyncSecretShareSlave {
    pub fn new() -> Self {
        Self
    }

    pub async fn run<S: AsyncWrite + AsyncRead + Unpin>(
        &mut self,
        stream: &mut WebSocketStream<S>,
        point: &EncodedPoint,
    ) -> Result<SecretShare, ()> {
        let slave = SecretShareSlave::new(&point);

        // Step 1
        let master_message = match stream.next().await {
            Some(message) => {
                proto::secret_share::MasterStepOne::decode(message.unwrap().into_data().as_slice())
                    .expect("Expected MasterStepOne")
            }
            _ => return Err(()),
        };
        let (message, slave) = slave.next(master_message.into());
        stream
            .send(Message::Binary(
                proto::secret_share::SlaveStepOne::from(message).encode_to_vec(),
            ))
            .await
            .unwrap();

        // Step 2
        let master_message = match stream.next().await {
            Some(message) => {
                proto::secret_share::MasterStepTwo::decode(message.unwrap().into_data().as_slice())
                    .expect("Expected MasterStepTwo")
            }
            _ => return Err(()),
        };
        let (message, slave) = slave.next(master_message.into());
        stream
            .send(Message::Binary(
                proto::secret_share::SlaveStepTwo::from(message).encode_to_vec(),
            ))
            .await
            .unwrap();

        // Complete
        let master_message = match stream.next().await {
            Some(message) => proto::secret_share::MasterStepThree::decode(
                message.unwrap().into_data().as_slice(),
            )
            .expect("Expected MasterStepThree"),
            _ => return Err(()),
        };

        let (message, slave) = slave.next(master_message.into());
        stream
            .send(Message::Binary(
                proto::secret_share::SlaveStepThree::from(message).encode_to_vec(),
            ))
            .await
            .unwrap();

        Ok(slave.secret())
    }
}
