pub mod errors;

use errors::*;
use futures_util::{SinkExt, StreamExt};
use mpc_core::ot;
use mpc_core::proto;
use mpc_core::Block;
use prost::Message as ProtoMessage;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{tungstenite::protocol::Message, WebSocketStream};

pub struct OtSender<OT> {
    ot: OT,
}

pub struct OtReceiver<OT> {
    ot: OT,
}

impl<OT: ot::OtSend> OtSender<OT> {
    pub fn new(ot: OT) -> Self {
        Self { ot }
    }

    pub async fn send<S: AsyncWrite + AsyncRead + Unpin>(
        &mut self,
        stream: &mut WebSocketStream<S>,
        inputs: &[[Block; 2]],
    ) -> Result<(), OtSenderError> {
        let base_sender_setup = match stream.next().await {
            Some(message) => {
                proto::BaseOtSenderSetup::decode(message.unwrap().into_data().as_slice())
                    .expect("Expected BaseOtSenderSetup")
            }
            _ => return Err(OtSenderError::MalformedMessage),
        };

        let base_setup = self.ot.base_setup(base_sender_setup.try_into().unwrap())?;

        stream
            .send(Message::Binary(
                proto::BaseOtReceiverSetup::from(base_setup).encode_to_vec(),
            ))
            .await
            .unwrap();

        let base_payload = match stream.next().await {
            Some(message) => {
                proto::BaseOtSenderPayload::decode(message.unwrap().into_data().as_slice())
                    .expect("Expected BaseOtSenderPayload")
            }
            _ => return Err(OtSenderError::MalformedMessage),
        };
        self.ot.base_receive(base_payload.try_into().unwrap())?;

        let extension_receiver_setup = match stream.next().await {
            Some(message) => {
                proto::OtReceiverSetup::decode(message.unwrap().into_data().as_slice())
                    .expect("Expected OtReceiverSetup")
            }
            _ => return Err(OtSenderError::MalformedMessage),
        };

        self.ot
            .extension_setup(extension_receiver_setup.try_into().unwrap())?;
        let payload: ot::OtSenderPayload = self.ot.send(inputs)?;

        stream
            .send(Message::Binary(
                proto::OtSenderPayload::from(payload).encode_to_vec(),
            ))
            .await
            .unwrap();

        Ok(())
    }
}

impl<OT: ot::OtReceive> OtReceiver<OT> {
    pub fn new(ot: OT) -> Self {
        Self { ot }
    }

    pub async fn receive<S: AsyncWrite + AsyncRead + Unpin>(
        &mut self,
        stream: &mut WebSocketStream<S>,
        choice: &[bool],
    ) -> Result<Vec<Block>, OtReceiverError> {
        let base_setup = self.ot.base_setup()?;

        stream
            .send(Message::Binary(
                proto::BaseOtSenderSetup::from(base_setup).encode_to_vec(),
            ))
            .await
            .unwrap();

        let base_receiver_setup = match stream.next().await {
            Some(message) => {
                proto::BaseOtReceiverSetup::decode(message.unwrap().into_data().as_slice())
                    .expect("Expected BaseOtReceiverSetup")
            }
            _ => return Err(OtReceiverError::MalformedMessage),
        };

        let payload = self.ot.base_send(base_receiver_setup.try_into().unwrap())?;

        stream
            .send(Message::Binary(
                proto::BaseOtSenderPayload::from(payload).encode_to_vec(),
            ))
            .await
            .unwrap();

        let setup = self.ot.extension_setup(choice)?;

        stream
            .send(Message::Binary(
                proto::OtReceiverSetup::from(setup).encode_to_vec(),
            ))
            .await
            .unwrap();

        let payload = match stream.next().await {
            Some(message) => {
                proto::OtSenderPayload::decode(message.unwrap().into_data().as_slice())
                    .expect("Expected OtSenderPayload")
            }
            _ => return Err(OtReceiverError::MalformedMessage),
        };

        let values = self.ot.receive(choice, payload.try_into().unwrap())?;

        Ok(values)
    }
}
