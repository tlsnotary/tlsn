use super::ObliviousReceive;
use crate::protocol::{ot::OTError, Protocol};
use async_trait::async_trait;
use futures::Stream;
use mpc_core::{
    msgs::ot::OTMessage,
    ot::{
        r_state::{self, ReceiverState},
        Kos15Receiver,
    },
};

impl<T: ReceiverState> Protocol for Kos15Receiver<T> {
    type Message = OTMessage;
    type Error = OTError;
}

#[async_trait]
impl ObliviousReceive for Kos15Receiver<r_state::RandSetup> {
    type Choices = ();
    type Outputs = ();

    async fn receive(&mut self, choices: Self::Choices) -> Result<Self::Outputs, OTError> {
        todo!()
    }
}
