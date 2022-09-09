use super::ObliviousReceive;
use crate::protocol::{ot::OTError, Agent, Protocol};
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

impl Agent<Kos15Receiver<r_state::Initialized>> {
    pub fn new(
        stream: Box<dyn Stream<Item = OTMessage> + Send>,
    ) -> (Box<dyn Stream<Item = OTMessage> + Send>, Self) {
        todo!()
    }

    fn setup(self) -> Kos15Receiver<r_state::Setup> {
        todo!()
    }
}

#[async_trait]
impl ObliviousReceive for Kos15Receiver<r_state::RandSetup> {
    type Choices = ();
    type Outputs = ();

    async fn receive(&mut self, choices: Self::Choices) -> Result<Self::Outputs, OTError> {
        todo!()
    }
}
