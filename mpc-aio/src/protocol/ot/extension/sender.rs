use super::ObliviousSend;
use crate::protocol::{ot::OTError, Agent, Protocol};
use async_trait::async_trait;
use futures::Stream;
use mpc_core::{
    msgs::ot::OTMessage,
    ot::{
        extension::{s_state, Kos15Sender},
        s_state::SenderState,
    },
};

impl<T: SenderState> Protocol for Kos15Sender<T> {
    type Message = OTMessage;
    type Error = OTError;
}

impl Agent<Kos15Sender<s_state::Initialized>> {
    pub fn new(
        stream: Box<dyn Stream<Item = OTMessage> + Send>,
    ) -> (Box<dyn Stream<Item = OTMessage> + Send>, Self) {
        todo!()
    }

    fn setup(self) -> Kos15Sender<s_state::Setup> {
        todo!()
    }
}

#[async_trait]
impl ObliviousSend for Kos15Sender<s_state::RandSetup> {
    type Inputs = ();

    async fn send(&mut self, inputs: Self::Inputs) -> Result<(), OTError> {
        todo!()
    }
}
