//pub mod base;
pub mod errors;
pub mod extension;

use async_trait::async_trait;
pub use errors::OTError;
use futures::{Sink, Stream};
use mpc_core::{
    msgs::ot::OTMessage,
    ot::{s_state, ExtSenderCoreError, Kos15Sender},
};

trait Protocol {
    type Message;
    type Error;
}

pub struct Agent<T>
where
    T: Protocol,
{
    inner: T,
    stream: Box<dyn Stream<Item = <T as Protocol>::Message> + Unpin + Send>,
    sink: Box<dyn Sink<<T as Protocol>::Message, Error = T::Error> + Unpin + Send>,
}

impl<T> Protocol for Kos15Sender<T> {
    type Message = OTMessage;
    type Error = ExtSenderCoreError;
}

impl Agent<Kos15Sender<s_state::Initialized>> {
    fn setup(self) -> Kos15Sender<s_state::Setup> {
        todo!()
    }
}

#[async_trait]
pub trait ObliviousSend {
    type Inputs;
    type Envelope;

    async fn send(
        &mut self,
        inputs: Self::Inputs,
    ) -> Box<dyn Stream<Item = Result<Self::Envelope, OTError>>>;
}

impl ObliviousSend for Agent<Kos15Sender<s_state::Setup>> {
    // ...
}

#[async_trait]
pub trait ObliviousReceive {
    type Choices;
    type Outputs;

    async fn receive(
        &mut self,
        choices: Self::Choices,
    ) -> Box<dyn Stream<Item = Result<Self::Outputs, OTError>>>;
}
