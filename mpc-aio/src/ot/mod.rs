//pub mod base;
pub mod errors;
pub mod extension;

use async_trait::async_trait;
pub use errors::OTError;
use futures::{Sink, Stream};

#[async_trait]
pub trait ObliviousSend {
    type Inputs;
    type Envelope;
    type Message;

    async fn send(
        &mut self,
        stream: impl Stream<Item = Self::Message> + Unpin + Send,
        inputs: Self::Inputs,
    ) -> Box<dyn Stream<Item = Result<Self::Envelope, OTError>>>;
}

#[async_trait]
pub trait ObliviousReceive {
    type Choices;
    type Outputs;
    type Message;

    async fn receive(
        &mut self,
        stream: impl Stream<Item = Self::Message> + Unpin + Send,
        sink: impl Sink<Self::Message> + Unpin + Send,
        choices: Self::Choices,
    ) -> Box<dyn Stream<Item = Result<Self::Outputs, OTError>>>;
}

#[async_trait]
pub trait ObliviousSetup {
    type Actor;
    type Message;

    async fn setup(
        stream: impl Stream<Item = Self::Message> + Unpin + Send,
        sink: impl Sink<Self::Message> + Unpin + Send,
    ) -> Result<Self::Actor, OTError>;
}
