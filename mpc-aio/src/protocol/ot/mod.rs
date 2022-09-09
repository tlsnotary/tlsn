//pub mod base;
pub mod base;
pub mod errors;
pub mod extension;

use super::{Agent, Protocol};
use async_trait::async_trait;
pub use errors::OTError;
use futures::{Sink, Stream};
use mpc_core::{
    msgs::ot::OTMessage,
    ot::{s_state, ExtSenderCoreError, Kos15Sender},
};

#[async_trait]
pub trait ObliviousSend {
    type Inputs;

    async fn send(&mut self, inputs: Self::Inputs) -> Result<(), OTError>;
}

impl ObliviousSend for Agent<Kos15Sender<s_state::Setup>> {
    // ...
}

#[async_trait]
pub trait ObliviousReceive {
    type Choices;
    type Outputs;

    async fn receive(&mut self, choices: Self::Choices) -> Result<Self::Outputs, OTError>;
}
