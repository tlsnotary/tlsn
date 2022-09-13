// pub mod base;
pub mod errors;
pub mod extension;

use std::pin::Pin;

use super::{Channel, Protocol};
use async_trait::async_trait;
pub use errors::OTError;
use mpc_core::msgs::ot::OTMessage;

pub struct ObliviousTransfer;

impl Protocol for ObliviousTransfer {
    type Message = OTMessage;
    type Error = OTError;
}

type OTChannel = Pin<
    Box<
        dyn Channel<
            <ObliviousTransfer as Protocol>::Message,
            Error = <ObliviousTransfer as Protocol>::Error,
        >,
    >,
>;

#[async_trait]
pub trait ObliviousSend {
    type Inputs;

    async fn send(
        &mut self,
        inputs: Self::Inputs,
    ) -> Result<(), <ObliviousTransfer as Protocol>::Error>;
}

#[async_trait]
pub trait ObliviousReceive {
    type Choices;
    type Outputs;

    async fn receive(
        &mut self,
        choices: Self::Choices,
    ) -> Result<Self::Outputs, <ObliviousTransfer as Protocol>::Error>;
}
