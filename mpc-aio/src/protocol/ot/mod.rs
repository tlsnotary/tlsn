// pub mod base;
pub mod errors;
pub mod extension;

use async_trait::async_trait;
pub use errors::OTError;

#[async_trait]
pub trait ObliviousSend {
    type Inputs;

    async fn send(&mut self, inputs: Self::Inputs) -> Result<(), OTError>;
}

#[async_trait]
pub trait ObliviousReceive {
    type Choices;
    type Outputs;

    async fn receive(&mut self, choices: Self::Choices) -> Result<Self::Outputs, OTError>;
}
