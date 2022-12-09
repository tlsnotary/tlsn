//! This subcrate implements the async IO layer for share-conversion

use async_trait::async_trait;
use mpc_aio::protocol::ot::{OTError, OTFactoryError};
use rand::{Rng, SeedableRng};
use recorder::Recorder;
use thiserror::Error;
use utils_aio::Channel;

pub mod gf2_128;
pub mod recorder;

/// Allows to convert additive shares of type `FieldElement` into multiplicative ones
#[async_trait]
pub trait AdditiveToMultiplicative {
    type FieldElement: Copy + std::fmt::Debug;
    async fn a_to_m(
        &mut self,
        input: &[Self::FieldElement],
    ) -> Result<Vec<Self::FieldElement>, ShareConversionError>;
}

/// Allows to convert multiplicative shares of type `FieldElement` into additive ones
#[async_trait]
pub trait MultiplicativeToAdditive {
    type FieldElement: Copy + std::fmt::Debug;
    async fn m_to_a(
        &mut self,
        input: &[Self::FieldElement],
    ) -> Result<Vec<Self::FieldElement>, ShareConversionError>;
}

pub type ConversionChannel<T, U> =
    Box<dyn Channel<ConversionMessage<T, U>, Error = std::io::Error>>;

pub struct ConversionMessage<T: SeedableRng + Rng + Send, U: Default + PartialEq + Send + Clone> {
    sender_tape: (Vec<<T as SeedableRng>::Seed>, Vec<Vec<U>>),
}

#[async_trait]
pub trait SendTape<T, U, V>
where
    T: Recorder<U, V>,
    U: SeedableRng + Rng + Send,
    V: Default + PartialEq + Send + Clone,
{
    async fn send_tape(self, channel: ConversionChannel<U, V>) -> Result<(), ShareConversionError>;
}

#[async_trait]
pub trait AcceptTape<T, U, V>
where
    T: Recorder<U, V>,
    U: SeedableRng + Rng + Send,
    V: Default + PartialEq + Send + Clone,
{
    async fn accept_tape(
        &mut self,
        channel: ConversionChannel<U, V>,
    ) -> Result<(), ShareConversionError>;
}

#[async_trait]
pub trait VerifyTape<T, U, V>
where
    T: Recorder<U, V>,
    U: Rng + SeedableRng,
{
    async fn verify_tape(self) -> Result<bool, ShareConversionError>;
}

/// An error for what can go wrong during conversion
#[derive(Debug, Error)]
pub enum ShareConversionError {
    #[error("OTFactoryError: {0}")]
    OTFactoryError(#[from] OTFactoryError),
    #[error("OTError: {0}")]
    OTError(#[from] OTError),
    #[error("IO Error: {0}")]
    IOError(#[from] std::io::Error),
}
