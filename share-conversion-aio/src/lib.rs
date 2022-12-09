//! This subcrate implements the async IO layer for share-conversion

use async_trait::async_trait;
use mpc_aio::protocol::ot::{OTError, OTFactoryError};
use thiserror::Error;

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

/// An error for what can go wrong during conversion
#[derive(Debug, Error)]
pub enum ShareConversionError {
    #[error("OTFactoryError: {0}")]
    OTFactoryError(#[from] OTFactoryError),
    #[error("OTError: {0}")]
    OTError(#[from] OTError),
}
