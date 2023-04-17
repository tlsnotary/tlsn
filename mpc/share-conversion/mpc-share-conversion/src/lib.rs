//! This subcrate implements the async IO layer for share-conversion

use async_trait::async_trait;
use mpc_ot::OTError;
use mpc_share_conversion_core::{fields::Field, ShareConversionCoreError};
use thiserror::Error;

pub mod conversion;

/// Allows to convert additive shares into multiplicative ones
#[async_trait]
pub trait AdditiveToMultiplicative<T: Field> {
    async fn a_to_m(&mut self, input: Vec<T>) -> Result<Vec<T>, ShareConversionError>;
}

/// Allows to convert multiplicative shares  into additive ones
#[async_trait]
pub trait MultiplicativeToAdditive<T: Field> {
    async fn m_to_a(&mut self, input: Vec<T>) -> Result<Vec<T>, ShareConversionError>;
}

/// Send a tape used for verification of the conversion
///
/// Senders record their inputs used during conversion and can send them to the receiver
/// afterwards. This will allow the receiver to use [VerifyTape].
#[async_trait]
pub trait SendTape {
    async fn send_tape(self) -> Result<(), ShareConversionError>;
}

/// Verify the recorded inputs of the sender
///
/// Will check if the conversion worked correctly. This allows to catch a malicious sender but
/// requires that he/she makes use of [SendTape].
#[async_trait]
pub trait VerifyTape {
    async fn verify_tape(self) -> Result<(), ShareConversionError>;
}

/// An error for what can go wrong during conversion
#[derive(Debug, Error)]
pub enum ShareConversionError {
    #[error("OTError: {0}")]
    OTError(#[from] OTError),
    #[error("IO Error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("ShareConversionCore Error: {0}")]
    ShareConversionCore(#[from] ShareConversionCoreError),
    #[error("Tape verification failed")]
    VerifyTapeFailed,
    #[error("Error: {0}")]
    Other(String),
}
